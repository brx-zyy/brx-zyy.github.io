---
title: OffSec | ProtoVault Breach (The Gauntlet)
date: 2026-08-07
description: A source code and Git history investigation into a leaked PostgreSQL database.
published: true
categories:
  - CTF
  - OffSec
tags:
  - offsec
  - the-gauntlet
  - git-forensics
  - git-secrets
  - credential-disclosure
  - s3-bucket
  - rot13
  - flask
  - postgresql
  - pbkdf2
  - data-breach
  - blue-team
image:
  path: /assets/kitty.jpg
---

## ProtoVault Breach - Investigation

**Format:** Source code and Git history forensics
**Scope:** A Flask asset management app and its Git repository

## Overview

This challenge hands you a source code archive and asks you to trace a real database leak back to its origin. Nothing here needs exploitation, it's pure investigation, reading code, reading Git history, and following a trail of things a developer meant to delete but couldn't quite scrub away. The path looks like this:

1. The application's own `app.py` stores its PostgreSQL connection string and Flask secret key in plaintext, a real weakness, but not actually the source of the leak.
2. Git commit history shows two backup and restore scripts, `backup_db.py` and `restore_db.py`, were added early on and later deliberately removed.
3. Checking out an old commit recovers `backup_db.py`, which reveals the backup process ROT13-encodes a full `pg_dump` of the database before uploading it to an S3 bucket.
4. Checking out a still earlier commit shows the S3 bucket name and key were different in an older version of the same script, and that earlier address is the one that's actually live and public.
5. Downloading the object with no credentials at all confirms the bucket has no access control whatsoever.
6. Reversing the ROT13 encoding with `tr` recovers a fully readable PostgreSQL dump, complete with every user's password hash.

## Getting the Files

The lab provides a password-protected ZIP containing a ransom email and a `source_code.zip`. Extracting the source into a working directory and unzipping it shows a Git repository sitting right alongside the application code.

```shell
mkdir -p Documents/OffSec/TheGauntlet/ProtoVaultBreach
cd Documents/OffSec/TheGauntlet/ProtoVaultBreach
mv ~/Desktop/source_code.zip .
unzip source_code.zip
```

```shell
ls -al

drwxrwxr-x 4 kali kali  4096 app
drwxrwxr-x 8 kali kali  4096 .git
-rw-r--r-- 1 kali kali    59 requirements.txt
-rw-rw-r-- 1 kali kali 78226 source_code.zip
```

An `app` directory and a full `.git` repository. Both turn out to matter.

## Reviewing the Application Source

`app/app.py` is a small Flask app for managing inventory items. The important part shows up in the first few lines.

```shell
cat app/app.py

from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
...
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a50deccc7fc4cc5d36ec28f3ffcc27fe6a515b5cd714a5b809fa6f1123aeb227'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://assetdba:8d631d2207ec1debaafd806822122250@pgsql_prod_db01.protoguard.local/pgamgt?sslmode=verify-full'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
```

The database connection string and the Flask secret key are both sitting in the source in plaintext, credentials, hostname, database name, all of it. That's a genuine finding on its own: a leak from this application is entirely plausible given how exposed this connection string is. But it turns out not to be the actual source of the breach described in the ransom note. The rest of `app.py`, `forms.py`, and the HTML templates don't add anything new, they're a fairly ordinary CRUD app with login, item categories, and notes.

## Digging Through Git History

With the application code itself mostly exhausted, the `.git` directory next door was worth a look. `.git/logs/HEAD` gives a quick, readable timeline of every commit without needing to page through `git log`.

```shell
cat .git/logs/HEAD

0000000000000000000000000000000000000000 444eb3a... Walter <walter.s@protoguard.local> ... commit (initial): Initial commit: Flask app scaffold
444eb3a... 3654766... Walter <walter.s@protoguard.local> ... commit: UI refactor
3654766... 5fe83a8... Walter <walter.s@protoguard.local> ... commit: Add authentication
5fe83a8... b32d77d... Walter <walter.s@protoguard.local> ... commit: database migration scripts
b32d77d... f22ba8a... Walter <walter.s@protoguard.local> ... commit: Add data models
f22ba8a... 9f257d2... Walter <walter.s@protoguard.local> ... commit: Add item details and notes forms
9f257d2... 8fe1a44... Walter <walter.s@protoguard.local> ... commit: Remove backup scripts
8fe1a44... a230bbc... Walter <walter.s@protoguard.local> ... commit: Release candidate
```

One line jumps out immediately: **Remove backup scripts**. Something existed in this repo that isn't there anymore, and Git never actually forgets.

## Using git-secrets to Confirm the Scope

Before chasing deleted files, it's worth confirming there isn't anything else obvious sitting in the repo's history. `git-secrets` scans both the working tree and full commit history for patterns like AWS keys, passwords, and custom keywords.

```shell
sudo apt install git-secrets
git secrets --install
git secrets --register-aws
git secrets --add 'password='
git secrets --add 'SECRET_KEY'
```

```shell
git secrets --scan

app/app.py:8:app.config['SECRET_KEY'] = 'a50deccc7fc4cc5d36ec28f3ffcc27fe6a515b5cd714a5b809fa6f1123aeb227'
[ERROR] Matched one or more prohibited patterns
```

Nothing new there, just the same secret key already found by hand. Scanning full history turns up more though.

```shell
git secrets --scan-history

ccd589a...:app/app.py:8:app.config['SECRET_KEY'] = 'a50deccc7fc4cc5d36ec28f3ffcc27fe6a515b5cd714a5b809fa6f1123aeb227'
503dba9...:app/app.py:9:app.config['SECRET_KEY'] = 'supersecretkey'
b400120...:app/app.py:5:app.config['SECRET_KEY'] = 'changeme'
```

The secret key was cycled through several different values across commits, `changeme`, `supersecretkey`, and the final long hex string. Interesting from a hygiene standpoint, credential reuse across environments is a real risk here, but it doesn't point any further toward the actual leak. Back to the deleted scripts.

## Recovering the Deleted Backup Script

`git log` with a diff filter for deletions shows exactly which files disappeared and in which commits.

```shell
git log --diff-filter=D --summary

commit 1cc71b0...
    Remove backup scripts

 delete mode 100644 app/util/backup_db.py
 delete mode 100644 app/util/restore_db.py
```

`app/util/backup_db.py` and `app/util/restore_db.py`, gone, but only from the working tree, not from history. Cross-referencing the commit hashes against `.git/logs/HEAD` shows the commit immediately before the removal, `9f257d253fc6c15860d2e24941b66ab0733e72aa`. Checking that commit out brings the files right back.

```shell
git checkout 9f257d253fc6c15860d2e24941b66ab0733e72aa
```

```shell
ls app/util

backup_db.py  restore_db.py
```

Reading `backup_db.py` explains everything.

```shell
cat app/util/backup_db.py

#!/usr/bin/env python3
import paramiko
import boto3
import codecs
import os
from scp import SCPClient

SSH_HOST = "pgsql_prod_db01.protoguard.local"
SSH_PORT = 22
SSH_USER = "dbadmin"
SSH_KEY = "/home/walter/.ssh/pgsql_key"

DB_NAME = "pgamgt"
DB_USER = "assetdba"
BACKUP_FILENAME = "db_backup.sql"
LOCAL_BACKUP = f"/tmp/{BACKUP_FILENAME}"
ENC_BACKUP = f"/tmp/{BACKUP_FILENAME}.xyz"

S3_BUCKET = "pgamgt-backups"
S3_KEY = "latest_backup.xyz"


def run_backup():
    ssh = create_ssh_client()
    dump_cmd = f"pg_dump -U {DB_USER} {DB_NAME} > /tmp/{BACKUP_FILENAME}"
    ...


def encode():
    with open(LOCAL_BACKUP, "r", encoding="utf-8", errors="ignore") as f:
        data = f.read()
    encoded = codecs.encode(data, "rot_13")
    with open(ENC_BACKUP, "w", encoding="utf-8") as f:
        f.write(encoded)


def upload_to_s3():
    s3 = boto3.client("s3")
    s3.upload_file(ENC_BACKUP, S3_BUCKET, S3_KEY)
```

The script SSHes into the database host, dumps the whole database with `pg_dump`, "encrypts" it with ROT13, and uploads that to an S3 bucket. ROT13 is not encryption, it's a letter-substitution cipher a teenager could break by eye, so calling it `encode()` is at least honest. This file is clearly the leak's real origin, the plaintext connection string in `app.py` was a red herring by comparison, or at least a secondary issue.

## Finding the Real (Earlier) S3 Address

The bucket referenced in this version, `pgamgt-backups`, and key `latest_backup.xyz`, seems like the obvious answer. Trying to fetch it says otherwise.

```shell
sudo apt install awscli
aws s3 cp s3://pgamgt-backups/latest_backup.xyz ./
```

```shell
fatal error: Unable to locate credentials
```

Retrying without credentials, since a leaked bucket is usually public, changes the error but doesn't fix it.

```shell
aws s3 cp s3://pgamgt-backups/latest_backup.xyz ./ --no-sign-request

fatal error: An error occurred (404) when calling the HeadObject operation: Key "latest_backup.xyz" does not exist
```

Wrong object, or an outdated one. Since the removal happened across two separate commits, it's worth checking the other one too. `ef917bbffedf1638f5ce7747132942197ce97703` is the commit immediately preceding the first "Remove backup scripts" event in the log.

```shell
git checkout ef917bbffedf1638f5ce7747132942197ce97703
cat app/util/backup_db.py
```

```shell
S3_BUCKET = "protoguard-asset-management"
S3_KEY = "db_backup.xyz"
S3_REGION = "us-east-2"
```

A different bucket, a different key, and a region this time. That's the earlier, and evidently still live, version of the backup target.

## Downloading the Leaked Backup

```shell
aws s3 cp s3://protoguard-asset-management/db_backup.xyz ./ --region us-east-2 --no-sign-request

download: s3://protoguard-asset-management/db_backup.xyz to ./db_backup.xyz
```

No credentials, no authentication, nothing. The bucket is genuinely public. This same object is also reachable directly over HTTPS at `https://protoguard-asset-management.s3.us-east-2.amazonaws.com/db_backup.xyz`, which is worth knowing since the path-style URL (`s3.us-east-2.amazonaws.com/bucket/key`) doesn't resolve the same way once virtual-hosted addressing is involved.

## Decoding the ROT13 Dump

Reading the downloaded file directly confirms the encoding from `backup_db.py` is exactly what it claimed to be.

```shell
cat db_backup.xyz

--
-- CbfgterFDY qngnonfr qhzc
--
FRG fgngrzrag_gvzrbhg = 0;
...
```

Gibberish, but recognizably gibberish, every character shifted by 13. `tr` handles the reverse shift in one line.

```shell
tr 'A-Za-z' 'N-ZA-Mn-za-m' < db_backup.xyz > decoded_backup.sql
```

```shell
cat decoded_backup.sql

--
-- PostgreSQL database dump
--
-- Dumped from database version 16.3
-- Dumped by pg_dump version 16.3

SET statement_timeout = 0;
...
```

A complete, readable PostgreSQL dump.

## Confirming the Leak

The last step is proving the dump actually contains real, sensitive data rather than just structure. A quick grep for a specific user turns up their full record, hash included.

```shell
grep "Naomi" decoded_backup.sql

11    Naomi    Adler    Cognitive Systems Research    naomi.adler    pbkdf2:sha256:600000$YQqIvcDipYLzzXPB$598fe450e5ac019cdd41b4b10c5c21515573ee63a8f4881f7d721fd74ee43d59
```

A `pbkdf2:sha256` hash with 600,000 iterations, that's Werkzeug's default `generate_password_hash` output, and it's exactly the confirmation needed: this dump is real, it's the actual user table, and it was sitting in an unauthenticated public S3 bucket the entire time.
