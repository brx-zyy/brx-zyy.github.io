---
title: Active Directory Fundamentals
date: 2023-03-31
description: Domains, forests, users, groups, GPOs, Kerberos, LDAP, ACLs, trusts, replication, and core AD security concepts.
published: true

categories:
  - Active Directory
  - Active Directory Fundamentals
    
tags:
  - active-directory
  - ad
  - ad-ds
  - windows
  - domain-controller
  - domain
  - forest
  - tree
  - organizational-unit
  - ou
  - users
  - computers
  - groups
  - group-policy
  - gpo
  - kerberos
  - ldap
  - ntlm
  - authentication
  - authorization
  - security
  - acl
  - ace
  - dacl
  - sid
  - guid
  - spn
  - global-catalog
  - replication
  - sysvol
  - ntds
  - fsmo
  - trusts
  - windows-security
  - penetration-testing
  - red-team
  - ctf

image:
  path: /assets/active-directory.jpg
---

# Active Directory Key Concepts & Terminology

Active Directory (AD) is Microsoft's directory service for Windows domain environments. It provides centralized **authentication, authorization, identity management, and resource management**.

**Active Directory Domain Services (AD DS)** is the primary Active Directory service responsible for storing and managing objects such as users, computers, groups, and organizational units (OUs).

---

## Active Directory Structure

### Forest

A **forest** is the highest-level logical boundary in Active Directory.

A forest:

- Contains one or more domains
- Shares a common schema
- Contains a Global Catalog
- Provides trust relationships between domains

### Tree

A **tree** is a collection of domains that share a contiguous DNS namespace.

```text
example.local
├── child.example.local
└── dev.example.local
```

### Domain

A **domain** is a logical security and administrative boundary containing objects such as:

- Users
- Computers
- Groups
- OUs

Example:

```text
example.local
```

### Organizational Unit (OU)

An **OU** is a container used to organize objects within a domain.

OUs are commonly used for:

- Organizing users and computers
- Delegating administration
- Applying Group Policy

Example:

```text
DC=example,DC=local
└── OU=Users
    ├── Alice
    └── Bob
```

---

## Domain Controllers

### Domain Controller (DC)

A **Domain Controller** is a Windows Server running AD DS.

A DC provides:

- Authentication
- Authorization
- LDAP services
- Kerberos authentication
- Directory queries
- AD replication
- Group Policy distribution

The main AD database is stored in:

```text
C:\Windows\NTDS\NTDS.dit
```

### Global Catalog

The **Global Catalog (GC)** provides a searchable representation of objects across the forest.

It:

- Contains a partial attribute set for objects across domains
- Allows forest-wide searches
- Helps locate objects across domains
- Supports certain authentication operations

Common ports:

```text
3268 → Global Catalog
3269 → Global Catalog over SSL
```

---

## AD Objects

An **object** is an entity stored in Active Directory.

Common objects include:

```text
User
Computer
Group
OU
Printer
Contact
Domain Controller
```

### Attributes

Attributes describe an AD object.

Common user attributes include:

```text
sAMAccountName
userPrincipalName
mail
memberOf
objectSid
objectGUID
servicePrincipalName
```

### Schema

The **schema** defines the types of objects and attributes that can exist in Active Directory.

Think of the schema as the **blueprint of AD**.

---

## Users and Computer Accounts

### Domain User

A domain user is centrally managed by Active Directory.

Examples:

```text
EXAMPLE\alice
alice@example.local
```

### Local User

A local account exists only on an individual machine.

Examples:

```text
Administrator
Guest
```

Built-in service identities include:

```text
SYSTEM
LOCAL SERVICE
NETWORK SERVICE
```

### Computer Account

A domain-joined computer has an AD computer object.

Computer accounts normally end with `$`:

```text
DC01$
WEB01$
CLIENT01$
```

Computer accounts are also **security principals** and can authenticate to the domain.

---

## Distinguished Names

A **Distinguished Name (DN)** describes an object's location in Active Directory.

Example:

```text
CN=starfire,OU=Users,DC=example,DC=local
```

Breakdown:

```text
CN=starfire  → Common Name
OU=Users     → Organizational Unit
DC=example   → Domain Component
DC=local     → Domain Component
```

### Relative Distinguished Name

The **RDN** is the portion of the DN that identifies an object at its current level.

Example:

```text
CN=starfire
```

---

## Groups

Groups simplify permission and access management.

Groups can contain:

- Users
- Computers
- Other groups

### Security Groups

Used to assign permissions and access to resources.

### Distribution Groups

Primarily used for email distribution and are not used for assigning security permissions.

---

## Group Scopes

### Domain Local

Domain Local groups are primarily used to assign permissions to resources within their domain.

They can contain security principals from trusted domains according to AD membership rules.

### Global

Global groups are typically used to organize users and computers from the same domain.

They can be granted permissions to resources in other domains.

### Universal

Universal groups are designed for use across multiple domains in a forest.

They can contain:

- Users
- Global groups
- Universal groups

Universal group membership is stored in the Global Catalog.

---

## AGDLP

A common Microsoft permission model is **AGDLP**:

```text
Accounts
   ↓
Global Groups
   ↓
Domain Local Groups
   ↓
Permissions
```

Example:

```text
Alice
  ↓
GG_HR_Users
  ↓
DL_HR_Share
  ↓
Read Access
```

---

## Group Policy

**Group Policy** allows administrators to centrally configure users and computers.

A **Group Policy Object (GPO)** can be linked to:

```text
Site
Domain
OU
```

GPOs are not linked directly to individual users or groups.

### Common GPO Uses

- Password and account policies
- Windows Defender configuration
- Firewall rules
- Application deployment
- Software restrictions
- PowerShell and CMD restrictions
- USB/removable media controls
- Audit policies
- Logon/logoff scripts
- Startup/shutdown scripts
- Desktop configuration
- Security settings

### GPO Processing

A simplified processing order is:

```text
Local
  ↓
Site
  ↓
Domain
  ↓
OU
```

Later-applied policies can generally override earlier settings, subject to mechanisms such as:

- Enforced links
- Inheritance
- Security filtering
- WMI filters

> **Note:** Domain password and account policies have special behavior. Creating separate GPOs on different OUs does not automatically create independent domain password policies.

---

## Authentication

### Kerberos

**Kerberos** is the primary authentication protocol used by modern Active Directory environments.

Simplified flow:

```text
User
 ↓
KDC
 ↓
TGT
 ↓
Service Ticket
 ↓
Service
```

The **Key Distribution Center (KDC)** runs on domain controllers and consists of:

- Authentication Service (AS)
- Ticket Granting Service (TGS)

### NTLM

**NTLM** is an older challenge-response authentication protocol.

It remains supported in many Windows environments but is generally less desirable than Kerberos.

---

## Kerberos Terminology

### TGT

A **Ticket Granting Ticket (TGT)** is issued after successful Kerberos authentication.

It is used to request service tickets.

### Service Ticket

A service ticket allows a user to authenticate to a specific Kerberos service.

### SPN

A **Service Principal Name (SPN)** identifies a service instance for Kerberos authentication.

Example:

```text
MSSQLSvc/sql01.example.local:1433
```

SPNs are associated with accounts and are important when studying attacks such as **Kerberoasting**.

---

## Security Identifiers

### SID

A **Security Identifier (SID)** uniquely identifies a security principal.

Example:

```text
S-1-5-21-...
```

Users, groups, and computer accounts can have SIDs.

### RID

The **Relative Identifier (RID)** identifies an object within a domain.

Example:

```text
S-1-5-21-AAA-BBB-CCC-1105
                       ↑
                      RID
```

### objectGUID

Each AD object has a globally unique 128-bit `objectGUID`.

### sIDHistory

`sIDHistory` stores previous SIDs associated with an account, commonly during domain migrations.

Improper control of `sIDHistory` can create serious privilege-escalation risks.

---

## ACLs and Permissions

### ACL

An **Access Control List (ACL)** defines access permissions for an object.

### ACE

An **Access Control Entry (ACE)** is an individual permission entry inside an ACL.

Example:

```text
Alice → Read
Bob   → Modify
Admin → Full Control
```

### DACL

The **Discretionary Access Control List (DACL)** defines who is allowed or denied access.

### SACL

The **System Access Control List (SACL)** defines which access attempts should be audited.

---

## Important AD Files and Shares

### NTDS.dit

The main Active Directory database:

```text
C:\Windows\NTDS\NTDS.dit
```

It contains directory information, including credential-related data such as password hashes.

### SYSVOL

`SYSVOL` is a domain-wide replicated share containing files required by domain controllers.

It commonly contains:

- Group Policy files
- Logon scripts
- Other domain-wide configuration files

Example:

```text
\\example.local\SYSVOL
```

### NETLOGON

`NETLOGON` is a commonly available DC share used for logon scripts and other domain-related files.

```text
\\DC01\NETLOGON
```

---

## Replication

Active Directory uses **multi-master replication**.

Changes made on one writable domain controller can be replicated to other domain controllers.

Important replication concepts include:

- Replication partners
- Replication topology
- Sites
- USNs
- Invocation IDs
- Replication metadata

Replication problems can cause inconsistent directory information between DCs.

---

## AD Sites

**Sites** represent physical or network locations.

They help AD optimize:

- Authentication
- Domain Controller selection
- Replication
- Client-to-DC communication

Example:

```text
Riko
├── DC01
└── DC02

Ravyn
└── DC03
```

---

## Trusts

Trusts allow security principals in different domains to access resources across domain boundaries.

Within a typical AD forest, parent and child domains have **transitive two-way trusts** by default.

Common trust relationships include:

```text
Parent ↔ Child
Domain ↔ Domain
Forest ↔ Forest
```

Trusts are important when analyzing **cross-domain and cross-forest access**.

---

## FSMO Roles

Active Directory has five **Flexible Single Master Operations (FSMO)** roles.

### Forest-Wide Roles

#### Schema Master

Controls modifications to the AD schema.

#### Domain Naming Master

Controls adding and removing domains and application partitions in the forest.

### Domain-Wide Roles

#### RID Master

Allocates RID pools to domain controllers.

#### PDC Emulator

Important for:

- Password changes
- Account lockouts
- Time synchronization
- Certain Group Policy operations

#### Infrastructure Master

Maintains references to objects from other domains.

```text
Forest
├── Schema Master
└── Domain Naming Master

Domain
├── RID Master
├── PDC Emulator
└── Infrastructure Master
```

---

## Deleted Objects

### Tombstone

When an AD object is deleted, information about the deleted object can be retained as a **tombstone** for a defined period.

This allows deletion to replicate correctly between domain controllers.

### Active Directory Recycle Bin

When enabled, the AD Recycle Bin provides improved recovery of deleted objects while preserving more of their original attributes.

---

## Privileged Groups

Common privileged groups include:

```text
Domain Admins
Enterprise Admins
Administrators
Account Operators
Backup Operators
Server Operators
```

Membership in privileged groups should be tightly controlled because excessive privileges can lead to domain compromise.

---

## AdminSDHolder

`AdminSDHolder` helps protect the permissions of privileged accounts and groups.

The **SDProp** process periodically applies the protected security descriptor to protected objects.

This is important when investigating unusual ACLs involving privileged accounts.

---

## LDAP

**LDAP (Lightweight Directory Access Protocol)** is used to query and interact with directory services.

Common AD ports:

```text
389  → LDAP
636  → LDAPS
3268 → Global Catalog
3269 → Global Catalog over SSL
```

LDAP is heavily used for AD enumeration.

---

## DNS and Active Directory

DNS is critical to Active Directory.

AD relies on DNS for locating services such as:

- Domain Controllers
- Kerberos
- LDAP
- Global Catalog

Important DNS records include **SRV records**.

Example:

```text
_ldap._tcp.dc._msdcs.example.local
```

If DNS is broken, many AD functions can fail.

---

## Useful AD Tools

### Active Directory Users and Computers

**ADUC** is a GUI tool used to manage:

- Users
- Groups
- Computers
- OUs

### ADSI Edit

**ADSI Edit** is an advanced GUI tool for directly viewing and modifying AD objects and attributes.

### PowerShell

Common AD PowerShell commands:

```powershell
Get-ADUser
Get-ADComputer
Get-ADGroup
Get-ADGroupMember
Get-ADObject
Get-ADDomain
Get-ADForest
```

---

## AD Security Concepts

Important Active Directory security topics include:

```text
Kerberoasting
AS-REP Roasting
NTLM Relay
Pass-the-Hash
Pass-the-Ticket
Credential Dumping
Password Spraying
ACL Abuse
Unconstrained Delegation
Constrained Delegation
Resource-Based Constrained Delegation
DCSync
Golden Ticket
Silver Ticket
Lateral Movement
Domain Privilege Escalation
Persistence
```

---

## Common AD Attack Path

A simplified Active Directory attack chain:

```text
Initial Access
      ↓
Enumeration
      ↓
Credential / Hash Discovery
      ↓
Privilege Escalation
      ↓
Lateral Movement
      ↓
Domain Admin
      ↓
Persistence
```

---

## Quick Mental Model

Think of Active Directory as:

```text
FOREST
│
├── TREE
│    │
│    └── DOMAIN
│         │
│         ├── OU
│         │    ├── Users
│         │    ├── Computers
│         │    └── Groups
│         │
│         ├── Domain Controllers
│         ├── GPOs
│         └── SYSVOL
│
└── Global Catalog
```

Core relationships:

```text
Users / Computers
        ↓
      Groups
        ↓
    Permissions
        ↓
     Resources
```

And:

```text
Forest
  ↓
Tree
  ↓
Domain
  ↓
OU
  ↓
Objects
```

> **Core AD foundation:** Understand **DNS, LDAP, Kerberos, Domain Controllers, Forests, Domains, OUs, Groups, GPOs, ACLs, SIDs, SPNs, Replication, and Trusts** before moving into advanced AD attacks.
