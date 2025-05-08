# Lab setup - TODO

This is the setup of the lab.

## S1. Server with AD:
VM: Windows Server 2019
-	AD installed here, default installation
Important: Host-Only network adapter
Tutorial: https://dev.to/adamkatora/building-an-active-directory-pentesting-home-lab-in-virtualbox-53dc
-	works

## S2. Client machine to join AD separately (required for some attacks?)
-	works

Setting	Value
IP address	192.168.56.10
Subnet mask	255.255.255.0
Default gateway	(leave blank)
Preferred DNS	192.168.56.2
Alternate DNS	(leave blank)

## S3. Attacker:
VM: Kali Linux
Important: Host-Only network adapter
Tutorial: any guide from the internet
-	works

## Script to populate AD with users, groups, and vulnerabilities:

1.	Basic: max 100 users
-	Link: https://github.com/safebuffer/vulnerable-AD/tree/master
-	works

2.	Advanced (BadBlood):
-	Link: https://github.com/davidprowe/BadBlood 
-	have not tried yet

## Test attack – Bloodhound enumeration 
-	find user and password from domain (? For now we cheated this step for testing)
-	do enumeration
-	Link: https://m8sec.medium.com/active-directory-acl-abuse-with-kali-linux-7434a27dd938
bloodhound-python \                                        
  -u merissa.lorrayne \
  -p 'Ip]z6tM0e*xC' \
  -d offensive.local \
  -c Acl \
  -dc DomainC.offensive.local \
  -ns 192.168.56.2
-	works
-	


## Kerberos setup

1. Pick or create two AD service accounts
If you haven’t already, make two accounts to hold your SPNs:

In PowerShell on DC (or RSAT-enabled client):
New-ADUser svcWeb  -SamAccountName svcWeb  -AccountPassword (ConvertTo-SecureString 'P@55w0rd!' -AsPlainText -Force) -Enabled $true


New-ADUser svcSQL  -SamAccountName svcSQL  -AccountPassword (ConvertTo-SecureString '!TryBr3akMeN0tPoss#bleY' -AsPlainText -Force) -Enabled $true

2. Register two SPNs pointing at those hosts
Still on the DC, run:

REM 1) HTTP service on the DC itself
setspn -s HTTP/DomainC.offensive.local svcWeb

REM 2) MSSQL service on the DC
setspn -s MSSQLSvc/DomainC.offensive.local:1433 svcSQL




## Passwords: 
Ms server: Andrei123
DSRM password: Codrin123
Domain name: offensive.local
Domain controller name: DomainC

Windows Client: name Alice, Alice123
Offensive.local, Windows account:
User: merissa.lorrayne
Pass: Ip]z6tM0e*xC

Security Questions Windows Client: 
childhood nickname: simi
first school: loga
city born: timisoara
