# Lab setup - SOME DETAILS STILL MISSING.

This is the setup of the lab.

## S1. Server with AD:
VM: Windows Server 2019
-	AD installed here, default installation
Important: Host-Only network adapter
Tutorial: https://dev.to/adamkatora/building-an-active-directory-pentesting-home-lab-in-virtualbox-53dc


## S2. Client machine to join AD separately (required for some attacks?)

VM: Windows 10 Pro image installed

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


## Script to populate AD with users, groups, and vulnerabilities:

1.	Basic: max 100 users
-	Link: https://github.com/safebuffer/vulnerable-AD/tree/master

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

