# Lab setup - SOME DETAILS STILL MISSING.

This is the setup of the lab.

## S1. Server with AD:
VM: Windows Server 2019
-	AD installed here, default installation
- Important: Host-Only network adapter
- Tutorial: https://dev.to/adamkatora/building-an-active-directory-pentesting-home-lab-in-virtualbox-53dc

## S1 ALTERNATIVE. Server with AD, but the original Windows Server 2019 ISO:
VM: Windows Server 2019, original 2019 ISO (no updates from later) - needed to exploit some vulnerabilities, which got patched after 2019. 
- In a real setting, it can be expected that not all Server machines are up to date with the latest security patches. We simulate this.
- Important: Host-Only network adapter
- Tutorial: https://dev.to/adamkatora/building-an-active-directory-pentesting-home-lab-in-virtualbox-53dc

## S2. Client machine to join AD separately (required for some attacks?)

VM: Windows 10 Pro image installed

Setting	Values:
- IP address	192.168.56.10
- Subnet mask	255.255.255.0
- Default gateway	(leave blank)
- Preferred DNS	192.168.56.2
- Alternate DNS	(leave blank)

## S3. Attacker:
- VM: Kali Linux
- Important: Host-Only network adapter
- Tutorial: any guide from the internet


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
- command: bloodhound-python \                                        
  -u merissa.lorrayne \
  -p 'Ip]z6tM0e*xC' \
  -d offensive.local \
  -c Acl \
  -dc DomainC.offensive.local \
  -ns 192.168.56.2

