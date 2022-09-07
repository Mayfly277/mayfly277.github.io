---
layout: post
title:  "GOAD - part 1 - reconnaissance and scan"
category : AD
tags :  AD, Lab, kerberos, nmap
---

The lab is now up and running [Goad introduction]({% link _posts/2022-07-02-GOADv2.md %}), let's do some recon on it.

## Enumerate Network

We will starting the reconnaissance of the Game Of Active Directory environment by searching all the availables IPs.

![mindmap_scan.png](/assets/blog/GOAD/mindmap_scan.png)

### First recon with cme

The first thing i personally do before launching an nmap is to scan for netbios results.
For this i launch crackmapexec (cme) on the IP range to quickly get netbios answers by windows computers.
This is a very kick way to get all the windows machine IP, names and domains.

```bash
cme smb 192.168.56.1/24
```

![cme.png](/assets/blog/GOAD/cme.png)

This command answer relatively quickly and send back a lot of useful informations!

We now know there is 3 domains:
- north.sevenkingdoms.local (2 ip)
  - CASTELBLACK (windows server 2019) (signing false)
  - WINTERFELL (windows server 2019) 
- sevenkingdoms.local (1 ip)
  - KINGSLANDING (windows server 2019)
- essos.local (2 ip)
  - BRAAVOS (windows server 2016) (signing false)
  - MEEREEN (windows server 2019)

Here as we got 3 domains we know that three DCs must be setup.
We also know that microsoft setup DC smb signing as true by default. So all the dc are the one with signing at true. (In a secure environment signing must true everywhere to avoid ntlm relay).


### Find DC ip

![mindmap_dc_ip.png](/assets/blog/GOAD/mindmap_dc_ip.png)

- Let's enumerate the DCs by quering the dns with nslookup

```shell
nslookup -type=srv _ldap._tcp.dc._msdcs.sevenkingdoms.local 192.168.56.10
```

![nslookup_dc.png](/assets/blog/GOAD/nslookup_dc.png)


### setup /etc/hosts and kerberos
- To use kerberos in our Linux environment we will do some configurations.
- First we must set the DNS by configuring the /etc/hosts file

```
# /etc/hosts
# GOAD
192.168.56.10   sevenkingdoms.local kingslanding.sevenkingdoms.local kingslanding
192.168.56.11   winterfell.north.sevenkingdoms.local north.sevenkingdoms.local winterfell
192.168.56.12   essos.local meereen.essos.local meereen
192.168.56.22   castelblack.north.sevenkingdoms.local castelblack
192.168.56.23   braavos.essos.local braavos
```

- We must install the Linux kerberos client

```bash
sudo apt install krb5-user
```

- We answer the questions with :
  - realm : essos.local
  - servers : meereen.essos.local

- We will setup the /etc/krb5.conf file like this :
```
[libdefaults]
	default_realm = essos.local
	kdc_timesync = 1
	ccache_type = 4
	forwardable = true
	proxiable = true
	fcc-mit-ticketflags = true
[realms]
	north.sevenkingdoms.local = {
		kdc = winterfell.north.sevenkingdoms.local
		admin_server = winterfell.north.sevenkingdoms.local
	}
	sevenkingdoms.local = {
		kdc = kingslanding.sevenkingdoms.local
		admin_server = kingslanding.sevenkingdoms.local
	}
	essos.local = {
		kdc = meereen.essos.local
		admin_server = meereen.essos.local
	}
...
```

- Now kerberos is set up on our environment we will try if we can get a TGT for a user.

```shell
getTGT.py essos.local/khal.drogo:horse
```

```
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Saving ticket in khal.drogo.ccache
```

```shell
export KRB5CCNAME=/workspace/khal.drogo.ccache 
```

```shell
smbclient.py -k @braavos.essos.local
```

```
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation
Type help for list of commands
# shares
ADMIN$
all
C$
CertEnroll
IPC$
public
# use C$
# ls
drw-rw-rw-          0  Wed Jun 29 10:41:11 2022 $Recycle.Bin
-rw-rw-rw-     384322  Thu Feb 14 20:38:48 2019 bootmgr
-rw-rw-rw-          1  Thu Feb 14 20:38:48 2019 BOOTNXT
drw-rw-rw-          0  Wed Jun 29 01:20:28 2022 Config.Msi
-rw-rw-rw-       1914  Wed Jun 29 07:46:13 2022 dns_log.txt
drw-rw-rw-          0  Wed Jun 29 08:29:08 2022 Documents and Settings
drw-rw-rw-          0  Wed Jun 29 01:26:54 2022 inetpub
-rw-rw-rw- 1342177280  Sun Jul  3 22:57:35 2022 pagefile.sys
drw-rw-rw-          0  Thu Feb 14 13:19:12 2019 PerfLogs
drw-rw-rw-          0  Wed Jun 29 01:19:59 2022 Program Files
drw-rw-rw-          0  Wed Jun 29 01:29:07 2022 Program Files (x86)
drw-rw-rw-          0  Wed Jun 29 10:46:28 2022 ProgramData
drw-rw-rw-          0  Wed Jun 29 00:29:20 2022 Recovery
drw-rw-rw-          0  Wed Jun 29 01:07:10 2022 setup
drw-rw-rw-          0  Wed Jun 29 01:31:47 2022 shares
drw-rw-rw-          0  Thu Feb 14 20:40:57 2019 System Volume Information
drw-rw-rw-          0  Wed Jun 29 01:01:06 2022 tmp
drw-rw-rw-          0  Wed Jun 29 10:40:42 2022 Users
drw-rw-rw-          0  Sun Jul  3 15:58:04 2022 vagrant
drw-rw-rw-          0  Thu Jun 30 17:33:12 2022 Windows
```

- Ok the kerberos setup is good :)
- We could now unset the ticket:

```shell
unset KRB5CCNAME
```

- Trouble on winterfell
- During the kerberos tests we saw we get trouble on winterfell:

```bash
getTGT.py north.sevenkingdoms.local/arya.stark:Needle
```

```
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation
[*] Saving ticket in arya.stark.ccache
```

```bash
export KRB5CCNAME=/workspace/arya.stark.ccache
```

```bash
smbclient.py -k -no-pass @winterfell.north.sevenkingdoms.local
```

```
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] SMB SessionError: STATUS_MORE_PROCESSING_REQUIRED({Still Busy} The specified I/O request packet (IRP) cannot be disposed of because the I/O operation is not complete.)
```

- Actually i don't know why kerberos doesn't work on winterfell with the full FQDN, but it's ok by just setting winterfell instead of winterfell.north.sevenkingdoms.local

```bash
smbclient.py -k -no-pass @winterfell
```

```
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation
Type help for list of commands
# shares
ADMIN$
C$
IPC$
NETLOGON
SYSVOL
# use SYSVOL
# ls
drw-rw-rw-          0  Wed Jun 29 00:48:39 2022 .
drw-rw-rw-          0  Wed Jun 29 00:48:39 2022 ..
drw-rw-rw-          0  Wed Jun 29 00:48:39 2022 north.sevenkingdoms.local
```

### Nmap

One thing to know is that nmap will do a ping before scanning the target. If the target doesn't answer to ping it will be ignore.

The way to be sure we doesn't miss anything on TCP, could be to scan with the following options:

```bash
nmap -Pn -p- -sC -sV -oA full_scan_goad 192.168.56.10-12,22-23
```

Let's analyze this command :
- `-Pn` don't do ping scan and scan all ip
- `-p-` scan the 56000 ports instead of the default nmap 1000 top ports by default
- `-sC` play the default script for reconnaissance
- `-sV` enumerate the version
- `-oA` write results in the 3 available format (nmap classic, grep format, xml format)

- The full scan result is:

```
Nmap scan report for sevenkingdoms.local (192.168.56.10)
Host is up (0.00066s latency).
Not shown: 65511 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-07-03 15:14:43Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sevenkingdoms.local0., Site: Default-First-Site-Name)
|_ssl-date: 2022-07-03T15:17:20+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=kingslanding.sevenkingdoms.local
| Subject Alternative Name: othername:<unsupported>, DNS:kingslanding.sevenkingdoms.local
| Not valid before: 2022-06-30T06:55:19
|_Not valid after:  2023-06-30T06:55:19
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sevenkingdoms.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=kingslanding.sevenkingdoms.local
| Subject Alternative Name: othername:<unsupported>, DNS:kingslanding.sevenkingdoms.local
| Not valid before: 2022-06-30T06:55:19
|_Not valid after:  2023-06-30T06:55:19
|_ssl-date: 2022-07-03T15:17:20+00:00; 0s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sevenkingdoms.local0., Site: Default-First-Site-Name)
|_ssl-date: 2022-07-03T15:17:20+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=kingslanding.sevenkingdoms.local
| Subject Alternative Name: othername:<unsupported>, DNS:kingslanding.sevenkingdoms.local
| Not valid before: 2022-06-30T06:55:19
|_Not valid after:  2023-06-30T06:55:19
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sevenkingdoms.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=kingslanding.sevenkingdoms.local
| Subject Alternative Name: othername:<unsupported>, DNS:kingslanding.sevenkingdoms.local
| Not valid before: 2022-06-30T06:55:19
|_Not valid after:  2023-06-30T06:55:19
|_ssl-date: 2022-07-03T15:17:20+00:00; 0s from scanner time.
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2022-07-03T15:17:20+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=kingslanding.sevenkingdoms.local
| Not valid before: 2022-06-27T22:40:05
|_Not valid after:  2022-12-27T22:40:05
| rdp-ntlm-info: 
|   Target_Name: SEVENKINGDOMS
|   NetBIOS_Domain_Name: SEVENKINGDOMS
|   NetBIOS_Computer_Name: KINGSLANDING
|   DNS_Domain_Name: sevenkingdoms.local
|   DNS_Computer_Name: kingslanding.sevenkingdoms.local
|   DNS_Tree_Name: sevenkingdoms.local
|   Product_Version: 10.0.17763
|_  System_Time: 2022-07-03T15:16:37+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
5986/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_ssl-date: 2022-07-03T15:17:20+00:00; 0s from scanner time.
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=VAGRANT
| Subject Alternative Name: DNS:VAGRANT, DNS:vagrant
| Not valid before: 2022-06-27T15:18:01
|_Not valid after:  2025-06-26T15:18:01
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49678/tcp open  msrpc         Microsoft Windows RPC
49680/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
49708/tcp open  msrpc         Microsoft Windows RPC
59098/tcp open  msrpc         Microsoft Windows RPC
MAC Address: 08:00:27:57:A4:F2 (Oracle VirtualBox virtual NIC)
Service Info: Host: KINGSLANDING; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_nbstat: NetBIOS name: KINGSLANDING, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:57:a4:f2 (Oracle VirtualBox virtual NIC)
| smb2-time: 
|   date: 2022-07-03T15:16:34
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

Nmap scan report for winterfell.north.sevenkingdoms.local (192.168.56.11)
Host is up (0.00068s latency).
Not shown: 65513 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-07-03 15:14:49Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sevenkingdoms.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=winterfell.north.sevenkingdoms.local
| Subject Alternative Name: othername:<unsupported>, DNS:winterfell.north.sevenkingdoms.local
| Not valid before: 2022-06-30T13:20:52
|_Not valid after:  2023-06-30T13:20:52
|_ssl-date: 2022-07-03T15:17:20+00:00; 0s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sevenkingdoms.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=winterfell.north.sevenkingdoms.local
| Subject Alternative Name: othername:<unsupported>, DNS:winterfell.north.sevenkingdoms.local
| Not valid before: 2022-06-30T13:20:52
|_Not valid after:  2023-06-30T13:20:52
|_ssl-date: 2022-07-03T15:17:20+00:00; 0s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sevenkingdoms.local0., Site: Default-First-Site-Name)
|_ssl-date: 2022-07-03T15:17:20+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=winterfell.north.sevenkingdoms.local
| Subject Alternative Name: othername:<unsupported>, DNS:winterfell.north.sevenkingdoms.local
| Not valid before: 2022-06-30T13:20:52
|_Not valid after:  2023-06-30T13:20:52
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sevenkingdoms.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=winterfell.north.sevenkingdoms.local
| Subject Alternative Name: othername:<unsupported>, DNS:winterfell.north.sevenkingdoms.local
| Not valid before: 2022-06-30T13:20:52
|_Not valid after:  2023-06-30T13:20:52
|_ssl-date: 2022-07-03T15:17:20+00:00; 0s from scanner time.
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=winterfell.north.sevenkingdoms.local
| Not valid before: 2022-06-27T22:49:00
|_Not valid after:  2022-12-27T22:49:00
|_ssl-date: 2022-07-03T15:17:20+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: NORTH
|   NetBIOS_Domain_Name: NORTH
|   NetBIOS_Computer_Name: WINTERFELL
|   DNS_Domain_Name: north.sevenkingdoms.local
|   DNS_Computer_Name: winterfell.north.sevenkingdoms.local
|   DNS_Tree_Name: sevenkingdoms.local
|   Product_Version: 10.0.17763
|_  System_Time: 2022-07-03T15:16:36+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
5986/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| tls-alpn: 
|_  http/1.1
|_http-server-header: Microsoft-HTTPAPI/2.0
|_ssl-date: 2022-07-03T15:17:20+00:00; 0s from scanner time.
|_http-title: Not Found
| ssl-cert: Subject: commonName=VAGRANT
| Subject Alternative Name: DNS:VAGRANT, DNS:vagrant
| Not valid before: 2022-06-27T15:21:08
|_Not valid after:  2025-06-26T15:21:08
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
49702/tcp open  msrpc         Microsoft Windows RPC
65091/tcp open  msrpc         Microsoft Windows RPC
MAC Address: 08:00:27:3E:C3:EF (Oracle VirtualBox virtual NIC)
Service Info: Host: WINTERFELL; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_nbstat: NetBIOS name: WINTERFELL, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:3e:c3:ef (Oracle VirtualBox virtual NIC)
| smb2-time: 
|   date: 2022-07-03T15:16:37
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

Nmap scan report for essos.local (192.168.56.12)
Host is up (0.00046s latency).
Not shown: 65513 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-07-03 15:15:01Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: essos.local, Site: Default-First-Site-Name)
|_ssl-date: 2022-07-03T15:17:20+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=meereen.essos.local
| Subject Alternative Name: othername:<unsupported>, DNS:meereen.essos.local
| Not valid before: 2022-06-29T08:30:39
|_Not valid after:  2023-06-29T08:30:39
445/tcp   open  microsoft-ds  Windows Server 2016 Standard Evaluation 14393 microsoft-ds (workgroup: ESSOS)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: essos.local, Site: Default-First-Site-Name)
|_ssl-date: 2022-07-03T15:17:20+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=meereen.essos.local
| Subject Alternative Name: othername:<unsupported>, DNS:meereen.essos.local
| Not valid before: 2022-06-29T08:30:39
|_Not valid after:  2023-06-29T08:30:39
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: essos.local, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=meereen.essos.local
| Subject Alternative Name: othername:<unsupported>, DNS:meereen.essos.local
| Not valid before: 2022-06-29T08:30:39
|_Not valid after:  2023-06-29T08:30:39
|_ssl-date: 2022-07-03T15:17:20+00:00; 0s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: essos.local, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=meereen.essos.local
| Subject Alternative Name: othername:<unsupported>, DNS:meereen.essos.local
| Not valid before: 2022-06-29T08:30:39
|_Not valid after:  2023-06-29T08:30:39
|_ssl-date: 2022-07-03T15:17:20+00:00; 0s from scanner time.
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2022-07-03T15:17:20+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=meereen.essos.local
| Not valid before: 2022-06-27T22:40:08
|_Not valid after:  2022-12-27T22:40:08
| rdp-ntlm-info: 
|   Target_Name: ESSOS
|   NetBIOS_Domain_Name: ESSOS
|   NetBIOS_Computer_Name: MEEREEN
|   DNS_Domain_Name: essos.local
|   DNS_Computer_Name: meereen.essos.local
|   DNS_Tree_Name: essos.local
|   Product_Version: 10.0.14393
|_  System_Time: 2022-07-03T15:16:38+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
5986/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_ssl-date: 2022-07-03T15:17:20+00:00; 0s from scanner time.
|_http-title: Not Found
| ssl-cert: Subject: commonName=VAGRANT
| Subject Alternative Name: DNS:VAGRANT, DNS:vagrant
| Not valid before: 2022-06-27T15:23:42
|_Not valid after:  2025-06-26T15:23:42
|_http-server-header: Microsoft-HTTPAPI/2.0
| tls-alpn: 
|   h2
|_  http/1.1
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49678/tcp open  msrpc         Microsoft Windows RPC
49680/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
60502/tcp open  msrpc         Microsoft Windows RPC
MAC Address: 08:00:27:33:DF:2F (Oracle VirtualBox virtual NIC)
Service Info: Host: MEEREEN; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2022-07-03T15:16:38
|_  start_date: 2022-07-03T13:56:01
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_nbstat: NetBIOS name: MEEREEN, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:33:df:2f (Oracle VirtualBox virtual NIC)
|_clock-skew: mean: 42m00s, deviation: 2h12m50s, median: 0s
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)
|   Computer name: meereen
|   NetBIOS computer name: MEEREEN\x00
|   Domain name: essos.local
|   Forest name: essos.local
|   FQDN: meereen.essos.local
|_  System time: 2022-07-03T08:16:38-07:00

Nmap scan report for castelblack.north.sevenkingdoms.local (192.168.56.22)
Host is up (0.00066s latency).
Not shown: 65525 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2022-07-03T13:57:05
|_Not valid after:  2052-07-03T13:57:05
|_ssl-date: 2022-07-03T15:17:20+00:00; 0s from scanner time.
| ms-sql-ntlm-info: 
|   Target_Name: NORTH
|   NetBIOS_Domain_Name: NORTH
|   NetBIOS_Computer_Name: CASTELBLACK
|   DNS_Domain_Name: north.sevenkingdoms.local
|   DNS_Computer_Name: castelblack.north.sevenkingdoms.local
|   DNS_Tree_Name: sevenkingdoms.local
|_  Product_Version: 10.0.17763
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=castelblack.north.sevenkingdoms.local
| Not valid before: 2022-06-27T22:56:08
|_Not valid after:  2022-12-27T22:56:08
| rdp-ntlm-info: 
|   Target_Name: NORTH
|   NetBIOS_Domain_Name: NORTH
|   NetBIOS_Computer_Name: CASTELBLACK
|   DNS_Domain_Name: north.sevenkingdoms.local
|   DNS_Computer_Name: castelblack.north.sevenkingdoms.local
|   DNS_Tree_Name: sevenkingdoms.local
|   Product_Version: 10.0.17763
|_  System_Time: 2022-07-03T15:16:40+00:00
|_ssl-date: 2022-07-03T15:17:20+00:00; 0s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
5986/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| ssl-cert: Subject: commonName=VAGRANT
| Subject Alternative Name: DNS:VAGRANT, DNS:vagrant
| Not valid before: 2022-06-27T15:26:52
|_Not valid after:  2025-06-26T15:26:52
| tls-alpn: 
|_  http/1.1
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
|_ssl-date: 2022-07-03T15:17:20+00:00; 0s from scanner time.
49666/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
MAC Address: 08:00:27:B9:6C:19 (Oracle VirtualBox virtual NIC)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2022-07-03T15:16:38
|_  start_date: N/A
| ms-sql-info: 
|   192.168.56.22:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_nbstat: NetBIOS name: CASTELBLACK, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:b9:6c:19 (Oracle VirtualBox virtual NIC)
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required

Stats: 0:09:09 elapsed; 4 hosts completed (5 up), 1 undergoing Script Scan
NSE Timing: About 99.93% done; ETC: 17:20 (0:00:00 remaining)
Nmap scan report for braavos.essos.local (192.168.56.23)
Host is up (0.00044s latency).
Not shown: 65524 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Windows Server 2016 Standard Evaluation 14393 microsoft-ds
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   Target_Name: ESSOS
|   NetBIOS_Domain_Name: ESSOS
|   NetBIOS_Computer_Name: BRAAVOS
|   DNS_Domain_Name: essos.local
|   DNS_Computer_Name: braavos.essos.local
|   DNS_Tree_Name: essos.local
|_  Product_Version: 10.0.14393
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2022-07-03T13:57:51
|_Not valid after:  2052-07-03T13:57:51
|_ssl-date: 2022-07-03T15:20:40+00:00; 0s from scanner time.
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: ESSOS
|   NetBIOS_Domain_Name: ESSOS
|   NetBIOS_Computer_Name: BRAAVOS
|   DNS_Domain_Name: essos.local
|   DNS_Computer_Name: braavos.essos.local
|   DNS_Tree_Name: essos.local
|   Product_Version: 10.0.14393
|_  System_Time: 2022-07-03T15:20:00+00:00
| ssl-cert: Subject: commonName=braavos.essos.local
| Not valid before: 2022-06-27T22:56:08
|_Not valid after:  2022-12-27T22:56:08
|_ssl-date: 2022-07-03T15:20:40+00:00; 0s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
5986/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| ssl-cert: Subject: commonName=VAGRANT
| Subject Alternative Name: DNS:VAGRANT, DNS:vagrant
| Not valid before: 2022-06-27T15:30:05
|_Not valid after:  2025-06-26T15:30:05
| tls-alpn: 
|   h2
|_  http/1.1
|_ssl-date: 2022-07-03T15:20:40+00:00; 0s from scanner time.
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49669/tcp open  msrpc         Microsoft Windows RPC
49685/tcp open  msrpc         Microsoft Windows RPC
49778/tcp open  msrpc         Microsoft Windows RPC
MAC Address: 08:00:27:A3:67:1D (Oracle VirtualBox virtual NIC)
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2022-07-03T15:20:00
|_  start_date: 2022-07-03T13:57:42
|_nbstat: NetBIOS name: BRAAVOS, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:a3:67:1d (Oracle VirtualBox virtual NIC)
| ms-sql-info: 
|   192.168.56.23:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)
|   Computer name: braavos
|   NetBIOS computer name: BRAAVOS\x00
|   Domain name: essos.local
|   Forest name: essos.local
|   FQDN: braavos.essos.local
|_  System time: 2022-07-03T08:20:00-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 52m29s, deviation: 2h28m29s, median: 0s

Post-scan script results:
| clock-skew: 
|   0s: 
|     192.168.56.11 (winterfell.north.sevenkingdoms.local)
|     192.168.56.22 (castelblack.north.sevenkingdoms.local)
|     192.168.56.12 (essos.local)
|     192.168.56.10 (sevenkingdoms.local)
|_    192.168.56.23 (braavos.essos.local)
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 5 IP addresses (5 hosts up) scanned in 572.00 seconds
```

- Ok we now know all the hosts and service exposed, let try an anonymous enumeration in the second part: [Goad pwning part2]({% link _posts/2022-07-04-GOADv2-pwning-part2.md %})
