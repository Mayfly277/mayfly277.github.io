---
layout: post
title:  "SCCM / MECM LAB - Part 0x0"
category : [AD, SCCM]
tags :  AD, SCCM
---

![SCCMLAB](/assets/blog/SCCM/SCCMLAB.png)

Some time ago i discovered the work of some researchers about SCCM, i was very interested by their research and as i reading i thought that i really need a lab to test all these cool attacks !

Thanks a lot to my colleague Issam ([@KenjiEndo15](https://twitter.com/KenjiEndo15)), who start the project and provide me some of ansible roles to start from !

After few ~~hours~~, ~~days~~, weeks of install, ansible recipe creation, try and retry. I am glad to announce a new lab on the [GOAD project](https://github.com/Orange-Cyberdefense/GOAD) : **SCCM**

This lab was created with the inspiration to test the following resources :
- [Github : Misconfiguration-Manager by specterOps](https://github.com/subat0mik/Misconfiguration-Manager/tree/main)
- [Youtube: SCCM Exploitation: The First Cred Is the Deepest II w/ Gabriel Prud'homme](https://www.youtube.com/watch?v=W9PC9erm_pI)
- [thehacker.recipes sccm-mecm](https://www.thehacker.recipes/a-d/movement/sccm-mecm)

Thanks to the writers, and thanks even more to all the searcher who have share all these findings about SCCM.

# Lab structure

![SCCMLAB_overview](/assets/blog/SCCM/SCCMLAB_overview.png)

The lab is build on top of 4 Vms:
- **DC.sccm.lab** :  Domain Controler 
- **MECM.sccm.lab** : mecm primary site serer
- **MSSQL.sccm.lab** : mecm sql server
- **CLIENT.sccm.lab** : mecm client computer

All vms are build on top of a windows server 2019 evaluation.

The lab is build around Microsoft Endpoint Configuration manager (a new name for SCCM : System Center Configuration Manager), the lab was named SCCM just because most of papers talk about SCCM and also i prefer this name ;)

> SMS / SCCM / MECM /ConfigMgr : ok that's the same product just different names and features over the years :
> - SMS : System Management Server
> - SCCM : System Center Configuration Manager
> - MECM : Microsoft Endpoint Configuration manager
> - ConfigMgr : Configuration Manager
{: .prompt-info } 

# Prerequisites
Just like for the GOAD lab you need some requirements to be installed before launching the lab install (the prerequisites are exactly the same as GOAD lab so if you have already install GOAD you should be fine)

- Vmware or Virtualbox ready and working
- Python >= 3.8

- Install script for ubuntu 22.04 (LTS) :
> If you are on an old ubuntu don't panic just install python3.8 and replace python3 by python3.8 in the commands below

```bash
# Install VirtualBox
sudo apt install virtualbox

# Install vagrant
wget -O- https://apt.releases.hashicorp.com/gpg | gpg --dearmor | sudo tee /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install vagrant

# Vagrant plugins
vagrant plugin install vagrant-vbguest

# If you use vmware
wget https://releases.hashicorp.com/vagrant-vmware-utility/1.0.22/vagrant-vmware-utility_1.0.22-1_amd64.deb
sudo dpkg -i vagrant-vmware-utility_1.0.22-1_amd64.deb
sudo systemctl start vagrant-vmware-utility
vagrant plugin install vagrant-vmware-desktop

# gem for winrm with ansible
gem install winrm winrm-fs winrm-elevated

# install some additional packages
sudo apt install sshpass lftp rsync openssh-client

# install project requirements
git clone https://github.com/Orange-Cyberdefense/GOAD.git
cd GOAD
sudo apt install python3-venv
python3 -m virtualenv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install ansible-core==2.12.6
python3 -m pip install pywinrm
ansible-galaxy install -r ansible/requirements.yml
```

# Install

- Just like goad lab the install is pretty simple:

```bash
source .venv/bin/activate
./goad.sh -t check -l SCCM -p vmware -m local
./goad.sh -t install -l SCCM -p vmware -m local
```

- The install is pretty big, you need 116 GB of disk space.
- Also during the install a lot of things are downloaded (windows iso, mecm installer, mssql installer,...) so be sure to have a good internet connection because multiple GB will be downloaded.

- If all goes well you should see this message at the end of the install :

![build_finish.png](/assets/blog/SCCM/build_finish.png)

> As comparison a GOAD installation take around 100 minutes to run.

# Install verifications

If all goes well you should have a working lab with configuration manager installed.
Let's verify if all is ok :

- Connect to MECM$ with the following credentials : dave/dragon (be carefull with qwerty/azerty)
![connect_as_dave.png](/assets/blog/SCCM/connect_as_dave.png)

- Open the configuration manager console
![console.png](/assets/blog/SCCM/console.png)

- Check if the clients are well enrolled (you should have a green check and client active on MSSQL, MECM and CLIENT computers)
![clients_ok.png](/assets/blog/SCCM/clients_ok.png)

- The distribution of boot images and operating system for pxe should be ok too
![distribution_status.png](/assets/blog/SCCM/distribution_status.png)

If all is ok you should have the same results has the screenshots before.

# Vulnerabilities

- SpecterOps team (@subat0mik, @garrfoster and @_Mayyhem) as done a great work to classify sccm attack in the website : 
[https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/_attack-techniques-list.md](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/_attack-techniques-list.md)
- To be clear We will take the notation they use on their repository in order to reproduce the attacks in the lab.
- All the attacks which are not present are not checked in the list bellow and the reason why is also described.

## present in the lab
Without creds:
- [X] cred-1 - PXE Credentials : Retrieve secrets from PXE boot media

With low users creds from linux :
- [X] recon-1 - ldap enumeration
- [X] recon-2 - smb enumeration
- [X] recon-3 - http enumeration
- [X] takeover-1 - Relay to Site DB (MSSQL)
- [X] takeover-2 - Relay to Site DB SMB

With low user creds from windows:
- [X] elevate-2 - Relay Client Push Installation

With machine account creds:
- [X] cred-2 - Policy Request Credentials

With admin access on client:
- [X] cred-3 - DPAPI Credentials
- [X] cred-4 - Legacy Credentials

With sccm admin account
- [X] cred-5 - Site Database Credentials
- [X] exec-1 - App Deployment
- [X] exec-2 - Script Deployment
- [X] recon-4 - CMPivot
- [X] recon-5 - SMS Provider Enumeration

## not present in the lab
The following attacks are not present du to the lab characteristics :

With low users creds :
- [ ] elevate-1 - Relay to Site System (SMB) (no separate siteserver to relay)
- [ ] takeover 3 - Relay to AD CS (no adcs in this lab)
- [ ] takeover 4 - Relay cas to child (no separate cas in the lab)
- [ ] takeover 5 - Relay to AdminService (no separate sms provider)
- [ ] takeover 6 - Relay to SMS (no separate sms provider)
- [ ] takeover 7  -Relay Between HA (no secondary site)
- [ ] takeover-8 - Relay http to LDAP (no webclient on MECM$)

With db users creds:
- [ ] takeover 9 - SQL Linked as DBA  (no sql link)

## What's Next ?

- All these SCCM/MECM attack process will be described in the following blog posts, if you can't wait go to [missconfiguration manager github repository](https://github.com/subat0mik/Misconfiguration-Manager/) , all is very well described ;)

- Next post: ([SCCM LAB part 0x1]({% link _posts/2024-03-28-SCCM-LAB-part0x1.md %}))
