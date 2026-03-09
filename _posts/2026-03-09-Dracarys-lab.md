---
layout: post
title:  Dracarys
category : [AD, GOAD, Dracarys]
tags :  AD, Dracarys
image:
  path: /assets/blog/DRACARYS/dracarys_logo.png
  alt: Dracarys - writeup
---

DRACARYS is a new lab environment challenge (not for beginners) on GOAD : [https://github.com/Orange-Cyberdefense/GOAD](https://github.com/Orange-Cyberdefense/GOAD)

The lab consists of **three machines**: two Windows Server 2025 (one DC and one server) and one Ubuntu 24.04 server. All connected to the same Active Directory domain "dracarys.lab".

The lab start on the **Linux machine with the .12 IP**, which serves as the starting point for reconnaissance and exploitation. The Ubuntu server is fully integrated into the domain, allowing us to (you will see :p).
During the exploitation process, several techniques and tools will need to be used.

The lab is available for the following providers:
* virtualbox
* vmware
* ludus
* proxmox
* aws
* azure


DRACARYS is written as a training challenge where GOAD was written as a lab with a maximum of vulns.
- You should find your way in to get domain admin on the domain dracarys.lab
- Using vagrant user is prohibited of course ^^
-Starting point is on lx01 : <ip_range>.12
- Obviously do not cheat by looking at the passwords and flags in the recipe files, the lab must start without user to full compromise.

- If you use goad previously your ansible requirements may not be up to date. Be sure to do this before the install:

```bash
source ~/.goad/.venv/bin/activate
cd ~/GOAD/ansible

# if you python is >=3.11
ansible-galaxy install -r requirements_311.yml 
# if you got a python <3.10
ansible-galaxy install -r requirements.yml 
```

- And install with :

```bash
./goad.sh -t install -l DRACARYS -p <provider>
```

or

```bash
./goad.sh
> set_lab DRACARYS
> set_provider <your_provider>
> set_iprange 192.168.56  # select the one you want and you can skip this with ludus
> install
```


- Once install finish disable vagrant user to avoid using it :

```bash
./goad.sh
> load <instance_id>
> disable_vagrant
```

- Now do a reboot of all the machine to avoid unintended secrets stored : 

```bash
> stop
> start
```

And you are ready to play ! :)

- If you need to re-enable vagrant

```bash
> load <instance_id>
> enable_vagrant
```

- If you want to create a write up of the chall, no problem, have fun. Please ping me on X (@M4yFly) or Discord, i will be happy to read it :)

> If you use aws or azure, i recommend you to exploit directly from the jump host to avoid any clock/kerberos issues ;)
{: .prompt-tip }

Stay tuned for more detailed walkthroughs on specific exploitation techniques within LINUX.

