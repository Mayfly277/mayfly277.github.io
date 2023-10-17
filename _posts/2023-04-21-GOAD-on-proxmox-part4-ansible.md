---
layout: post
title:  "GOAD on proxmox - Part4 - Provisioning with Ansible"
category : proxmox
tags :  AD, Lab, Ansible, proxmox
---

![ansible-logo.png](/assets/blog/proxmox/ansible-logo.png)

If you followed the 3 previous part, you should have a running proxmox instance with the 5 windows vm in it.
On part 4 we will setup all the GOAD configuration with ansible.

- An inventory file is already setup for proxmox and can be found on the folder GOAD/ad/GOAD/providers/proxmox/inventory

## Setup inventory

```
[default]                                                 
; Note: ansible_host *MUST* be an IPv4 address or setting things like DNS
; servers will break.                
; ------------------------------------------------  
; sevenkingdoms.local
; ------------------------------------------------
dc01 ansible_host=192.168.10.10 dns_domain=dc01 dict_key=dc01
; ------------------------------------------------
; north.sevenkingdoms.local
; ------------------------------------------------
dc02 ansible_host=192.168.10.11 dns_domain=dc01 dict_key=dc02       
srv02 ansible_host=192.168.10.22 dns_domain=dc02 dict_key=srv02
; ------------------------------------------------           
; essos.local
; ------------------------------------------------
dc03 ansible_host=192.168.10.12 dns_domain=dc03 dict_key=dc03
srv03 ansible_host=192.168.10.23 dns_domain=dc03 dict_key=srv03
; ------------------------------------------------                  
; Other                                                  
; ------------------------------------------------
elk ansible_host=192.168.10.50 ansible_connection=ssh
                                                                    
[all:vars]
; domain_name : folder inside ad/
domain_name=proxmox-sevenkingdoms.local                    
                                                                    
force_dns_server=yes
dns_server=192.168.10.1                                             
                                                                    
two_adapters=no
nat_adapter=Ethernet 2
domain_adapter=Ethernet 2
...
```

- The changes between GOAD/ad/GOAD/providers/proxmox/inventory and GOAD/ad/GOAD/providers/virtualbox/inventory are :
  - the machine's IP
  - force_dns_server and dns_server : to force dns_server to value 192.168.10.1 on the start of the ansible playbook to give internet to the virtual machine
  - two_adapters with the value "no", to disable all the mechanisms which enable/disable one adapter during the domain installation.

- Another global inventory is also available at GOAD/ad/GOAD/data/inventory containing the project scenario

## Install the requirements

```bash
cd /root/GOAD/ansible
ansible-galaxy install -r requirements.yml
```

## Run the playbook

```bash
cd /root/GOAD/ansible
export ANSIBLE_COMMAND="ansible-playbook -i ../ad/GOAD/data/inventory -i ../ad/GOAD/providers/proxmox/inventory"
../scripts/provisionning.sh
```

And wait until all the lab complete :

![ansible_complete.png](/assets/blog/proxmox/ansible_complete.png)

- If the playbook fail just relaunch it.

- If you got this error : 
![ansible_error.png](/assets/blog/proxmox/ansible_error.png)

- Maybe some rule miss on your firewall you could try to add some.


## Create snapshots

- Now our lab is complete and we don't want to do all that steps every time we want to trash and recreate our lab.

```bash
qm list
VMID NAME                 STATUS     MEM(MB)    BOOTDISK(GB) PID       
100 pfsense              running    4096              40.00 9015      
102 WinServer2019x64-cloudinit stopped    4096              40.00 0         
103 WinServer2016x64-cloudinit stopped    4096              40.00 0         
104 SRV03                running    4096              40.00 14964     
105 DC02                 running    4096              40.00 36555     
106 DC03                 running    4096              40.00 14819     
107 SRV02                running    4096              40.00 32841     
108 DC01                 running    4096              40.00 20459     
```

- So let's create snapshots :

```bash
vms=("DC01" "DC02" "DC03" "SRV02" "SRV03")
COMMENT="after ansible"
# Loop over the array
for vm in "${vms[@]}"
do
  echo "[+] Create snapshot for $vm"
  id=$(qm list | grep $vm  | awk '{print $1}')
  echo "[+] VM id is : $id"
  qm snapshot "$id" 'snapshot-'$(date '+%Y-%m-%d--%H-%M') --vmstate 1 --description "$COMMENT"
done
```

![create_snapshots.png](/assets/blog/proxmox/create_snapshots.png)
