---
layout: post
title:  "GOAD on proxmox - Part3 - Providing with Terraform"
category : proxmox
tags :  AD, Lab, terraform, proxmox
---

![terraform-logo.png](/assets/blog/proxmox/terraform-logo.png)

To providing the vm we will use terraform, the official documentation for proxmox and Qemu can be found here : [https://registry.terraform.io/providers/Telmate/proxmox/latest/docs/resources/vm_qemu](https://registry.terraform.io/providers/Telmate/proxmox/latest/docs/resources/vm_qemu)

## Prepare proxmox

- terraform use a lot of permission and i haven't make the work to find all the special permissions to enable so we will go dirty by giving the PVEAdmin permission to our infra_as_code user ^^

```bash
pveum acl modify / -user 'infra_as_code@pve' -role Administrator
```

## Configure terraform

- First we go the provioning machine : `ssh goadprovisioning`

```
cd /root/GOAD/providers/proxmox/terraform
cp variables.template variables.tf
```

- And we setup the variables.tf file : 

```
variable "pm_api_url" {
  default = "https://192.168.1.1:8006/api2/json"
}

variable "pm_user" {
  default = "infra_as_code@pve"
}

variable "pm_password" {
  default = "changeme"
}

variable "pm_node" {
  default = "proxmox-goad"
}

variable "pm_pool" {
  default = "GOAD"
}
```

## Terraform recipe 

- The terraform recipe got this format for each computer :

```
resource "proxmox_vm_qemu" "dc01" {
    name = "DC01"
    desc = "DC01 - windows server 2019 - 192.168.10.10"
    qemu_os = "win10"
    target_node = var.pm_node
    pool = var.pm_pool

    sockets = 1
    cores = 2
    memory = 4096
    agent = 1
    clone = "WinServer2019x64-cloudinit"

    network {
     bridge    = "vmbr3"
     model     = "e1000"
     tag       = 10
    }

    lifecycle {
      ignore_changes = [
        disk,
      ]
    }

   nameserver = "192.168.10.1"
   ipconfig0 = "ip=192.168.10.10/24,gw=192.168.10.1"
}
...
```

- For each VM we will configure ram, cpu, target pool, name, description and the template to use.
- We will also setup the network adapter with static ip (this will setup the ip on cloudinit and the service will change our vm ip and gateway).
- And we configure the nameserver to our pfsense : 192.168.10.1 to give the vm dns resolution
- Here we will not setting up disk as we will use the one defined during the template creation phase, if we add disk here it will add more disk to the vm but 40Go for each vm is already enough and we don't need another disk.

>I have tried multiple time to make all work with virtio adapters, but the ansible domain join failed every time with that adapter. When switched to e1000 all was ok.

## VM creation

- Then we init terraform to download the plugin and prepare the terraform folder :
```bash
terraform init
```

- We run plan to prepare the VM creation :
```bash
terraform plan -out goad.plan
```

![terraform_plan.png](/assets/blog/GOAD/terraform_plan.png)

- And we launch the vm creation with apply :
```bash
terraform apply "goad.plan"
```

And after ~20-25 minutes the 5 vms are created.

> If you got an error during this phase just relaunch plan and apply to not recreate everything. Timeout or other errors could append, but if you are lucky enough, all will be complete in one try ;)

![terraform_complete.png](/assets/blog/proxmox/terraform_complete.png)

- We now got 5 windows VM up and running in our lab (just like we done on our computer with vagrant up).
- As you can see we use a lot of memory but the CPU and HDD space are fine.

![terraform_complete2.png](/assets/blog/proxmox/terraform_complete2.png)

- Now wait some minutes as all vm will restart one after the other due to cloud-init IP configuration.


# resources

fr:
- [https://blog.zedas.fr/posts/terraformer-son-server/](https://blog.zedas.fr/posts/terraformer-son-server/)

en:
- [https://registry.terraform.io/providers/Telmate/proxmox/latest/docs/resources/vm_qemu](https://registry.terraform.io/providers/Telmate/proxmox/latest/docs/resources/vm_qemu)
- [https://austinsnerdythings.com/2021/09/01/how-to-deploy-vms-in-proxmox-with-terraform/](https://austinsnerdythings.com/2021/09/01/how-to-deploy-vms-in-proxmox-with-terraform/)
- [https://lachlanlife.net/posts/2022-09-provisioning-vms/](https://lachlanlife.net/posts/2022-09-provisioning-vms/)
- [https://cloudalbania.com/posts/2022-01-homelab-with-proxmox-and-terraform/](https://cloudalbania.com/posts/2022-01-homelab-with-proxmox-and-terraform/)
- [https://yetiops.net/posts/proxmox-terraform-cloudinit-windows/](https://yetiops.net/posts/proxmox-terraform-cloudinit-windows/)
