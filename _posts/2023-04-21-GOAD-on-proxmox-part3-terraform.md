---
layout: post
title:  "GOAD on proxmox - Part3 - Providing with Terraform"
category : [AD, proxmox]
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
cd /root/GOAD/ad/GOAD/providers/proxmox/terraform
cp variables.tf.template variables.tf
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

variable "pm_full_clone" {
  default = false
}

# change this value with the id of your templates (win10 can be ignored if not used)
variable "vm_template_id" {
  type = map(number)

  # set the ids according to your templates
  default = {
      "WinServer2019_x64"  = 0
      "WinServer2016_x64"  = 0
      "Windows10_22h2_x64" = 0
  }
}

variable "storage" {
  # change this with the name of the storage you use
  default = "local"
}

variable "network_bridge" {
  default = "vmbr3"
}

variable "network_model" {
  default = "e1000"
}

variable "network_vlan" {
  default = 10
}
```

## Terraform recipe 

- The terraform recipe got this format for each computer :

```
resource "proxmox_virtual_environment_vm" "bgp" {
  for_each = var.vm_config

    name = each.value.name
    description = each.value.desc
    node_name   = var.pm_node
    pool_id     = var.pm_pool

    operating_system {
      type = "win10"
    }

    cpu {
      cores   = each.value.cores
      sockets = 1
    }

    memory {
      dedicated = each.value.memory
    }

    clone {
      vm_id = lookup(var.vm_template_id, each.value.clone, -1)
      full  = var.pm_full_clone
    }

    agent {
      # read 'Qemu guest agent' section, change to true only when ready
      enabled = true
    }

    network_device {
      bridge  = var.network_bridge
      model   = var.network_model
      vlan_id = var.network_vlan
    }

    lifecycle {
      ignore_changes = [
        vga,
      ]
    }

    initialization {
      datastore_id = var.storage
      dns {
        servers = [
          each.value.dns,
          "1.1.1.1",
        ]
      }
      ip_config {
        ipv4 {
          address = each.value.ip
          gateway = each.value.gateway
        }
      }
    }
}
...
```

- A global variable vm_config is setup at the start off the goad.tf template which describe each computer

```
variable "vm_config" {
  type = map(object({
    name               = string
    desc               = string
    cores              = number
    memory             = number
    clone              = string
    dns                = string
    ip                 = string
    gateway            = string
  }))

  default = {
    "dc01" = {
      name               = "GOAD-DC01"
      desc               = "DC01 - windows server 2019 - 192.168.10.10"
      cores              = 2
      memory             = 3096
      clone              = "WinServer2019_x64"
      dns                = "192.168.10.1"
      ip                 = "192.168.10.10/24"
      gateway            = "192.168.10.1"
    }
    ...
```

- For each VM we will configure ram, cpu, target pool, name, description and the template to use (the corresponding template id should be set in the variable file)
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

![terraform_plan.png](/assets/blog/proxmox/terraform_plan.png)

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

> update: Please note that the provider as change on recent version of GOAD.
> - the old provider was telmate : https://registry.terraform.io/providers/Telmate/proxmox/latest
> - the new provider is now bgp : https://registry.terraform.io/providers/bpg/proxmox/latest
> BGP is more active and more compatible with proxmox 8, which solve a lot of issues.
> - If you have a previous install delete the files not includes in the repo, change the variable file according to the tempalte and redo a terrafom init
{: .prompt-tip }

# resources

fr:
- [https://blog.zedas.fr/posts/terraformer-son-server/](https://blog.zedas.fr/posts/terraformer-son-server/)

en:
- [https://registry.terraform.io/providers/Telmate/proxmox/latest/docs/resources/vm_qemu](https://registry.terraform.io/providers/Telmate/proxmox/latest/docs/resources/vm_qemu)
- [https://austinsnerdythings.com/2021/09/01/how-to-deploy-vms-in-proxmox-with-terraform/](https://austinsnerdythings.com/2021/09/01/how-to-deploy-vms-in-proxmox-with-terraform/)
- [https://lachlanlife.net/posts/2022-09-provisioning-vms/](https://lachlanlife.net/posts/2022-09-provisioning-vms/)
- [https://cloudalbania.com/posts/2022-01-homelab-with-proxmox-and-terraform/](https://cloudalbania.com/posts/2022-01-homelab-with-proxmox-and-terraform/)
- [https://yetiops.net/posts/proxmox-terraform-cloudinit-windows/](https://yetiops.net/posts/proxmox-terraform-cloudinit-windows/)
