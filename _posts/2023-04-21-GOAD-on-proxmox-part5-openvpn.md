---
layout: post
title:  "GOAD on proxmox - Part5 - VPN access with openvpn"
category : proxmox
tags :  AD, Lab, Openvpn, proxmox
---

![open_vpn_logo.png](/assets/blog/proxmox/open_vpn_logo.png)

Now our lab is up and running, but we need to make an easy access on it.
Like a lot of ctf with active directory we will create a VPN access to our lab.

To do that we will create an openvpn access with pfsense.
A blog post already explain this phase very well and in details : [https://www.it-connect.fr/pfsense-configurer-un-vpn-ssl-client-to-site-avec-openvpn/](https://www.it-connect.fr/pfsense-configurer-un-vpn-ssl-client-to-site-avec-openvpn/), we will here follow these steps and adapt it to our configuration.

# Create openvpn access

## Create certificate autority

- System > certmanager
- Add an new CAs

![openvpn_addca.png](/assets/blog/proxmox/openvpn_addca.png)

- add a name to the ca and create it

![openvpn_addca2.png](/assets/blog/proxmox/openvpn_addca2.png)

## Create certificate server

- Create the server certificate, set the certificate authority created before, a descriptive name, a common name like "vpn.goad.lab", a lifetime duration and a certificate type "server certificate"

![openvpn_sense2.png](/assets/blog/proxmox/openvpn_sense2.png)

![openvpn_server_certificate.png](/assets/blog/proxmox/openvpn_server_certificate.png)

- And save it

## Create local user

- In order to use the vpn we will create local users
- Go to System > User manager > user
- Create a non login user with a certificate attached to the certificate authority

![openvpn_createusers.png](/assets/blog/proxmox/openvpn_createusers.png)


## Create open vpn service

- Got to VPN > openVPN
- Add a new server

![openvpn_cerate_server.png](/assets/blog/proxmox/openvpn_cerate_server.png)

![openvpn_cerate_server2.png](/assets/blog/proxmox/openvpn_cerate_server2.png)

![openvpn_cerate_server3.png](/assets/blog/proxmox/openvpn_cerate_server3.png)

- Add network configuration
![openvpn_cerate_server4.png](/assets/blog/proxmox/openvpn_cerate_server4.png)
![openvpn_cerate_server5.png](/assets/blog/proxmox/openvpn_cerate_server5.png)

## Add package openvpn client export

System > Package Manager > Available Packages
![openvpn_addpackage.png](/assets/blog/proxmox/openvpn_addpackage.png)

- Install the package
- Now got to VPN > OpenVPN > client export
- And export the certificate 


## Download and use certificate

- Now go to VPN > openvpn > client export 

- Change the host name resolution to other :

![openvpn_setup_hostname.png](/assets/blog/proxmox/openvpn_setup_hostname.png)

- In the bottom of the page you can download your vpn configuration

![openvpn_export.png](/assets/blog/proxmox/openvpn_export.png)


## Configure firewall

- Now we will review the firewall rules :

- WAN

![fw_rules_wan.png](/assets/blog/proxmox/fw_rules_wan.png)

- LAN

![fw_rules_lan.png](/assets/blog/proxmox/fw_rules_lan.png)

- VLAN

![fw_rules_vlan_goad.png](/assets/blog/proxmox/fw_rules_vlan_goad.png)

- OPENVPN

![fw_rules_vlan_openvpn.png](/assets/blog/proxmox/fw_rules_vlan_openvpn.png)

## Connect

- And now you could connect to the VPN and enjoy :)

![openvpn_connected.png](/assets/blog/proxmox/openvpn_connected.png)

- And now you can use it as your lab !

![openvpn_cme.png](/assets/blog/proxmox/openvpn_cme.png)

- If you want to listen for responder you can also add a CT in the vlan10 to listen LLMNR request.

## resources

FR: 
- [https://www.it-connect.fr/pfsense-configurer-un-vpn-ssl-client-to-site-avec-openvpn/](https://www.it-connect.fr/pfsense-configurer-un-vpn-ssl-client-to-site-avec-openvpn/)

EN:
- [https://www.wundertech.net/how-to-create-firewall-rules-in-pfsense/](https://www.wundertech.net/how-to-create-firewall-rules-in-pfsense/)
- [https://docs.netgate.com/pfsense/en/latest/firewall/configure.html](https://docs.netgate.com/pfsense/en/latest/firewall/configure.html)
- [https://www.wundertech.net/how-to-set-up-openvpn-on-pfsense/](https://www.wundertech.net/how-to-set-up-openvpn-on-pfsense/)