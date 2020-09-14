Linux Foundation Certified Engineer

# Managing Networking Basics
## network administration
### Managing Network Configuration with ifconfig or ip

> ip help
> ip address help
> ip addr add dev eth0 172.17.0.5/16
> yum provides ifconfig
> yum install net-tools
> ifconfig 
> ip -s link RX (receive bytes) and TX(Transmit bytes)

### Managing Persistent Network Configurations

> yum install  NetworkManager-tui
> vi  /etc/sysconfig/network-scripts/ifcfg-ens3
> IPADDR
> DNS
> GATEWAY
> ONBOOT
> ifdown eth0
> ifup eth0
> ubuntu vi /etc/network/interfaces
> iface eth1 inet static
> address 192.168.4.140
> netmask 255.255.255.0
> gateway 192.168.4.2
> ifdown eth1
> ifup eth1



### Configuring Static Routing

> ip route show
> systemctl restart network
> ubuntu /etc/network/interfaces
> up route add -net 0.0.0.0 netmask 0.0.0.0 gw x x x x dev eth1
> ifdown eth1 && ifup eth1
> route -n

### Configuring Dynamic Routing
> OSPF

+ Quagga - formerly known as Zebra - provides dynamic routing
+ > yum install quagga
+ It contains different daemons that have to be started / enabled
+ show rpm -ql quagga | grep systemd for a list of all daemons
> OSPF is the most common protocol for LAN(Open Shortest Path first)

> /etc/quagga/zebra.conf
> ospfd.conf
> daemons
> FRRouting(Centos 8)


### Configuring Gerneric Network Security

#### TCP Wrappers


+ Access is controlled through /etc/hosts.allow and /etc/hosts.deny
> These are respected by any service that uses libwrap, as well as the original inetd
> Patterns are specified to allow access: daemon:client
  + If a pattern matches in /etc/hosts.allow, traffice is permitted
  > If it is not in /etc/hosts.allow and it is in /etc/hosts.deny it will be denied
  > if it is in neither file ,traffice will be permitted
hosts.allow:
vsftpd: ALL
ALL: LOCAL
ALL: 192. EXCEPT .somewhere.com

hosts.deny
ALL: ALL

> man hosts_access
> man hosts_options
> ldd $(which sshd) | grep libwrap
> yum install vsftpd
> systemctl start vsftpd
> yum install lsftp

### Troubleshooting Networking issues

+ ping

> ping -f
> ping -f -s 4096

+ traceroute

> yum provides */traceroute
> yum install traceroute
> traceroute nulnl



+ nmap

> yum install nmap
> nmap  192.168.4.100
> nmap  -sn 192.168.4.0/24 # scan network


+ arp

> arp -d


+ telnet example.com 80 followed by GET 
  + You will need to 'speak' the right protocol
+ openssl s_client -connect example.com:443
+ tcpdump / wireshark
  + tcpdump -i eth0 -w capture.pcap port 22

+ ss (socket statistis)

> ss -tua

> netstat -tulpen

## network Monitoring & Reporting

### Monitoring Network Performance

+ ifconfig
+ ip -s link
+ ethtool -S eth0
+ iptraf

> yum install iptraf-ng
> iptraf-ng

+ ntop
> listen on 3000

> apt install ntop

### Understanding Network Performance parameters

> MTU
> TCP slide window


### Managing /proc Network parameters



### Producing system Report Using sar
### Using ss to Monitor Network Service Availiablity
### Using nmap to Verify Remote Port Availiablity




## Implementing Packet Filtering
## Managing Remote Access





# Managing File Service

## Samba 
## NFS
## FTP
# Managing Web Services
## Apache
## Suid Proxy 
## Nginx
# Managing Mail Services
# Managing Infrastructure Services
## DNS
## Docker Containers
## Setting up an IPA server as a central LDAP and certificate server
