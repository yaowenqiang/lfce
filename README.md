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

+ dstat

> yum install dstat

> dstat -n
> dstat --output output.csv

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

> sysctl -a
> sysctl -a | grep net
> cd /proc/sys/net
> yum search kernel | grep doc
> yum install kernel-doc
> cd /usr/share/doc/kernel-doc-3.10.0
> grep -Rl dsack 2>/dev/null
> networking/ip-sysctl.txt
> ls networking/ip-syctl.txt
> /tcp_wmem

### Producing system Report Using sar

> yum install sysstat
> /etc/cron.d/sysstat
> /var/log/sa 
> sar -n ALL

### Using ss to Monitor Network Service Availiablity


> ss -tuna # don't resolve service names
> ss -ltn 
> ss -at '( dport = :ssh or sport = :ssh )'
> ss -at dst :443 or dst :80


### Using nmap to Verify Remote Port Availiablity

> nmap -sn 192.168.1.1
> nmap 192.168.1.0/24
> nmap -O 192.168.1.0/24 # check target operation system
> nmap -sS -sU -Pn 192.168.1.1
> nmap -sS -sU -Pn -o 1-56635 192.168.1.1
> nmap -sA 192.168.1.1 # firework scan
> man nmap


> ethtool -S eth0
> ssh -tuna


## Implementing Packet Filtering

### Understanding Linux Firewall Solutions

+ firewalld
+ ufw
+ susefirewall


### Understanding Iptables Working



### Setting up a Basic Iiptables Configurations

> systemctl status firewalld
> systemctl disable --now firewalld
> systemctl mask firewalld

> yum install iptables-services iptables-utils
> iptables -L
> ipables -P INPUT DROP
> ipables -P FORWARD DROP
> ipables -P input DROP

> iptables -A INPUT -i lo -j ACCEPT
> iptables -A OUTPUT -i lo -j ACCEPT

> iptables -A INPUT -p tcp --dport 80 -j ACCEPT
> iptables -A INPUT -p tcp --dport 443 -j ACCEPT
> iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# DNS
> iptables -I INPUT 2 -p tcp --dport 53 -j ACCEPT
> iptables -I INPUT 2 -p udp --dport 53 -j ACCEPT

> iptables -A OUT  -m state --state ESTABLISHED,RELEATED -j ACCEPT
> iptables -A OUT -p tcp --dport 80 -j ACCEPT
> iptables -A OUT -p tcp --dport 443 -j ACCEPT
> iptables -A OUT -p tcp --dport 22 -j ACCEPT
> iptables -L -v



### Making the Iptables Configuration Persistent

> iptables-save > /etc/sysconfig/iptables

### Configuring Iptables NAT

> iptables -A INPUT -p icmp -j ACCEPT
> cat /proc/sys/net/ipv4/ip_forward
> vim /etc/sysctl.conf
> cd /usr/lib/sysctl.d/
> grep ip_forward *
> cd /etc/sysctl.d/
> net.ipv4.ip_forward = 1
> iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
> iptables -t nat -A FORWARD -i eth0  -o eth0  --state  RELATED,ESTABLISHED -j ACCEPT
> iptables -A FORWARD -i eth0 -o eth0 -j ACCEPT



### Implementing Packet Filtering
### Using Logging for Iptabales Troubleshooting

> iptables -A INPUT -j LOG
> iptables -A OUTPUT -j LOG
> cat /var/log/messages
> iptables -A OUTPUT -p udp --dport 123 -j ACCEPT
> systemctl restart iptables
> iptables -A OUTPUT -p udp --dport 123 -j ACCEPT
> iptables -A INPUT -j LOG
> iptables -A OUTPUT -j LOG
> cat /etc/services


### Configuring Port Forwarding in Iptables

> iptables -A PREROUTING -t nat -i eth0 -p tcp --dport 2222 -j DNAT --t o10.0.0.20:22
> iptables -L -t nat
> grep 2222 /proc/net/nf_contrac





## Managing Remote Access
### An introduction to Croptography


Introducing Cryptography

+ Cryptography has different goals
  + Data integrity
  + Confidentiality
  + Authentication
  + Non-repudication
+ The two main tchonologies are shared secrect and public/private key encryption


Symmetric Key Disadvantages

+ A secure channel must exist for exchanging keys 
+ Keys should be changed frequently
+ For 1 to n communications, a unique key must exists for every communications channel
+ This make key management a real challenge


Shared Secrets

+ Sender and receiver use the same key to produce scrambled data
+ Block ciphers are the common approach, where blocks of data are scrambled
+ DES and AES are common standards, but old
  + Triple DES currently is still used often
+ Shared secret cryptography isn't very secure, but it's fast
+ Hashing is a technology where a longer string is represented by a shorter string
  + 2 strings will never generate the same hash
  + Used in password encryption
  + MD%, SHA and Bluwfish are current hashing technologies

Public Key Cryptography

+ Public key is commonly availiable; private key is derived from the public key and kept as a secret
+ Private keys uses
  + Decryption of messages that are encrypted with the public key of the recipient
  + Signing of messages
  + Non-repudiation
+ Certificate authority is required to guarantee the authenticity of a key


### Configuring SSH Key Based Authentication

> ssh-keygen -t dsa
> ssh-copy-id 192.168.1.2
> ssh-agent /bin/bash
> ssh-add




### Configuring SSH Tunneling and Port Forwarding

SSH Port Forwarding

+ From server1, type ssh -fNL 4444:rhacert.com:80 root@server2.example.com

> curl localhost:444  -> get rhacert.com content
> lsof -i4TCP:4444  | grep LISTEN



+ Compare to ssh -fNL 5555:localhost:80 root@192.168.10.10 where you'll see the webpage on server2, it's localhost on the server you'are connecting to, not on your actual server


> curl localhost:5555 > gget 80 on 192.168.10.10
+ Test with elinks http://localhost:4444
+ Remote port forwarding is less common and can be used to connect to a local port (which cannot be reached from the internet) to a port on a server that is available on the internet
  + ssh -的 80:localhost:8086 user@lab.xxx.com
  + You must change GatewayPorts and set to yes on your local machine for this to work
+ Monitor tunnels with lsof -i -n | grep sshd or netstat -tupen

### Optimizing SSH Performance

> man sshd_config

> vim /etc/ssh/sshd_config

> port
> listenAddress
> PermitRootLogin 
> AllowUseers username
> MaxSessions
> PasswordAuthentication 
> GSSAPIAuthentication 
> UseDNS
> TCPKeepAlive 
> ClientAliveInterval
> ClientAliveCountMax

### Managing SSH Client Options

> man ssh_config

> ForwardX11 
> StrictHostKeyChecking
> GSSAPIAuthentication  no


### Transfering Files Securely over the Network

> scp
> rsync
> yum provides */rsync
> yum insjtall -y rsync
> rysnc -r /rsync/ root@192.168.10.10:/rsync/
> dd if=/dev/zero of=bigfile bs=2m count=100
> rysnc -rv /rsync/ root@192.168.10.10:/rsync/

### Troubleshooting SSH issues

> sed -i -e '3d' .ssh/known_hosts



### Configuring VNC Server




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
