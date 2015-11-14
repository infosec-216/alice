#!/bin/bash

ROUTER=192.168.0.111
SLEUTH=192.168.0.131
SUSPECT=192.168.0.120

#sysctl -w net.ipv4.ip_forward="1"
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -I FORWARD -s $SUSPECT -j ACCEPT
iptables -I FORWARD -d $SUSPECT -j ACCEPT
iptables -t nat -I POSTROUTING -s $SUSPECT -j MASQUERADE
