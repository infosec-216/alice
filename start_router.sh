#!/bin/bash

iptables -t nat -S
#iptables -t nat -D

export ROUTER=192.168.0.135
export SLEUTH=192.168.0.127
export SUSPECT=192.168.0.120
export REAL_ROUTER=192.168.0.1

ip rule list
#ip rule list del
ip route list table 111
export TABLE=111

ip rule add from $SUSPECT table $TABLE priority 4
#ip route del table 111
ip route add default via $SLEUTH table $TABLE

#iptables -t nat -I PREROUTING -s $SUSPECT -d $ROUTER -j DNAT --to-destination $SLEUTH

iptables -t nat -S

export INTERFACE=eth0

echo 1 > /proc/sys/net/ipv4/ip_forward

arpspoof -i $INTERFACE -t $SUSPECT $REAL_ROUTER
