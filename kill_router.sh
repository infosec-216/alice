#!/bin/bash

iptables -t nat -S
#iptables -t nat -D

export ROUTER=192.168.0.111
export SLEUTH=192.168.0.127
export SUSPECT=192.168.0.104
export REAL_ROUTER=192.168.0.1

export TABLE=111
ip rule del $TABLE
ip rule list

ip rule del from 192.168.0.104 lookup $TABLE
ip route del table $TABLE
ip route del default via $SLEUTH table $TABLE

#iptables -t nat -I PREROUTING -s $SUSPECT -d $ROUTER -j DNAT --to-destination $SLEUTH

iptables -t nat -S

export INTERFACE=eth0

echo 0 > /proc/sys/net/ipv4/ip_forward

#arpspoof -i $INTERFACE -t $SUSPECT $REAL_ROUTER
