#!/bin/bash

export ROUTER=192.168.0.111
export SLEUTH=192.168.0.127
export SUSPECT=192.168.0.104
export REAL_ROUTER=192.168.0.1
export TABLE=111
export INTERFACE=eth0



if [ "$1" = "start" ]
then
	echo "CURRENT PARAMS:" 
	echo
	echo "IPTABLES"
	iptables -S
	echo "NAT"
	iptables -t nat -S
	echo 
	echo
	echo
	iptables -I FORWARD -s $SUSPECT -j ACCEPT
	iptables -I FORWARD -d $SUSPECT -j ACCEPT
	iptables -t nat -I POSTROUTING -s $SUSPECT -j MASQUERADE
	iptables -t nat -A PREROUTING -i $INTERFACE -p tcp --dport 80 -j REDIRECT --to-port 8080 
	iptables -t nat -A PREROUTING -i $INTERFACE -p tcp --dport 443 -j REDIRECT --to-port 8080	
	echo 1 > /proc/sys/net/ipv4/ip_forward
	echo
	echo
	echo "NEW PARAMS:" 
	echo
	echo "IPTABLES"
	iptables -S
	echo "NAT"
	iptables -t nat -S
	echo 
	echo
	echo
else
if [ "$1" = "kill" ]
then
	echo "CURRENT PARAMS:" 
	echo
	echo "IPTABLES"
	iptables -S
	echo "NAT"
	iptables -t nat -S
	echo 
	echo
	echo
	iptables -D FORWARD -d $SUSPECT -j ACCEPT
	iptables -D FORWARD -s $SUSPECT -j ACCEPT
	iptables -t nat -D POSTROUTING -s $SUSPECT -j MASQUERADE
	iptables -t nat -D PREROUTING -i $INTERFACE -p tcp --dport 80 -j REDIRECT --to-port 8080 
	iptables -t nat -D PREROUTING -i $INTERFACE -p tcp --dport 443 -j REDIRECT --to-port 8080	
	iecho 0 > /proc/sys/net/ipv4/ip_forward
	echo 
	echo 
	echo 
	echo "NEW PARAMS:" 
	echo
	echo "IPTABLES"
	iptables -S
	echo "NAT"
	iptables -t nat -S
	echo
	echo 
	echo
else
	echo "Please use 'start' or 'kill' args"
fi
fi


