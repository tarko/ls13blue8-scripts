#!/bin/sh

while [ true ]; do 
	for i in 10.0.108.31 10.0.108.21; do
		echo > /tmp/arpmon
		ssh fwadm@$i "/sbin/arp -n | grep ether | grep -v 10.0.108." >> /tmp/arpmon
	done

	diff /tmp/arpmon-old /tmp/arpmon
	mv /tmp/arpmon /tmp/arpmon-old

	sleep 30
done
