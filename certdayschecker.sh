#!/bin/sh
#set -x
CONFFILE=/usr/local/etc/certdayschecker.conf
export PATH=$PATH:/usr/local/bin

OFS="$IFS"
IFS=":"
sed 's/#.*$//' $CONFFILE | grep "^[^:]*:[^:]*:[^:]*$" | while read name host port; do
     n=`certdaysremaining -h $host -p $port -H`
     message=
     if [ ! -z "$n" ]; then
     	if [ "$n" -eq 60 ]; then
	   message="Sixty days remaining on the certificate for the $name"
	else
	   if [ "$n" -eq 30 ]; then
	      message="Thirty days remaining on the certificate for the $name"
	   else
		if [ "$n" -le 15 ]; then
		   message="$n days remaining on the certificate for the $name"
		fi
	   fi
	fi
	if [ ! -z "$message" ]; then
	  echo $message
	fi
     else
	echo "$name: Error getting certificate info"
     fi
done
IFS="$OFS"
