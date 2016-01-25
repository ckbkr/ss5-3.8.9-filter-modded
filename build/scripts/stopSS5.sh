#!/bin/sh
ps aux | grep ss5 | awk -F " " '{print $2}' | while read line
do
	echo "$line"
	/bin/kill "$line"
done
