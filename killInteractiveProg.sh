#!/bin/bash
#so will need to user bash script instead...
#kill an interactive program. Can't work out how to kill within fuzzer.py
if [ $# -ne 1 ]; then
	echo "Need single argument with filename according to \"ps auc\""
	exit 1
fi
prog=$1
#to end the program you must either kill it, or use ctrl+c (depending on whether background or foreground process
while true; do
	RUNNING=(`ps auc |grep -i $prog| awk '{print $2,$8}'`)
	numRunning=${#RUNNING[@]}
	#get the time the program started
	pid=${RUNNING[$numRunning-2]}
	progTime=`ps -p $pid -o etime=`
	progSec=`echo $progTime|cut -d: -f2`
        if [ $progSec -gt "1" ]; then
		echo Stopping $prog with PID $pid
		kill -9 $pid
	fi
	
	sleep 1s
done
