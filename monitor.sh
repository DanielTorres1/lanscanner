#!/bin/bash
# */10 * * * * root cd /home/hkng/monitor; bash monitor.sh >> log.txt
# anonftp,” or “x11open.”
OKBLUE='\033[94m'
OKRED='\033[91m'
OKGREEN='\033[92m'
RESET='\e[0m'

while true; do 
current_time=`date +"%H:%M"`
echo "Current time: $current_time"
delta=`date +"%M"`
delta=$(echo "($delta*2)/60" | bc -l )
echo "Delta: $delta"
echo ""


echo -e "$OKBLUE[+] Revisando procesos de smbmap $RESET"		
for line in $( ps aux | egrep --color=never "smbmap" | grep "H" | grep -v color | awk '{print $2,$9}' | tr " " ";" ); do
	pid=`echo $line | cut -f1 -d";"`
	#time=`echo $line | cut -f2 -d";"`
	time=`ps -p $pid -o etime | grep : | cut -d ":" -f1`
    #echo process time: $time
    echo "pid: $pid time $time"
               
	# diff=$(  echo "$current_time - $time"  | sed 's%:%+(1/60)*%g' | bc -l )	
	# diff=$(echo "($diff - $delta)*60" | bc  ) # fix with delta
	# diff=`printf "%.0f\n" "$diff"` # round
	# diff=`echo $diff | tr -d -`
	#echo "Idle time: $time minutes"	
	
	if [[  $time -gt 1  ]];then 
		
		echo -e "$OKRED[-] Killing $pid) $RESET"
		echo "line $line"
		kill -9 $pid		
	else
		echo -e "$OKGREEN[+] OK $RESET"		
	fi
	echo ""		
done
echo ""

echo -e "$OKBLUE[+] Revisando procesos de get_ssl_cert/lbd/rpcclient $RESET"		
for line in $( ps aux | egrep --color=never "get_ssl_cert|lbd|rpcclient" | grep -v color | awk '{print $2,$9}' | tr " " ";" ); do
	pid=`echo $line | cut -f1 -d";"`
	#time=`echo $line | cut -f2 -d";"`
	time=`ps -p $pid -o etime | grep : | cut -d ":" -f1`
    #echo process time: $time
    echo "pid: $pid time $time"
               
	# diff=$(  echo "$current_time - $time"  | sed 's%:%+(1/60)*%g' | bc -l )	
	# diff=$(echo "($diff - $delta)*60" | bc  ) # fix with delta
	# diff=`printf "%.0f\n" "$diff"` # round
	# diff=`echo $diff | tr -d -`
	# echo "Idle time: $diff minutes"	
	
	if [[  $time -gt 1  ]];then 
		
		echo -e "$OKRED[-] Killing $pid) $RESET"
		echo "line $line"
		kill -9 $pid		
	else
		echo -e "$OKGREEN[+] OK $RESET"		
	fi
	echo ""		
done
echo ""


echo -e "$OKBLUE[+] Revisando procesos de blackwidow|testssl $RESET"		
for line in $( ps aux | egrep --color=never "blackwidow|testssl" | grep -v color | awk '{print $2,$9}' | tr " " ";" ); do
	pid=`echo $line | cut -f1 -d";"`
	#time=`echo $line | cut -f2 -d";"`
	time=`ps -p $pid -o etime | grep : | cut -d ":" -f1`
    #echo process time: $time
    echo "pid: $pid time $time"
               
	# diff=$(  echo "$current_time - $time"  | sed 's%:%+(1/60)*%g' | bc -l )	
	# diff=$(echo "($diff - $delta)*60" | bc  ) # fix with delta
	# diff=`printf "%.0f\n" "$diff"` # round
	# diff=`echo $diff | tr -d -`
	# echo "Idle time: $diff minutes"	
	
	if [[  $time -gt 5  ]];then 
		
		echo -e "$OKRED[-] Killing $pid) $RESET"
		kill -9 $pid		
	else
		echo -e "$OKGREEN[+] OK $RESET"		
	fi
	echo ""		
done
echo ""


echo -e "$OKBLUE[+] Revisando procesos de snmpwalk|dnsenum $RESET"		
for line in $( ps aux | egrep --color=never 'snmpwalk|snmpbrute|dnsenum' | grep -v color | awk '{print $2,$9}' | tr " " ";" ); do
	pid=`echo $line | cut -f1 -d";"`
	#time=`echo $line | cut -f2 -d";"`
	time=`ps -p $pid -o etime | grep : | cut -d ":" -f1`
    #echo process time: $time
    echo "pid: $pid time $time"
               
	# diff=$(  echo "$current_time - $time"  | sed 's%:%+(1/60)*%g' | bc -l )	
	# diff=$(echo "($diff - $delta)*60" | bc  ) # fix with delta
	# diff=`printf "%.0f\n" "$diff"` # round
	# diff=`echo $diff | tr -d -`
	# echo "Idle time: $diff minutes"	
	
	if [[  $time -gt 15  ]];then 
		
		echo -e "$OKRED[-] Killing $pid) $RESET"
		kill -9 $pid		
	else
		echo -e "$OKGREEN[+] OK $RESET"		
	fi
	echo ""		
done
echo ""


echo -e "$OKBLUE[+] Revisando procesos de netcat|msfconsole  $RESET"		
for line in $( ps aux | egrep --color=never "nc|msfconsole" | grep -v color | grep "\-w 3" | awk '{print $2,$9}' | tr " " ";" ); do
	pid=`echo $line | cut -f1 -d";"`
	#time=`echo $line | cut -f2 -d";"`
	time=`ps -p $pid -o etime | grep : | cut -d ":" -f1`
    #echo process time: $time
    echo "pid: $pid time $time"
               
	# diff=$(  echo "$current_time - $time"  | sed 's%:%+(1/60)*%g' | bc -l )	
	# diff=$(echo "($diff - $delta)*60" | bc  ) # fix with delta
	# diff=`printf "%.0f\n" "$diff"` # round
	# diff=`echo $diff | tr -d -`
	# echo "Idle time: $diff minutes"	
	
	if [[  $time -gt 3  ]];then 
		
		echo -e "$OKRED[-] Killing $pid) $RESET"
		kill -9 $pid		
	else
		echo -e "$OKGREEN[+] OK $RESET"		
	fi
	echo ""		
done
echo ""


echo -e "$OKBLUE[+] Revisando procesos de perl $RESET"		
for line in $( ps aux | grep --color=never perl  | grep -v color | egrep -v "dnsenum|finger|passWeb|joomscan|buster|getBanners|color|getDomainInfo|mass-scan|smtp-user-enum" | awk '{print $2,$9}' | tr " " ";" ); do
	pid=`echo $line | cut -f1 -d";"`
	#time=`echo $line | cut -f2 -d";"`
	time=`ps -p $pid -o etime | grep : | cut -d ":" -f1`
    #echo process time: $time
    echo "pid: $pid time $time"
               
	
	if [[  $time -gt 2  ]];then 
		
		echo -e "$OKRED[-] Killing $pid) $RESET"
		kill -9 $pid		
	else
		echo -e "$OKGREEN[+] OK $RESET"		
	fi
	echo ""		
done
echo ""


echo -e "$OKBLUE[+] Revisando procesos de web-buster $RESET"		
for line in $( ps aux | grep --color=never web-buster | grep -v color | awk '{print $2,$9}' | tr " " ";" ); do
	pid=`echo $line | cut -f1 -d";"`
	#time=`echo $line | cut -f2 -d";"`
	time=`ps -p $pid -o etime | grep : | cut -d ":" -f1`
    #echo process time: $time
    echo "pid: $pid time $time"
               
	# diff=$(  echo "$current_time - $time"  | sed 's%:%+(1/60)*%g' | bc -l )	
	# diff=$(echo "($diff - $delta)*60" | bc  ) # fix with delta
	# diff=`printf "%.0f\n" "$diff"` # round
	# diff=`echo $diff | tr -d -`
	# echo "Idle time: $diff minutes"	
	
	if [[  $time -gt 30  ]];then 
		
		echo -e "$OKRED[-] Killing $pid) $RESET"
		kill -9 $pid		
	else
		echo -e "$OKGREEN[+] OK $RESET"		
	fi
	echo ""		
done
echo ""

echo -e "$OKBLUE[+] Revisando procesos de hydra/medusa/patator $RESET"		
for line in $( ps aux | egrep --color=never "hydra|medusa|patator|prtgadmin" | grep -v color | awk '{print $2,$9}' | tr " " ";" ); do
	pid=`echo $line | cut -f1 -d";"`
	#time=`echo $line | cut -f2 -d";"`
	time=`ps -p $pid -o etime | grep : | cut -d ":" -f1`
    #echo process time: $time
    echo "pid: $pid time $time"

	
	if [[  $time -gt 10  ]];then 
		
		echo -e "$OKRED[-] Killing $pid) $RESET"
		kill -9 $pid		
	else
		echo -e "$OKGREEN[+] OK $RESET"		
	fi
	echo ""		
done
echo ""

echo -e "$OKBLUE[+] Revisando procesos de masscan $RESET"		
for line in $( ps aux | egrep --color=never "masscan" | grep -v color | awk '{print $2,$9}' | tr " " ";" ); do
	pid=`echo $line | cut -f1 -d";"`
	#time=`echo $line | cut -f2 -d";"`
	time=`ps -p $pid -o etime | grep : | cut -d ":" -f1`
    #echo process time: $time
    echo "pid: $pid time $time"
               
	# diff=$(  echo "$current_time - $time"  | sed 's%:%+(1/60)*%g' | bc -l )	
	# diff=$(echo "($diff - $delta)*60" | bc  ) # fix with delta
	# diff=`printf "%.0f\n" "$diff"` # round
	# diff=`echo $diff | tr -d -`
	# echo "Idle time: $diff minutes"	
	
	if [[  $time -gt 3 && $time -lt 180 ]];then 
		
		echo -e "$OKRED[-] Killing $pid) $RESET"
		kill -9 $pid		
	else
		echo -e "$OKGREEN[+] OK $RESET"		
	fi
	echo ""		
done
echo ""

echo -e "$OKBLUE[+] Revisando procesos de reaver/pptp $RESET"		
for line in $( ps aux | egrep --color=never "reaver|pptp" | grep -v color | awk '{print $2,$9}' | tr " " ";" ); do
	pid=`echo $line | cut -f1 -d";"`
	#time=`echo $line | cut -f2 -d";"`
	time=`ps -p $pid -o etime | grep : | cut -d ":" -f1`
    #echo process time: $time
    echo "pid: $pid time $time"
               
	# diff=$(  echo "$current_time - $time"  | sed 's%:%+(1/60)*%g' | bc -l )	
	# diff=$(echo "($diff - $delta)*60" | bc  ) # fix with delta
	# diff=`printf "%.0f\n" "$diff"` # round
	# diff=`echo $diff | tr -d -`
	# echo "Idle time: $diff minutes"	
	
	if [[  $time -gt 0  ]];then 
		
		echo -e "$OKRED[-] Killing $pid) $RESET"
		kill -9 $pid		
	else
		echo -e "$OKGREEN[+] OK $RESET"		
	fi
	echo ""		
done
echo ""

# echo -e "$OKBLUE[+] Revisando procesos de nmap y naabu $RESET"		
# for line in $( ps aux | egrep --color=never "nmap|naabu" | egrep -v "getBanners|color|nmap-udp" | awk '{print $2,$9}' | tr " " ";" ); do
# 	pid=`echo $line | cut -f1 -d";"`
# 	time=`echo $line | cut -f2 -d";"`
#     #echo process time: $time
#     echo "pid: $pid time $time"
               
# 	diff=$(  echo "$current_time - $time"  | sed 's%:%+(1/60)*%g' | bc -l )	
# 	diff=$(echo "($diff - $delta)*60" | bc  ) # fix with delta
# 	diff=`printf "%.0f\n" "$diff"` # round
# 	diff=`echo $diff | tr -d -`
# 	echo "Idle time: $diff minutes"	
	
	
# 	if [[  $diff -gt 60 && $diff -lt 120 ]];then 
		
# 		echo -e "$OKRED[-] Killing $pid) $RESET"
# 		kill -9 $pid		
# 	else
# 		echo -e "$OKGREEN[+] OK $RESET"		
# 	fi
# 	echo ""		
# done


echo -e "$OKBLUE[+] Revisando procesos de udp-hunter $RESET"		
for line in $( ps aux | egrep --color=never "udp-hunter" | egrep -v "getBanners|color|nmap-udp" | awk '{print $2,$9}' | tr " " ";" ); do
	pid=`echo $line | cut -f1 -d";"`
	#time=`echo $line | cut -f2 -d";"`
	time=`ps -p $pid -o etime | grep : | cut -d ":" -f1`
    #echo process time: $time
    echo "pid: $pid time $time"
               
	# diff=$(  echo "$current_time - $time"  | sed 's%:%+(1/60)*%g' | bc -l )	
	# diff=$(echo "($diff - $delta)*60" | bc  ) # fix with delta
	# diff=`printf "%.0f\n" "$diff"` # round
	# diff=`echo $diff | tr -d -`
	# echo "Idle time: $diff minutes"	
	
	
	if [[  $time -gt 1  ]];then 
		
		echo -e "$OKRED[-] Killing $pid) $RESET"
		kill -9 $pid		
	else
		echo -e "$OKGREEN[+] OK $RESET"		
	fi
	echo ""		
done


echo -e "$OKBLUE[+] Revisando procesos de wpscan/joomscan $RESET"		
for line in $( ps aux | egrep --color=never "wpscan|joomscan" | grep -v color | awk '{print $2,$9}' | tr " " ";" ); do
	pid=`echo $line | cut -f1 -d";"`
	#time=`echo $line | cut -f2 -d";"`
	time=`ps -p $pid -o etime | grep : | cut -d ":" -f1`
    #echo process time: $time
    echo "pid: $pid time $time"
               
	# diff=$(  echo "$current_time - $time"  |  )	
	# diff=$(echo "($diff - $delta)*60" | bc  ) # fix with delta
	# diff=`printf "%.0f\n" "$diff"` # round
	# diff=`echo $diff | tr -d -`
	# echo "Idle time: $diff minutes"	
	
	
	if [[  $time -gt 40  ]];then 
		
		echo -e "$OKRED[-] Killing $pid) $RESET"
		kill -9 $pid		
	else
		echo -e "$OKGREEN[+] OK $RESET"		
	fi
	echo ""		
done



echo -e "$OKBLUE[+] Revisando procesos de msfconsole $RESET"		
for line in $( ps aux | egrep --color=never "msfconsole" | grep "auxiliary" | awk '{print $2,$9}' | tr " " ";" ); do
	pid=`echo $line | cut -f1 -d";"`
	#time=`echo $line | cut -f2 -d";"`
	time=`ps -p $pid -o etime | grep : | cut -d ":" -f1`
    #echo process time: $time
    echo "pid: $pid time $time"
               
	# diff=$(  echo "$current_time - $time"  | sed 's%:%+(1/60)*%g' | bc -l )	
	# diff=$(echo "($diff - $delta)*60" | bc  ) # fix with delta
	# diff=`printf "%.0f\n" "$diff"` # round
	# diff=`echo $diff | tr -d -`
	# echo "Idle time: $diff minutes"	
	
	
	if [[  $time -gt 4  ]];then 
		
		echo -e "$OKRED[-] Killing $pid) $RESET"
		kill -9 $pid		
	else
		echo -e "$OKGREEN[+] OK $RESET"		
	fi
	echo ""		
done


echo ""
echo ""
sleep 3
done

