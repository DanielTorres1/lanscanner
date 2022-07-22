#!/bin/bash

function print_ascii_art {
cat << "EOF"
   __               __                                 
  / /  __ _ _ __   / _\ ___ __ _ _ __  _ __   ___ _ __ 
 / /  / _` | '_ \  \ \ / __/ _` | '_ \| '_ \ / _ \ '__|
/ /__| (_| | | | | _\ \ (_| (_| | | | | | | |  __/ |   
\____/\__,_|_| |_| \__/\___\__,_|_| |_|_| |_|\___|_|   
                                                       

					daniel.torres@owasp.org
					https://github.com/DanielTorres1

EOF
}


print_ascii_art

RED="\033[01;31m"      # Issues/Errors
GREEN="\033[01;32m"    # Success
YELLOW="\033[01;33m"   # Warnings/Information
BLUE="\033[01;34m"     # Heading
BOLD="\033[01;01m"     # Highlight
RESET="\033[00m"       # Normal

echo -e "${RED}[+]${BLUE} Instalar docker ${RESET}"
sudo apt-get install ca-certificates curl gnupg lsb-release
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian buster stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get -y  install  docker-ce docker-ce-cli containerd.io docker-compose-plugin
  

echo -e "${GREEN} [+] Instalando herramientas disponibles en repositorio ${RESET}" 
sudo apt-get update
sudo apt-get -y install bc npm nbtscan nfs-common snmp finger sqlite3 sqlitebrowser nmap masscan onesixtyone whatweb libssl-dev ike-scan postgresql-client elinks smbclient bc libcurl4-openssl-dev xterm ipmitool lbd exiftool libpq-dev libpcap-dev tshark p7zip-full default-mysql-client python3-pip libssl-dev swig python3-dev gcc libcrypt-ssleay-perl metasploit-framework patator hydra enum4linux wpscan dnsutils python3-setuptools gedit tor gedit xterm dsniff terminator sipvicious remmina filezilla libmemcached-tools seclists oscanner encfs squidclient snmp-mibs-downloader redis-tools fdupes rusers kinit krb5-user tnscmd10g nfs-common open-iscsi erlang xdotool php-memcached glusterfs-cli kpcli libssl-dev prips golang-go jq

echo -e "${GREEN} [+] Instalando ofuscador de bash ${RESET}" 
npm install -g bash-obfuscate


echo -e "${GREEN} [+] Instalando wappalyzer ${RESET}" 
npm i -g wappalyzer

# usar TLS 1.0 
sed -i 's/MinProtocol = TLSv1.2/MinProtocol = TLSv1.0/' /etc/ssl/openssl.cnf

echo -e "${GREEN} [+] Instalando requisitos PIP ${RESET}" 
pip install netaddr colorama argparse ifaddr datetime jsbeautifier
pip install sqlite-utils paramiko
pip install requests==2.25.1 argparse rich urllib3
pip install cqlsh
pip3 install cpppo

echo -e "${GREEN} [+] Instalando naabu ${RESET}" 
#GO111MODULE=on go get -v github.com/projectdiscovery/naabu/v2/cmd/naabu
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
sudo cp ~/go/bin/naabu /usr/bin/naabu 
chmod a+x /usr/bin/naabu

echo "www2" > /usr/share/seclists/Discovery/DNS/subdomain.txt


echo -e "${GREEN} [+] Instalando DumpsterDiver ${RESET}" 
cd DumpsterDiver
docker build -t dumpster-diver .
cd ..


echo -e "${GREEN} [+] Instalando hakrevdns ${RESET}"
go install github.com/hakluke/hakrevdns@latest

echo -e "${GREEN} [+] Copiando archivos ${RESET}"
mkdir /usr/share/lanscanner 2>/dev/null
cp  files/share/* /usr/share/lanscanner
cp  files/share/.resultados.db /usr/share/lanscanner/.resultados.db


cp *.nse /usr/share/nmap/scripts/
cp rtsp.lua /usr/share/nmap/nselib/rtsp.lua
cp cve_2019_0708_bluekeep.rb /usr/share/metasploit-framework/modules/auxiliary/scanner/rdp
cd ..
echo ""


echo -e "${RED}[+]${GREEN} Instalando odat ${RESET}"
cd pentest/
wget https://github.com/quentinhardy/odat/releases/download/5.1.1/odat-linux-libc2.17-x86_64.tar.gz
tar -zxvf odat-linux-libc2.17-x86_64.tar.gz
cd ../

echo -e "${GREEN} [+] Copiando scripts a /usr/bin ${RESET}"
cp -r pentest /usr/bin
cp lanscanner.sh /usr/bin
cp monitor.sh /usr/bin
cp discover.sh /usr/bin
cp smbrelay.sh /usr/bin
ln -s /usr/bin/discover.sh /usr/bin/autohack.sh

cp files/image.png /usr/share/lanscanner/image.png
cp files/vulnerabilidades.xml /usr/share/lanscanner/vulnerabilidades.xml
cp files/info.php /usr/share/lanscanner/info.php

chmod a+x /usr/bin/monitor.sh
chmod a+x /usr/bin/lanscanner.sh
chmod a+x /usr/bin/autohack.sh
chmod a+x /usr/bin/smbrelay.sh
echo ""


echo -e "${GREEN} [+] Instalando scripts de SMBRelay ${RESET}"
rm -rf ~/.config/terminator 
mkdir -p ~/.config/terminator
cp files/smbrelay/config ~/.config/terminator   
cp -r files/smbrelay/ /usr/share/lanscanner    


    
echo -e "${GREEN} [+] Instalando librerias de perl ${RESET}"
sudo cpan G/GR/GROMMEL/Math-Round-0.07.tar.gz
sudo cpan U/UR/URI/File-Slurp-9999.19.tar.gz
sudo cpan M/MA/MAKAMAKA/JSON-2.90.tar.gz
sudo cpan I/IS/ISHIGAKI/JSON-4.02.tar.gz
sudo cpan G/GR/GRANTM/XML-Simple-2.25.tar.gz


# echo -e "${RED}[+]${GREEN} Instalando truffleHog ${RESET}"
# cat <<EOF | sudo tee -a /etc/docker/daemon.json
# {
#     "dns": ["8.8.8.8"]
# }
# EOF
# sudo service docker restart

# cd truffleHog
# docker build . -t trufflehog
# cd ../


echo -e "${RED}[+]${GREEN} Instalando Interlace ${RESET}"
pwd
cd Interlace
pip install -r requirements.txt
python3 setup.py install
echo ""
cd ../


echo -e "${RED}[+]${GREEN} Instalando impacket ${RESET}"
cd impacket
python3 -m pip install .
cd ..

echo -e "${RED}[+]${GREEN} Instalando wafw00f ${RESET}"
pwd
cd wafw00f
python3 setup.py install
echo ""
cd ../

echo -e "${RED}[+]${GREEN} Instalando SirepRAT ${RESET}"
cd pentest/SirepRAT
pip install -r requirements.txt
echo ""
cd ../../




echo -e "${GREEN} [+] Modificando PATH ${RESET}"
echo export PATH="$PATH:/usr/bin/pentest" >> ~/.bashrc
echo export PATH="$PATH:/usr/bin/pentest" >> ~/.zshrc
echo ""
chmod a+x /usr/bin/pentest/*

echo -e "${GREEN} [+] Habilitando samba ${RESET}"
cat <<EOF | sudo tee -a /etc/samba/smb.conf
[smb]
    comment = Samba
    path = /tmp/
    guest ok = yes
    read only = no
    browsable = yes
EOF

    
echo -e "${GREEN} [+] Instalando webhacks ${RESET}"
git clone https://github.com/DanielTorres1/webhacks
cd webhacks
bash instalar.sh
cd ..


mkdir -p /usr/share/wordlists/ 2>/dev/null
#cd /usr/share/wordlists/
#wget https://raw.githubusercontent.com/DanielTorres1/passwords/master/usuarios-es.txt

echo -e "${RED}[+]${GREEN} Instalando Empire  ${RESET}"
cd  /opt/
git clone --recursive https://github.com/BC-SECURITY/Empire.git
cd Empire
sudo ./setup/install.sh


gem install evil-winrm

# echo -e "${RED}[+]${GREEN} Instalando Covenant ${RESET}"
# sudo dpkg -i files/libicu57_57.1-6+deb9u4_amd64.deb

# cp -r exploits/Covenant2/ /opt

# wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.asc.gpg
# sudo mv microsoft.asc.gpg /etc/apt/trusted.gpg.d/
# wget -q https://packages.microsoft.com/config/debian/10/prod.list
# sudo mv prod.list /etc/apt/sources.list.d/microsoft-prod.list
# sudo chown root:root /etc/apt/trusted.gpg.d/microsoft.asc.gpg
# sudo chown root:root /etc/apt/sources.list.d/microsoft-prod.list
# sudo apt-get update
# sudo apt-get install -y apt-transport-https
# sudo apt-get update
# sudo apt install -y dotnet-sdk-3.1
# cd /opt/Covenant2/Covenant
# dotnet build
# echo ""


echo -e "${GREEN} [+] LISTO!! TODO OK"
echo -e "${RED} [i] IMPORTANTE: Para empezar a usar los scripts inicia otra terminal :V ${RED}"
