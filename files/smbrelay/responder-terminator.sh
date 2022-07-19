#!/bin/bash

LBlue='\033[0;94m'      # Ligth Blue
BBlue='\033[1;34m'      # Bold Blue
BWhite='\033[1;37m'     # Bold White
Color_Off='\033[0m'     # Text Reset

#tput civis
echo -e "${LBlue}[${BBlue}+${LBlue}] ${BWhite}Configurando Responder...${Color_Off}\n"

# Modificando parametros de Responder.conf
cp /usr/bin/pentest/Responder/Responder.conf.smbrelay /usr/bin/pentest/Responder/Responder.conf

# Iniciando Responder
/usr/bin/pentest/responder.sh -I eth0 -dw

sleep 5
