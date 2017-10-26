#!/bin/bash

#Scan-Analisis UDP
if [ $# != 1 ]; then
        echo "Falta la ip"
else 
clear
#########################Arrenquem TCPDUMP i comencem l'analisis amb  unicornscan######################
echo -e "\e[1;31m#######SCAN UDP PORTS - VERSIO BETA#############################\e[0m"
ip=$1
rm resultados_unicorn.txt 2>/dev/null
echo "Analisis a la ip $ip"
echo "Start TCPDUMP"
	tcpdump -vvv -X -n -i eth0 host $ip and udp -w resultados_tcpdump.pcap 2> /dev/null &
#$!= obtencion del numero de proceso que se esta ejecutando
numero_proceso=$!
echo "Numero del proces $numero_proceso"
echo "Start unicornscan"
	unicornscan -mU $ip:a -l resultados_unicorn.txt 2>/dev/null &&
codigo_error=$?
echo "Fi unicornscan amb el codi $codigo_error"
echo "Fi del proces tcmp amb el PID $numero_proceso"
kill $numero_proceso
echo " "
#Analisis dels resultats
echo -e "\e[0;34m###Analisis dels resultats###\e[0m"
echo "Analisis dels ports oberts"
cat resultados_unicorn.txt | grep -v unknown | cut -d [ -f 2 | cut -d ] -f 1 > puertos_abiertos
numero_ports=`wc -l puertos_abiertos |cut -d" " -f 1`
echo "Hi ha $numero_ports oberts"
sed -i -e 's/^[ \t]*//; s/[ \t]*$//; /^$/d' puertos_abiertos
cat puertos_abiertos
cp puertos_abiertos puertos_analisis
echo " "
echo "Analisis Ports efimers"
cat resultados_unicorn.txt | grep unknow | cut -d [ -f 2 | cut -d ] -f 1 > puertos_abiertos
numero_ports=`wc -l puertos_abiertos |cut -d" " -f 1`
echo "Hi ha $numero_ports efimers oberts"
sed -i -e 's/^[ \t]*//; s/[ \t]*$//; /^$/d' puertos_abiertos
tcpdump -t -n -r resultados_tcpdump.pcap > temporal.txt 2>/dev/null

limite=`wc -l puertos_abiertos | cut -d " " -f 1`
iteracion=0
while [ $iteracion -lt $limite ]; do
        linea=$(($limite - $iteracion))
        puerto_remoto_out=`head -$linea puertos_abiertos | tail -1`
        let iteracion=iteracion+1
	puerto_local_in=`cat temporal.txt | grep "$ip.$puerto_remoto_out >" | cut -d . -f 9 | cut -d : -f 1`
	echo "El port remot es $puerto_remoto_out y el port local es el $puerto_local_in"
	puerto_remoto_escanear=`cat temporal.txt | grep ".$puerto_local_in >" |grep -v UDP | cut -d . -f 9 | cut -d : -f 1 | head -1`
	echo "Port efimer: $puerto_remoto_out" 
	echo -e "\e[1;32mPort remot REAL a revisar: $puerto_remoto_escanear\e[0m"
	echo $puerto_remoto_escanear >> puertos_analisis
done
sleep 3
puertos_finales=`paste -d "," -s puertos_analisis`
echo "Aquests son els ports que seran analitzats:  $puertos_finales"
echo -e "\e[0;34m###START NMAP###\e[0m"
rm temporal.txt 
rm puertos_abiertos
rm puertos_analisis
nmap -v -sU -T4 -sV -p $puertos_finales $ip | tee resultados_nmap.txt
fi
