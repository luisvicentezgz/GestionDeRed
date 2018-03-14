#################################
#####   Network discovery   #####
#################################

import scapy.all
import snmp_library
import os
import sys

#Conf verb to 0
#conf.verb = 0 #disable verbose mode

def GetMac(ans):
    MAC = str(ans)
    print MAC
    ini = MAC.find("bwsrc=")+6
    end = MAC.rfind("psrc=")-1
    return MAC[inicio:fin]




# Check the network
ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op="who-has", psrc="155.210.157.99", pdst="155.210.157.3"))
print ans[0]

# Para cada una de las repuestas snd y rcv son el paquete que has mandado y la respuesta que has recivido
for snd, rcv in ans:
    # Escaneo todos los puertos
    answers, un_answered = sr()
    #
    for req, resp in answers:
        # Compruebo si la respuesta es un SYN/ACK
        pass # Pass solamente esta para llenar el loop. Tu lo deberas borrar


    # En caso de ser SYN/ACK cierro la conexion con un reset