# Network discovery
from scapy.all import sr,srp,Ether,ARP,IP,TCP,conf
from snmp_library import *


# Conf verb to 0
conf.verb = 0

# Check the network
ans, unans = srp()

# Para cada una de las repuestas snd y rcv son el paquete que has mandado y la respuesta que has recivido
for snd, rcv in ans:

    # Escaneo todos los puertos
    answers, un_answered = sr()
    #
    for req, resp in answers:
        # Compruebo si la respuesta es un SYN/ACK
        pass # Pass solamente esta para llenar el loop. Tu lo deberas borrar


    # En caso de ser SYN/ACK cierro la conexion con un reset

