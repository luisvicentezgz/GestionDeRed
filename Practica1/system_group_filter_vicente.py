from snmp_library import *
from pysnmp.hlapi.asyncore import *

# Email
from email.mime import multipart, text
import smtplib

# TrapReceiver
from pysnmp.carrier.asyncore.dispatch import AsyncoreDispatcher
from pysnmp.carrier.asyncore.dgram import udp, udp6, unix
from pyasn1.codec.ber import decoder
from pysnmp.proto import api

# Configuracion sonda

version = 'v1'
ip_addr = '155.210.157.204'
community = 'security'
port = 161

snmp_engine = snmp_requests(version, community, ip_addr, port)

################################################################################
#monitorizar cada 5" tráfico ARP

## GRUPO FILTER
#1-Obtener OID
varBinds = [ObjectType(ObjectIdentity('aaaaaaaaaaaaaaaaaaaaa'))]#6 mata
response = snmp_engine.snmpget(varBinds)
if (response==OctetString(hexValue='ARP')):
    print 'match'
#2-Config Offset en GrupoFilter/filterPktDataOffset (imprimir paquete en HEX para asegurar)
#1.3.6.1.2.1.16.7.1.1.3.xxx
#3-Config GrupoChannel

OctetString(hexValue='F23C')
##########

#type=ARP=OFFSET12(to13)


##GRUPO CAPTURE
#mac_src=OFFSET 6(to11:     X7X:X8X:X9X:X10X:X11X:X12X)
#ip_src=OFFSET 28(to31)
#ip_dst=38to41


##MOSTRAR PAQUETES



varBinds = [ObjectType(ObjectIdentity('1.3.6.1.2.1.16.7.2.1.12.3'), Integer(2))]
response = snmp_engine.snmpset(varBinds)
varBinds = [ObjectType(ObjectIdentity('1.3.6.1.2.1.16.7.2.1.2.3'), Integer(3))]#interface=eth1=3
response = snmp_engine.snmpset(varBinds)

varBinds = [ObjectType(ObjectIdentity('1.3.6.1.2.1.16.7.1.1.11.3'), Integer(2))]
response = snmp_engine.snmpset(varBinds)


print response.varBinds[0][1]
print response.varBinds[0][0]










print response.varBinds[0][1]
print response.varBinds[0][0]