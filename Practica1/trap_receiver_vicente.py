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
## BORAR LAS ALARMAS DE OTROS (a)
#a=[3,4,15,40,60,80,111,112,512]
#i=0#SOLO CON  "a"
#for i in a:
#    varBinds = [ObjectType(ObjectIdentity('1.3.6.1.2.1.16.3.1.1.12.'+str(a[i])))]
#    response = snmp_engine.snmpget(varBinds)
#    if str(response.varBinds[0][1]) == '3' or str(response.varBinds[0][1]) == '1':
#        varBinds = [ObjectType(ObjectIdentity('1.3.6.1.2.1.16.3.1.1.12.'+str(a[i])),Integer(4))]
#        response = snmp_engine.snmpset(varBinds)
#        print 'killed: '+str(i)

#for i in range(513):
#    varBinds = [ObjectType(ObjectIdentity('1.3.6.1.2.1.16.9.1.1.7.'+str(i)))]#str(a[i])
#    response = snmp_engine.snmpget(varBinds)
#    varBinds = [ObjectType(ObjectIdentity('1.3.6.1.2.1.16.9.1.1.4'+str(i)))]#str(a[i])
#    response2 = snmp_engine.snmpget(varBinds)
#    if ((str(response.varBinds[0][1]) == '3' or str(response.varBinds[0][1]) == '1') and (response2.varBinds[0][1] != 'monitor')):#dejo los de monitor
#        varBinds = [ObjectType(ObjectIdentity('1.3.6.1.2.1.16.3.1.1.7.'+str(i)),Integer(4))]#str(a[i])
#        response = snmp_engine.snmpset(varBinds)
#        print 'killed: '+str(i)
################################################################################
##VER SI ESTA LIBRE
varBinds = [ObjectType(ObjectIdentity('1.3.6.1.2.1.16.3.1.1.12.17'))]
response = snmp_engine.snmpget(varBinds)
print response.varBinds[0][1]
print response.varBinds[0][0]
if str(response.varBinds[0][1]) == '3' or str(response.varBinds[0][1]) == '1':
#############################################################################
#alarm
    varBinds = [ObjectType(ObjectIdentity('1.3.6.1.2.1.16.3.1.1.11.17'),OctetString('FourierSlave'))]#owner
    response = snmp_engine.snmpset(varBinds)
    varBinds = [ObjectType(ObjectIdentity('1.3.6.1.2.1.16.3.1.1.3.17'),ObjectIdentifier('1.3.6.1.2.1.5.8.0'))]#identificador de la instancia de ICMP
    response = snmp_engine.snmpset(varBinds)
    varBinds = [ObjectType(ObjectIdentity('1.3.6.1.2.1.16.3.1.1.4.17'),Integer(2))]#sampleType: 1=absolute -- 2=delta
    response = snmp_engine.snmpset(varBinds)
    varBinds = [ObjectType(ObjectIdentity('1.3.6.1.2.1.16.3.1.1.6.17'),Integer(500))]#Startup: 1=risingAlarm--2=falling--3=risingORfalling
    response = snmp_engine.snmpset(varBinds)
    varBinds = [ObjectType(ObjectIdentity('1.3.6.1.2.1.16.3.1.1.7.17'),Integer(100))]#RisingThreshold (si el valor es >=)
    response = snmp_engine.snmpset(varBinds)
    #varBinds = [ObjectType(ObjectIdentity('1.3.6.1.2.1.16.3.1.1.8.17'),Integer(1))]#FallingThreshold (si el valor es <=)
    #response = snmp_engine.snmpset(varBinds)
    varBinds = [ObjectType(ObjectIdentity('1.3.6.1.2.1.16.3.1.1.2.17'), Integer(25))]#alarmInterval
    response = snmp_engine.snmpset(varBinds)
    varBinds = [ObjectType(ObjectIdentity('1.3.6.1.2.1.16.3.1.1.9.17'),Integer(1717))]#alarmIndex PARA RELACIONAR
    response = snmp_engine.snmpset(varBinds)
    varBinds = [ObjectType(ObjectIdentity('1.3.6.1.2.1.16.3.1.1.12.17'),Integer(1))] #confirmo la alarma validando estado(1)
    response = snmp_engine.snmpset(varBinds)
else:
    varBinds = [ObjectType(ObjectIdentity('1.3.6.1.2.1.16.3.1.1.12.17'),Integer(2))]#creo alarma
    response = snmp_engine.snmpset(varBinds)
#event
varBinds = [ObjectType(ObjectIdentity('1.3.6.1.2.1.16.9.1.1.6.1717'),OctetString('FourierSlave'))]#owner
response = snmp_engine.snmpset(varBinds)
varBinds = [ObjectType(ObjectIdentity('1.3.6.1.2.1.16.9.1.1.2.1717'),OctetString('El_evento_de_Fourier'))]#Description
response = snmp_engine.snmpset(varBinds)
varBinds = [ObjectType(ObjectIdentity('1.3.6.1.2.1.16.9.1.1.3.1717'),Integer(4))]#eventType, 4=logAndTrap--snmptrap=3--log=2--none=1
response = snmp_engine.snmpset(varBinds)
varBinds = [ObjectType(ObjectIdentity('1.3.6.1.2.1.16.9.1.1.4.1717'),OctetString('public'))]#community
response = snmp_engine.snmpset(varBinds)
varBinds = [ObjectType(ObjectIdentity('1.3.6.1.2.1.16.9.1.1.7.1717'),Integer(1))]#validamos estatus con 1
response = snmp_engine.snmpset(varBinds)


#localSNMP:@ip, comunidad
#1.3.6.1.4.1.43.10.10




##############mail que voy a utilizar (capturar trap y generar mail)
# Habilitar https://myaccount.google.com/lesssecureapps

#practgest1on@gmail.com
#practgesti0n

########################################
##pillar LOGS

#pto2 SNMP
varBinds = [ObjectType(ObjectIdentity('1.3.6.1.4.1.43.10.10.2.1.7.2'), Integer(4))]
response = snmp_engine.snmpset(varBinds)
print response.varBinds[0][1]
print response.varBinds[0][0]
#varBinds = [ObjectType(ObjectIdentity('1.3.6.1.4.1.43.10.10.2.1.2.2'), OctetString('155.210.157.204'))]  #ssh de vagrant
#response = snmp_engine.snmpset(varBinds)
#varBinds = [ObjectType(ObjectIdentity('1.3.6.1.4.1.43.10.10.2.1.3.2'), Integer(2))]  #ssh de vagrant
#response = snmp_engine.snmpset(varBinds)
#varBinds = [ObjectType(ObjectIdentity('1.3.6.1.4.1.43.10.10.2.1.4.2'), OctetString('public'))]  # ssh de vagrant
#response = snmp_engine.snmpset(varBinds)



#print response.varBinds[0][1]
#print response.varBinds[0][0]