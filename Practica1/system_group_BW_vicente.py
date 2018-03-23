# Imports
from snmp_library import *
from pysnmp.hlapi.asyncore import *
import time

import numpy as np
import matplotlib.pyplot as plt


# Variables in my program
version = 'v1'#v2c
community = 'security'#public, private, security, calabaza...
ip_addr = '155.210.157.3'#155.210.157.3 es un hub, .4 el switch
port = 161

# SNMP engine inicialization
snmp_engine = snmp_requests(version, community, ip_addr, port)


#######################################################################
#                            SNMP BW                                  #
#######################################################################
#1.3.6.1.2.1.2.2.1.10 ifInOctets
#1.3.6.1.2.1.2.2.1.16 ifOutOctets
#1.3.6.1.2.1.1.3 sysUpTime

#varBinds1 = [ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.10.4227666'))] #get a ifOutOctets del pto10 RECUERDA QUE ES TABLA
varBinds1 = [ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.10.39534'))]
varBinds11 = [ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.16.39534'))]
#elijo puertos que son de monitorizacion y no gestion(2 de gestion) y elijo los que pueden contener trafico
#haciendo getnext desde get 1.3.6.1.2.1.2.2.1.10 sabiendo que el puerto10 esta en 4227666 con getnext
#habria que mirar que fuese puerto activo, podemos deducirlo del ifDescription si el gestor les pone nombre reconocible o del trafico monitorizado en cada puerto
# tambien con MG-soft
response1 = snmp_engine.snmpget(varBinds1)
response11 = snmp_engine.snmpget(varBinds11)
bw=response1.varBinds[0][1]
bwo=response11.varBinds[0][1]
varBinds2 = [ObjectType(ObjectIdentity('1.3.6.1.2.1.1.3.0'))] #get a sysUpTime
response2 = snmp_engine.snmpget(varBinds2)
tt=response2.varBinds[0][1]

t=5#cada cuantos segundos se actualiza
i=0

while(True):
    response1 = snmp_engine.snmpget(varBinds1)
    response11 = snmp_engine.snmpget(varBinds11)
    bw2 = response1.varBinds[0][1]
    bwo2 = response11.varBinds[0][1]
    incBw = (bw2 - bw)*8;#lo paso a bits desde octetos
    incBwo = (bwo2 - bwo)*8;#lo paso a bits desde octetos
    response2 = snmp_engine.snmpget(varBinds2)
    tt2 = response2.varBinds[0][1]
    incTt = (tt2 - tt);#lo paso desde centesimas de segundo

    rate=incBw/(incTt/10)
    rate2=incBwo/(incTt/10)


    #print 'Bandwith in rate: ' + str(rate)+ ' bps'
    #print 'Bandwith out rate: ' + str(rate2)+ ' bps'
    #print('-----------------------------------------')

    # printeo
    # listas valores
    if (i == 0):
        x = [i]
        y1 = [rate]
        y2 = [rate2]
    else:
        x += [i]
        y1 += [rate]
        y2 += [rate2]
    # grafico
    plt.plot(x, y1, 'r^', x, y2, 'bs')
    plt.ylabel('UPstream[red] DOWNstream[blue]      (bps)')
    plt.xlabel('Instante')



    plt.grid(True)
    plt.pause(0.0025)
    i += 1
    #print('.')





#reseteo
    bw=bw2
    tt=tt2
    time.sleep(1)