# Imports
from snmp_library import *
from pysnmp.hlapi.asyncore import *
import time


# Variables in my program
version = 'v2c'#v1
community = 'public'
ip_addr = '192.168.3.4'#es un switch
port = 161

# SNMP engine inicialization
snmp_engine = snmp_requests(version, community, ip_addr, port)


#######################################################################
#                            SNMP WALK                                #
#######################################################################
t = time.time()


#len()-dif
#dif=1 si hay mas objetos del mismo nivel por debajo, 3  para comparar el siguiente


#1.3.6.1.2.1.2.1.0  ->  1.3.6.1.2.1.2.2.1.1.1
#1.3.6.1.2.1.2.1    ->  1.3.6.1.2.1.2.2.1.1.1
#1.3.6.1.2.1.2.2.1.1->  1.3.6.1.2.1.2.2.1.1.. .26 (+2.1)

ini=1
while (True):
    if (ini):
        varBinds = [ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.1'))]
        response = snmp_engine.snmpgetnext(varBinds)

        pos = len(str(varBinds[0][0])) -1           #ultima posicion del OID
        if(str(varBinds[0][0])[pos] == 0):          #si no sea entity (.0) conserva
            pos = len(str(varBinds[0][0])) -3       #si es entity, miro el -1-2

        index = str(varBinds[0][0])[pos]            #valor que cambiara
        ini = 0
    else:
        varBinds = [ObjectType(ObjectIdentity(str(response.varBinds[0][0])))]
        response = snmp_engine.snmpgetnext(varBinds)

    newIndex = str(varBinds[0][0])[pos]
    if index != newIndex:  # estamos en otro nivel
        print '     OID del siguiente objeto'
        break

    print response.varBinds[0][0]




# ending time counter
elapsed = time.time() - t
print 'Total execution time: ' + str(elapsed) + ' seconds'





if response.errorIndication:
    print 'errorIndication'
elif response.errorStatus:
    print 'errorStatus'
else:
    print 'varBinds'

