# Imports
from snmp_library import *
from pysnmp.hlapi.asyncore import *
import time


# Variables in my program
version = 'v2c'
community = 'public'
ip_addr = '192.168.3.4'
port = 161

# SNMP engine inicialization
snmp_engine = snmp_requests(version, community, ip_addr, port)


#######################################################################
#                            SNMP GET  NEXT                           #
#######################################################################
t = time.time()



ini=1
while (True):
    if (ini):
        varBinds = [ObjectType(ObjectIdentity('1.3.6.1.2.1.1'))]
        #varBinds = [ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2'))]
        response = snmp_engine.snmpgetnext(varBinds)
        ini=0
    else:
        varBinds = [ObjectType(ObjectIdentity(str(response.varBinds[0][0])))]
        response = snmp_engine.snmpgetnext(varBinds)
    print response.varBinds[0][0]

    if str(varBinds[0][0])[12] == '2':#habremos salido de system cuando = '1.3.6.1.2.1.2'
        print('this is not used')
        break