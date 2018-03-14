# Imports
from snmp_library import *
from pysnmp.hlapi.asyncore import *
import time


# Variables in my program
version = 'v2c'#v1
community = 'private'  #comunidad de lectura/escritura
ip_addr = '192.168.3.4' #es un switch
port = 161

# SNMP engine inicialization
snmp_engine = snmp_requests(version, community, ip_addr, port)


#######################################################################
#                            SNMP SET                                 #
#######################################################################
t = time.time()

varBinds = [ObjectType(ObjectIdentity('1.3.6.1.2.1.1.5.0'),OctetString('Admin'))]#instancia(.0) de OID del sysName 1.3.6.1.2.1.1.5, cambio el valor a Admin
response = snmp_engine.snmpset(varBinds)

#print response.varBinds[0][0]#print value of zero-position


# ending time counter
elapsed = time.time() - t
print 'Total execution time: ' + str(elapsed) + ' seconds'

print response.errorIndication

if response.errorIndication:
    print 'errorIndication'
elif response.errorStatus:
    print 'errorStatus'
else:
    print 'varBinds'