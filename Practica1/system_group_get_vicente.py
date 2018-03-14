# Imports
from snmp_library import *
from pysnmp.hlapi.asyncore import *
import time


# Variables in my program
version = 'v2c'#v1
community = 'public' #comunidad utilizada (public/private...)
ip_addr = '192.168.3.4'#direccion del agente
port = 161

# SNMP engine inicialization
snmp_engine = snmp_requests(version, community, ip_addr, port)


#######################################################################
#                            SNMP GET                                 #
#######################################################################
#                  1.- 1 PDU SNMPGET por cada objeto
t = time.time()
i = 1
while (i<8):
    # varBinds = [ObjectType(ObjectIdentity('1.3'),OctetString('calabaza'))] podemos mandar ObjectTipe(OID, null) en vez de calabaza
    varBinds = [ObjectType(ObjectIdentity('1.3.6.1.2.1.1.' + str(i) + '.0'))]
    response = snmp_engine.snmpget(varBinds)
    tipe=tools().var_type(varBinds)#nos dice el tipo de variable(self,var) EN ESTE CASO ES: list
    #print str(response.varBinds[0][0])+' contiene: '+str(response.varBinds[0][1])#elemento 0, OID y objeto contenido
    #print tipe
    i+=1

# ending time counter
elapsed = time.time() - t
print 'Total execution time: ' + str(elapsed) + ' seconds'





#                  2.- 1 unico PDU SNMP GET para todo el grupo
t2 = time.time()
#PEDIMOS TODOS LOS OBJETOS QUE NECESITE EN EL VARBINS UNA VEZ HEMOPS REFERENCIADO QUE SON ObjectType
varBinds = [ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0')), ObjectType(ObjectIdentity('1.3.6.1.2.1.1.2.0')),
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.3.0')), ObjectType(ObjectIdentity('1.3.6.1.2.1.1.4.0')),
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.5.0')), ObjectType(ObjectIdentity('1.3.6.1.2.1.1.6.0')),
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.7.0'))]
#print varBinds
response = snmp_engine.snmpget(varBinds)
#print response.varBinds[0]
tipe=tools().var_type(varBinds[0])
#print tipe

elapsed2 = time.time() - t2
print 'Total execution time2 : ' + str(elapsed2) + ' seconds'





#                  3.-como 2 pero con un OID mal formado
t = time.time()
varBinds = [ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0')), ObjectType(ObjectIdentity('1.3.6.1.2.1.1.2.0')),
           ObjectType(ObjectIdentity('1.3.6.1.2.1.1.3.0')), ObjectType(ObjectIdentity('1.3.6.1.2.1.1.4.0')),
           ObjectType(ObjectIdentity('1.3.6.1.2.1.1.55.0')), ObjectType(ObjectIdentity('1.3.6.1.2.1.1.6.0')),#instroduzco error en 55
           ObjectType(ObjectIdentity('1.3.6.1.2.1.1.7.0'))]
response = snmp_engine.snmpget(varBinds)
#print response.errorIndication
#print response.errorStatus
#print response.errorIndex
print response.varBinds[4]
print response.varBinds[2]#no me devuelve el resto, como deberia hacer el agente segun el standar
#deberiamos recibir un genError e vez de notSuchName rfc2576
#se esta comportando como la v1 en vez de v2c

tipe=tools().var_type(response.varBinds[4][1])#el erroneo
print tipe

elapsed = time.time() - t
print 'Total execution time: ' + str(elapsed) + ' seconds'










# Send request

if response.errorIndication:
    print 'errorIndication'
elif response.errorStatus:
    print 'errorStatus'
else:
    print 'varBinds'

