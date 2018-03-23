# Imports
from snmp_library import *
from pysnmp.hlapi.asyncore import *
import time
from scapy.all import *
# Imports
from snmp_library import *
from pysnmp.hlapi.asyncore import *

import os
import sys

####################graficas
#import numpy as np
#import matplotlib.pyplot as plt

# Variables in my program
version = 'v1'#v2c
community = 'security'
ip_addr = '155.210.157.204'#155.210.157.3 es un hub, .4 el switch
port = 161

# SNMP engine inicialization
snmp_engine = snmp_requests(version, community, ip_addr, port)


#######################################################################
#                            SNMP pp                                  #
#######################################################################


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

#tras cacti:
##
##monitorizar tabla channel