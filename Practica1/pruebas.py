# Imports
from snmp_library import *
from pysnmp.hlapi.asyncore import *
import time
import sys
import numpy as np
import matplotlib.pyplot as plt

# Variables in my program
version = 'v1'#v2c
community = 'public'
ip_addr = '155.210.157.3'#155.210.157.3 es un hub, .4 el switch
port = 161

# SNMP engine inicialization
snmp_engine = snmp_requests(version, community, ip_addr, port)


#######################################################################
#                            SNMP pp                                  #
#######################################################################
# Imports
from snmp_library import *
from pysnmp.hlapi.asyncore import *
import time

import numpy as np
import matplotlib.pyplot as plt


# Variables in my program
version = 'v1'#v2c
community = 'private'
ip_addr = '155.210.157.3'#155.210.157.3 es un hub, .4 el switch
port = 161

# SNMP engine inicialization
snmp_engine = snmp_requests(version, community, ip_addr, port)

varBinds1 = [ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.10.39534'))]
























#print response1.errorIndication
#print response1.errorStatus