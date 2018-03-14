# Imports
from snmp_library import *
from pysnmp.hlapi.asyncore import *
import time
import numpy
from  matplotlib import pyplot


# Variables in my program
version = 'v1'
community = 'public'
ip_addr = '155.210.157.4'
port = 161
t = []
bps = []

# SNMP engine inicialization
snmp_engine = snmp_requests(version, community, ip_addr, port)






pyplot.plot(t, bps)
pyplot.xlabel('')
pyplot.ylabel('')
pyplot.title('')
pyplot.grid(True)

pyplot.show()
