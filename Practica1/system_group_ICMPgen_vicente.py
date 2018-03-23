from snmp_library import *
from pysnmp.hlapi.asyncore import *

# Email
from scapy.all import *
import snmp_library
import os
import sys

conf.verb = 0

#version = 'v1'
ip_addr = '155.210.157.204'
#community = 'private'
#port = 161

#snmp_engine = snmp_requests(version, community, ip_addr, port)

for i in range(100):
    sr(IP(dst=ip_addr)/ICMP(),timeout=0.01)