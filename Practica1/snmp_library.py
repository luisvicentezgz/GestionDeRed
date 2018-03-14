from pysnmp.hlapi.asyncore import *
from pysnmp.smi.rfc1902 import *
import re
import time

class response (object):

    def __init__(self, errorIndication, errorStatus, errorIndex, varBinds):
        self.errorIndication = errorIndication
        self.errorStatus = errorStatus
        self.errorIndex = errorIndex
        self.varBinds = varBinds
        self.varBinds = varBinds

    def pretty_print(self):
        if self.errorIndication:
            print self.errorIndication
        elif self.errorStatus:
            print self.errorStatus
            print self.errorIndex
        else:
            for varBind in self.varBinds:
                print tools().var_type(varBind[0]) + ' : ' + str(varBind[0])
                print tools().var_type(varBind[1]) + ' : ' + str(varBind[1])



class snmp_requests():

    def __init__(self, version, community, ip_addr, port):
        self.version = version
        self.community = community
        self.ip_addr = ip_addr
        self.port = port
        self.response = response('Only v1 and v2c supported', 0, 0, [])

    def cbFun_get_set(self, snmpEngine, sendRequestHandle, errorIndication, errorStatus, errorIndex, varBinds, cbCtx):
        self.response = response(errorIndication, errorStatus, errorIndex, varBinds)

    def cbFun_next(self, snmpEngine, sendRequestHandle, errorIndication, errorStatus, errorIndex, varBinds, cbCtx):
        if len(varBinds) > 0:
            varBinds = varBinds[0]
        self.response = response(errorIndication, errorStatus, errorIndex, varBinds)

    def cbFun_bulk(self, snmpEngine, sendRequestHandle, errorIndication, errorStatus, errorIndex, varBinds, cbCtx):
        # Formato de varBinds, suponiendo nonRepeaters=1 y maxRepetitions=3, para dos varBinds en el requests
        # Para aquellso correspondientes al nonRepeaters, aparece maxRepetitiones veces el mismo varBind
        # [ [resp 1.1, resp 2.1], [resp 1.1, resp 2.2], [resp 1.1, resp 2.3] ]
        # Donde resp 1.1 es la respuesta al primer varBind del request (en este caso solo un varBinds por ser nonRepeaters)
        # Donde resp 2.1,2.2,2.3 son las maxRepetitions varBinds correspondientes a las siguientes varBinds del request

        # Formato de aux
        # [ [resp1.1], [resp 2.1, resp 2.2, resp 2.3] ]
        aux = []
        for i in range(len(varBinds)):
            varBind = varBinds[i]
            for j in range(len(varBind)):
                if i == 0:
                    aux.append([])
                if (len(aux[j]) == 0) or (aux[j][0][0] != varBind[j][0]):
                    aux[j].append(varBind[j])

        aux2 = []
        for a in aux:
            for b in a:
                aux2.append(b)

        self.response = response(errorIndication, errorStatus, errorIndex, aux2)


    def snmpget(self, varbinds):

        snmpEngine = SnmpEngine()
        if self.version == 'v1':
            getCmd(snmpEngine,
                   CommunityData(self.community, mpModel=0),
                   UdpTransportTarget((self.ip_addr, self.port)),
                   ContextData(),
                   *varbinds,
                   cbFun=self.cbFun_get_set
                  )

        elif self.version == 'v2c':
            getCmd(snmpEngine,
                   CommunityData(self.community),
                   UdpTransportTarget((self.ip_addr, self.port)),
                   ContextData(),
                   *varbinds,
                   cbFun=self.cbFun_get_set
                  )

        else:
            return self.response

        snmpEngine.transportDispatcher.runDispatcher()
        return self.response



    def snmpgetnext(self, varbinds):

        snmpEngine = SnmpEngine()
        if self.version == 'v1':
            nextCmd(snmpEngine,
                   CommunityData(self.community, mpModel=0),
                   UdpTransportTarget((self.ip_addr, self.port)),
                   ContextData(),
                   *varbinds,
                   cbFun=self.cbFun_next
                  )

        elif self.version == 'v2c':
            nextCmd(snmpEngine,
                   CommunityData(self.community),
                   UdpTransportTarget((self.ip_addr, self.port)),
                   ContextData(),
                   *varbinds,
                   cbFun=self.cbFun_next
                  )

        else:
            return self.response

        snmpEngine.transportDispatcher.runDispatcher()
        return self.response



    def snmpset(self, varbinds):

        snmpEngine = SnmpEngine()
        if self.version == 'v1':
            setCmd(snmpEngine,
                   CommunityData(self.community, mpModel=0),
                   UdpTransportTarget((self.ip_addr, self.port)),
                   ContextData(),
                   *varbinds,
                   cbFun=self.cbFun_get_set
                  )

        elif self.version == 'v2c':
            setCmd(snmpEngine,
                   CommunityData(self.community),
                   UdpTransportTarget((self.ip_addr, self.port)),
                   ContextData(),
                   *varbinds,
                   cbFun=self.cbFun_get_set
                  )

        else:
            return self.response

        snmpEngine.transportDispatcher.runDispatcher()
        return self.response


    def snmpbulk(self, nonRepeaters, maxRepetitions, varbinds):

        snmpEngine = SnmpEngine()
        if self.version == 'v2c':
            bulkCmd(snmpEngine,
                   CommunityData(self.community),
                   UdpTransportTarget((self.ip_addr, self.port)),
                   ContextData(),
                   nonRepeaters, maxRepetitions,
                   *varbinds,
                   cbFun=self.cbFun_bulk
                  )

        else:
            return self.response

        snmpEngine.transportDispatcher.runDispatcher()
        return self.response



class tools():

    def var_type(self, var):
        s = str(type(var))
        ss = re.findall(r"'(.*?)'",s)[0]
        if '.' not in ss:
            return ss
        else:
            return ss.rsplit('.', 1)[-1]


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'