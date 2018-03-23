#################################
#####   Network discovery   #####
#################################
#LIBRARIES
from scapy.all import *
import snmp_library
import os
import sys

conf.verb = 0 #disable verbose mode


#FUNCTIONS

# ARPdiscovery every @ip        [ansARP]=
def ARPping(IP_src):
    i=0
    while (i < 255):
        i+=1
        IP_dst = "155.210.157."+str(i)#recorre toda la red
        ansARP, unansARP = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op="who-has", psrc=IP_src, pdst=IP_dst), timeout=2, inter=0.1, verbose=0)
        ######## free-delay by printing if desired
        #print(str(ansARP)+' -- #'+str(i)+' iteration')
        return ansARP
#cut bwsrc from mac
def GetMac(ans):
    MAC = str(ans)
    print MAC
    ini = MAC.find("bwsrc=")+6
    end = MAC.rfind("psrc=")-1#por si hay varios segmentos
    return MAC[ini:end]#return MAC[ini:(ini+17)]
#ARPping vTCP sr       [ansSYN]=
def SYNTCP (IP_src, IP_dst, port_src, port_dst):
    ip = IP(src=IP_src, dst=IP_dst)
    tcp = TPC(sport=port_src, dport=port_dst, flags='S', seq=1000)
    ansSYN, unansSYN = sr(ip/tcp, timeout=1)
    return ansSYN

IP_src = '155.210.157.99'#puedo suplantar otra IP pero tmbn tendre que escuchar esos mensajes en vez de los mios
#IP_dst = '155.210.157.4'
#port_dst=80
port_src = 80#http(sobre ARP)

req_ports = [21,23,25,80,143,161,162]
trad_ports = ['FTPCtrol','Telnet','SMTP','HTTP','IMAP','SNMP','trapTCP']
res=[]

i=0
MAC_dst=':('#predet
while(i<255):
   i+=1
   IP_dst = "155.210.157."+str(i)#recorre toda la red
   ansARP=ARPping(IP_src)
   try:
       for rcvARP in ansARP:
           MAC_dst=GetMac(rcvARP)
   except:
       MAC_dst = ':('
   res+=[str(IP_dst)+"\t"+str(MAC_dst)]
   res[i-1] += "\tports:"
   print(res[i-1])

   if(MAC_dst == ':('):
       for port_dst in req_ports:
           ansSYN=SYNTCP(IP_src, IP_dst, port_src, port_dst)
           for rcvSYN in ansSYN:
               if(str(rcvSYN).find("flags=SA")):
                   try:
                       res[i] += " "+str(port_dst)+"--"+str(trad_ports[req_ports.find(port_dst)])
                   except:
                       print("error..")
#
#
##SYN       ->
#
#
##SYN/ACK   <-
#
##ACK       ->
#
#
while (i>-1):
    print (res[i])
    i-=1