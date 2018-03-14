from scapy.all import *

# El paquete se construye desde dentro hacia afuera, es decir, empezamos construyendo a partir de los ObjectType
# especificos que se solicitan, despues se construye el varBind qeu contiene el ObjectType, despues el el PDU que
# contiene los varBinds y finalmente el paquete SNMP completo.



# OID solicitado
var_bind_1_oid_type = [int('00' + '0' + '00110', base=2)]
var_bind_1_oid_len = [int('00001000', base=2)]
var_bind_1_oid_val = [int('00101011', base=2), \
                      int('00000110', base=2), \
                      int('00000001', base=2), \
                      int('00000010', base=2), \
                      int('00000001', base=2), \
                      int('00000001', base=2), \
                      int('00000001', base=2),
                      int('00000000', base=2)]

var_bind_1_oid = var_bind_1_oid_type + var_bind_1_oid_len + var_bind_1_oid_val


# Valor de ese OID
var_bind_1_val_type = [int('00' + '0' + '00101', base=2)]
var_bind_1_val_len = [int('00000000', base=2)]
var_bind_1_val_val = []

var_bind_1_val = var_bind_1_val_type + var_bind_1_val_len + var_bind_1_val_val


# Creamos el varBind 1
var_bind_1_type = [int('00' + '1' + '10000', base=2)]
var_bind_1_len = [int('00001100', base=2)]
var_bind_1_val = var_bind_1_oid + var_bind_1_val

var_bind_1 = var_bind_1_type + var_bind_1_len +var_bind_1_val


# Creamos los varBinds
var_binds_type = [int('00' + '1' + '10000', base=2)]
var_binds_len = [int('00001110', base=2)]
var_binds_val = var_bind_1

var_binds = var_binds_type + var_binds_len + var_binds_val


# Creamos el requestID
request_id_type = [int('00' + '0' + '00010', base=2)]
request_id_len = [int('00000010', base=2)]
request_id_val = [int('00010001', base=2),
                  int('00010001', base=2)]

request_id = request_id_type + request_id_len + request_id_val


# Error status
error_status_type = [int('00' + '0' + '00010', base=2)]
error_status_len = [int('00000001', base=2)]
error_status_val = [int('00000000', base=2)]

error_status = error_status_type + error_status_len + error_status_val

# Error index
error_index_type = [int('00' + '0' + '00010', base=2)]
error_index_len = [int('00000001', base=2)]
error_index_val = [int('00000000', base=2)]

error_index = error_index_type + error_index_len + error_index_val


# Creamos la PDU
pdu_type = [int('10' + '1' + '00000', base=2)]
pdu_len = [int('00011010', base=2)]
pdu_val = request_id + error_status + error_index + var_binds

pdu = pdu_type + pdu_len + pdu_val


# Definimos la version
version_type = [int('00' + '0' + '00010', base=2)]
version_len = [int('00000001', base=2)]
version_val = [int('00000000', base=2)]

version = version_type + version_len + version_val


# Definimos la comunidad
community_type = [int('00' + '0' + '00100', base=2)]
community_len = [int('00000110', base=2)]
community_val = [ord('p'), ord('u'), ord('b'), ord('l'), ord('i'), ord('c')]

community = community_type + community_len + community_val


# Creamos le paquete snmp
message_type = [int('00' + '1' + '10000', base=2)]
message_len = [int('00100111', base=2)]
message_val = version + community + pdu


message = message_type + message_len + message_val

message_str = []
for i in message:
    message_str.append(chr(i))


pq = IP(src="192.168.3.5", dst="155.210.157.204") \
    /UDP(sport=12345, dport=161) \
    /Raw(''.join(message_str))



#for i in message:
#    print hex(i)



answers, un_answered = sr(pq, timeout=2)
for req, resp in answers:
    print resp.show()
