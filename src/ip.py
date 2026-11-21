'''
    ip.py
    
    Funciones necesarias para implementar el nivel IP
    Autor: Javier Ramos <javier.ramos@uam.es>
    2022 EPS-UAM
'''
from ethernet import *
from arp import *
from fcntl import ioctl
import subprocess
from arp import *
SIOCGIFMTU = 0x8921
SIOCGIFNETMASK = 0x891b
# Diccionario de protocolos. Las claves con los valores numéricos de protocolos de nivel superior a IP
# por ejemplo (1, 6 o 17) y los valores son los nombres de las funciones de callback a ejecutar.
protocols={}
# IP de la interfaz
myIp = None
# IPID
ipId = None
# Opciones de IP
ipOpts = None
# Tamaño máximo de bloque
MTU = None
# Máscara de red local
netmask = None
# 
defaultGW = None

#Versión IP
IP_VERSION = 0x4
#Type of service
TOS_DEF = 1
#Time to live
TTL_DEF = 40

#Tamaño mínimo de la cabecera IP
IP_MIN_HLEN = 20
#Tamaño máximo de la cabecera IP
IP_MAX_HLEN = 60
#Ethertype de un datagrama IP
IP_ETHERTYPE = 0x0800


NUM_PAREJA = 3
def chksum(msg):
    '''
        Nombre: chksum
        Descripción: Esta función calcula el checksum IP sobre unos datos de entrada dados (msg)
        Argumentos:
            -msg: array de bytes con el contenido sobre el que se calculará el checksum
        Retorno: Entero de 16 bits con el resultado del checksum en ORDEN DE RED
    '''
    s = 0
    y = 0xa29f    
    for i in range(0, len(msg), 2):
        if (i+1) < len(msg):
            a = msg[i] 
            b = msg[i+1]
            s = s + (a+(b << 8))
        elif (i+1)==len(msg):
            s += msg[i]
        else:
            raise 'Error calculando el checksum'
    y = y & 0x00ff
    s = s + (s >> 16)
    s = ~s & 0xffff

    return s

def getMTU(interface):
    '''
        Nombre: getMTU
        Descripción: Esta función obteiene la MTU para un interfaz dada
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar la MTU
        Retorno: Entero con el valor de la MTU para la interfaz especificada
    '''
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    ifr = struct.pack('16sH', interface.encode("utf-8"), 0)
    mtu = struct.unpack('16sH', ioctl(s,SIOCGIFMTU, ifr))[1]
   
    s.close()
   
    return mtu
   
def getNetmask(interface):
    '''
        Nombre: getNetmask
        Descripción: Esta función obteiene la máscara de red asignada a una interfaz 
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar la máscara
        Retorno: Entero de 32 bits con el valor de la máscara de red
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = fcntl.ioctl(
        s.fileno(),
       SIOCGIFNETMASK,
        struct.pack('256s', (interface[:15].encode('utf-8')))
    )[20:24]
    s.close()
    return struct.unpack('!I',ip)[0]


def getDefaultGW(interface):
    '''
        Nombre: getDefaultGW
        Descripción: Esta función obteiene el gateway por defecto para una interfaz dada
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar el gateway
        Retorno: Entero de 32 bits con la IP del gateway
    '''
    p = subprocess.Popen(['ip r | grep default | awk \'{print $3}\''], stdout=subprocess.PIPE, shell=True)
    dfw = p.stdout.read().decode('utf-8').strip()
    print(dfw)
    if not dfw:
        return None
    return struct.unpack('!I', socket.inet_aton(dfw))[0]

#Devuelve el nibble más significativo dentro de un byte
def getMsn(byte):
    return (byte>>4 & 0xF)

#Devuelve el nibble menos significativo dentro de un byte
def getLsn(byte):
    return byte & 0xF

def process_IP_datagram(us,header,data,srcMac):
    '''
        Nombre: process_IP_datagram
        Descripción: Esta función procesa datagramas IP recibidos.
            Se ejecuta una vez por cada trama Ethernet recibida con Ethertype 0x0800
            Esta función debe realizar, al menos, las siguientes tareas:
                -Extraer los campos de la cabecera IP (includa la longitud de la cabecera)
                -Calcular el checksum y comprobar que es correcto                    
                -Analizar los bits de de MF y el offset. Si el offset tiene un valor != 0 dejar de procesar el datagrama (no vamos a reensamblar)
                -Loggear (usando logging.debug) el valor de los siguientes campos:
                    -Longitud de la cabecera IP
                    -IPID
                    -TTL
                    -Valor de las banderas DF y MF
                    -Valor de offset
                    -IP origen y destino
                    -Protocolo
                -Comprobar si tenemos registrada una función de callback de nivel superior consultando el diccionario protocols y usando como
                clave el valor del campo protocolo del datagrama IP.
                    -En caso de que haya una función de nivel superior registrada, debe llamarse a dicha funciñón 
                    pasando los datos (payload) contenidos en el datagrama IP.
        
        Argumentos:
            -us: Datos de usuario pasados desde la llamada de pcap_loop. En nuestro caso será None
            -header: cabecera pcap_pktheader
            -data: array de bytes con el contenido del datagrama IP
            -srcMac: MAC origen de la trama Ethernet que se ha recibido
        Retorno: Ninguno
    '''

    global myIp, MTU, protocols

    # Se descarta un datagrama en caso de que sea demasiado grande
    if len(data) > MTU or len(data) < 1: return

    version = getMsn(data[0])
    ihl = getLsn(data[0]) * 4

    # En caso de cabecera mal formateada se descarta
    if ihl < IP_MIN_HLEN or ihl > IP_MAX_HLEN or ihl > len(data): return
    if chksum(data[:ihl]) != 0: return

    tos = data[1]
    totalLength = int.from_bytes(data[2:4], 'big')
    curIPID = int.from_bytes(data[4:6], 'big')
    flagsAndOffset = int.from_bytes(data[6:8], 'big')
    df = flagsAndOffset & 1<<14
    mf = flagsAndOffset & 1<<13
    offset = flagsAndOffset & 0x1FFF
    # Descartamos reensamblado
    if offset != 0: return
    ttl = data[8]
    protocol = data[9]
    ipOrig = data[12:16]
    ipDest = data[16:20]

    logging.debug(
                "Longitud de cabecera: {}\n"
                "IPID: {}\n"
                "TTL: {}\n"
                "DF: {}\n"
                "MF: {}\n"
                "Offset: {}\n"
                "IP origen: {}\n"
                "IP destino: {}\n"
                "Protocolo: {}\n\n".
                format(
                    ihl,
                    curIPID,
                    ttl, 
                    df, 
                    mf, 
                    offset, 
                    '.'.join(['{}'.format(b) for b in ipOrig]), 
                    '.'.join(['{}'.format(b) for b in ipDest]), 
                    protocol)
                )

    if protocol in protocols:
        protocols[protocol](us, header, data[ihl:], int.from_bytes(ipOrig, 'big'))




def registerIPProtocol(callback,protocol):
    '''
        Nombre: registerIPProtocol
        Descripción: Esta función recibirá el nombre de una función y su valor de protocolo IP asociado y añadirá en la tabla 
            (diccionario) de protocolos de nivel superior dicha asociación. 
            Este mecanismo nos permite saber a qué función de nivel superior debemos llamar al recibir un datagrama IP  con un 
            determinado valor del campo protocolo (por ejemplo TCP o UDP).
            Por ejemplo, podemos registrar una función llamada process_UDP_datagram asociada al valor de protocolo 17 y otra 
            llamada process_ICMP_message asocaida al valor de protocolo 1. 
        Argumentos:
            -callback_fun: función de callback a ejecutar cuando se reciba el protocolo especificado. 
                La función que se pase como argumento debe tener el siguiente prototipo: funcion(us,header,data,srcIp):
                Dónde:
                    -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
                    -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
                    -data: payload del datagrama IP. Es decir, la cabecera IP NUNCA se pasa hacia arriba.
                    -srcIP: dirección IP que ha enviado el datagrama actual.
                La función no retornará nada. Si un datagrama se quiere descartar basta con hacer un return sin valor y dejará de procesarse.
            -protocol: valor del campo protocolo de IP para el cuál se quiere registrar una función de callback.
        Retorno: Ninguno 
    '''

    global protocols
    protocols[protocol] = callback

def initIP(interface,opts=None):
    global myIp, MTU, netmask, defaultGW,ipOpts,ipId
    '''
        Nombre: initIP
        Descripción: Esta función inicializará el nivel IP. Esta función debe realizar, al menos, las siguientes tareas:
            -Llamar a initARP para inicializar el nivel ARP
            -Obtener (llamando a las funciones correspondientes) y almacenar en variables globales los siguientes datos:
                -IP propia
                -MTU
                -Máscara de red (netmask)
                -Gateway por defecto
            -Almacenar el valor de opts en la variable global ipOpts
            -Registrar a nivel Ethernet (llamando a registerCallback) la función process_IP_datagram con el Ethertype 0x0800
            -Inicializar el valor de IPID con el número de pareja
        Argumentos:
            -interface: cadena de texto con el nombre de la interfaz sobre la que inicializar ip
            -opts: array de bytes con las opciones a nivel IP a incluir en los datagramas o None si no hay opciones a añadir
        Retorno: True o False en función de si se ha inicializado el nivel o no
    '''
    if interface is None: return False

    if initARP(interface) == -1: return False

    myIp = getIP(interface)
    MTU = getMTU(interface)
    netmask = getNetmask(interface)
    defaultGW = getDefaultGW(interface)

    if myIp is None or MTU is None or netmask is None or defaultGW is None: return False
    
    if opts is not None: ipOpts = opts 

    registerEthCallback(process_IP_datagram, IP_ETHERTYPE)

    ipId = NUM_PAREJA

    return True



def sendIPDatagram(dstIP,data,protocol):
    global myIp, ipId, defaultGW, netmask
    '''
        Nombre: sendIPDatagram
        Descripción: Esta función construye un datagrama IP y lo envía. En caso de que los datos a enviar sean muy grandes la función
        debe generar y enviar el número de fragmentos IP que sean necesarios.
        Esta función debe realizar, al menos, las siguientes tareas:
            -Determinar si se debe fragmentar o no y calcular el número de fragmentos
            -Para cada datagrama o fragmento:
                -Construir la cabecera IP con los valores que corresponda.Incluir opciones en caso de que ipOpts sea distinto de None
                -Calcular el checksum sobre la cabecera y añadirlo a la cabecera
                -Añadir los datos a la cabecera IP
                -En el caso de que sea un fragmento ajustar los valores de los campos MF y offset de manera adecuada
                -Enviar el datagrama o fragmento llamando a sendEthernetFrame. Para determinar la dirección MAC de destino
                al enviar los datagramas se debe hacer unso de la máscara de red:                  
            -Para cada datagrama (no fragmento):
                -Incrementar la variable IPID en 1.
        Argumentos:
            -dstIP: entero de 32 bits con la IP destino del datagrama 
            -data: array de bytes con los datos a incluir como payload en el datagrama
            -protocol: valor numérico del campo IP protocolo que indica el protocolo de nivel superior de los datos
            contenidos en el payload. Por ejemplo 1, 6 o 17.
        Retorno: True o False en función de si se ha enviado el datagrama correctamente o no
          
    '''

    ihl = 20 + 4*( (len(ipOpts)+3) //4) if ipOpts is not None else 20

    dataSize = MTU - ihl
    dataSize = (dataSize // 8) * 8

    # Función techo, si no cabe hace falta mandar uno más
    nFragments = (len(data) + dataSize - 1) // dataSize 

    optsInFragment = None
    if (ipOpts is not None):
        relleno = (4 - (len(ipOpts) % 4)) % 4
        optsInFragment = ipOpts + bytes(relleno)

    totalSize = len(data)
    offset = 0

    if myIp & netmask == dstIP & netmask:
        dstMac = ARPResolution(dstIP)
    else:
        dstMac = ARPResolution(defaultGW)

    if dstMac is None: return False

    for x in range(1,nFragments+1) : 
        ipHeader = bytes([IP_VERSION<<4 | ihl//4, TOS_DEF])
        dataSentSize = min(totalSize, dataSize)
        fragmentSize = dataSentSize + ihl
        dataInFragment = data[offset*8: offset*8 + dataSentSize]

        ipHeader += fragmentSize.to_bytes(2, 'big')
        ipHeader += ipId.to_bytes(2, 'big')

        MF = 1 if x<nFragments else 0
        flagsAndOffset = offset | MF<<13
        ipHeader += flagsAndOffset.to_bytes(2, 'big')
        ipHeader += TTL_DEF.to_bytes(1, 'big')
        ipHeader += bytes([protocol])
       
        ipHeader += bytes(2)
        
        ipHeader += myIp.to_bytes(4, 'big')
        ipHeader += dstIP.to_bytes(4, 'big')

        if optsInFragment is not None: ipHeader += optsInFragment

        checksum = chksum(ipHeader)
        ipHeader = ipHeader[:10] + checksum.to_bytes(2, 'big') + ipHeader[12:]

        if sendEthernetFrame(ipHeader + dataInFragment, len(ipHeader) + len(dataInFragment), IP_ETHERTYPE, dstMac) == -1: return False

        totalSize -= dataSentSize
        offset += dataSize // 8 

    ipId+=1


