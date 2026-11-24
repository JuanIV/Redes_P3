'''
    practica3.py
    Envía datagramas UDP o ICMP sobre protocolo IP. 

    Autor: Javier Ramos <javier.ramos@uam.es>
    2022 EPS-UAM
'''


from udp import *
from icmp import *
from ethernet import *
from ethmsg import *
import sys
import binascii
import signal
import argparse
import struct
from argparse import RawTextHelpFormatter
import time
import logging
import socket

DST_PORT = 53
ICMP_ECHO_REQUEST_TYPE = 8
ICMP_ECHO_REQUEST_CODE = 0
ICMP_ID = 3

ipRROption = bytes([7,11,4,0,0,0,0,0,0,0,0,0])

if __name__ == "__main__":
	ICMP_SEQNUM = 0
	parser = argparse.ArgumentParser(description='Envía datagramas UDP o mensajes ICMP con diferentes opciones',
	formatter_class=RawTextHelpFormatter)
	parser.add_argument('--itf', dest='interface', default=False,help='Interfaz a abrir')
	parser.add_argument('--dstIP',dest='dstIP',default = False,help='Dirección IP destino')
	parser.add_argument('--debug', dest='debug', default=False, action='store_true',help='Activar Debug messages')
	parser.add_argument('--addOptions', dest='addOptions', default=False, action='store_true',help='Añadir opciones a los datagranas IP')
	parser.add_argument('--dataFile',dest='dataFile',default = False,help='Fichero con datos a enviar')
	parser.add_argument('--icmpsize',dest='icmpsize', type = int, default = False,help='Tamaño en bytes de los paquetes ICMP a enviar')
	#TODO: Opción --icmpsize
	args = parser.parse_args()

	if args.debug:
		logging.basicConfig(level = logging.DEBUG, format = '[%(asctime)s %(levelname)s]\t%(message)s')
	else:
		logging.basicConfig(level = logging.INFO, format = '[%(asctime)s %(levelname)s]\t%(message)s')

	if args.interface is False:
		logging.error('No se ha especificado interfaz')
		parser.print_help()
		sys.exit(-1)

	if args.dstIP is False:
		logging.error('No se ha especificado dirección IP')
		parser.print_help()
		sys.exit(-1)

	ipOpts = None
	if args.addOptions:
		ipOpts = ipRROption

	udp_data = bytes([0,6,1,0,0,1,0,0,0,0,0,0,3,0x77,0x77,0x77,6,0x67,0x6f,0x6f,0x67,0x6c,0x65,3,0x63,0x6f,0x6d,0,0,1,0,1])
	if args.dataFile:
		with open(args.dataFile,'r') as f:
			#Leemos el contenido del fichero
			data=f.read()
			#Pasamos los datos de cadena a bytes
			udp_data = data.encode()
			
	icmp_data = b'ABCDEFGHIJKL'
	if args.icmpsize is not False:
		if args.icmpsize < 0:
			logging.error('El tamaño ICMP no puede ser negativo')
			sys.exit(-1)
		letras = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
		icmp_data = (letras * (args.icmpsize // len(letras) + 1))[:args.icmpsize]

	#Inicializamos el nivel Ethernet en la interfaz especificada
	if (startEthernetLevel(args.interface) != 0):
		logging.error('Ethernet no inicializado')
		sys.exit(-1)
	
	if (initEthMsg(args.interface) != 0):
		logging.error('EthMsg no inicializado')
		stopEthernetLevel()
		sys.exit(-1)

	if initIP(args.interface,ipOpts) == False:
		logging.error('Inicializando nivel IP')
		sys.exit(-1)
		
	initICMP()
	initUDP()

	
	
	
	while True:
		try:
			msg = input('\n\t0x16\n\tIntroduzca opcion:\n\t1.Enviar ping\n\t2.Enviar datagrama UDP:')
			if msg == 'q':
				break
			elif msg == '1':
				sendICMPMessage(icmp_data,ICMP_ECHO_REQUEST_TYPE,ICMP_ECHO_REQUEST_CODE,ICMP_ID,ICMP_SEQNUM,struct.unpack('!I',socket.inet_aton(args.dstIP))[0])
				ICMP_SEQNUM += 1
			elif msg == '2':
				sendUDPDatagram(udp_data,DST_PORT,struct.unpack('!I',socket.inet_aton(args.dstIP))[0])
		except KeyboardInterrupt:
			print('\n')
			break

	logging.info('Cerrando ....')
	stopEthernetLevel()
