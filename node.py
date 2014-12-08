from scapy.all import *
import datetime
import sys

data = list()

def checkPacket(pkt):
	#define global data vars
	global data

	#Filter for DNS Responses
	if DNSRR in pkt and pkt.sport == 53:
		# A DNS packet was found

		# Extract transaction id & Checksum
		tID = pkt[DNS].id
		extractedChecksum = 0xff & tID

		# Extract query name
		name = pkt[DNSRR].rrname[0:-1]
		print name		
		nameChecksum = sum(bytearray(name))%256

		# Extracted Data
		extractedData = (0xff00 & tID) >> 8

		print("DSN packet sniffed: \n"
			  "   tID=%d \n"
			  "   name=%s \n"
			  "   name checksum=%d \n"
			  "   extracted checksum=%d \n"
			  "   extracted data byte = %d"
			   % (tID,name,nameChecksum,extractedChecksum,extractedData))
		
		#Check for encoded packet
		if (extractedChecksum==nameChecksum):
			print("Encoded packet found!")

			# concatenate data			
			data.append(extractedData)			
			print ''.join(chr(i) for i in data)


sniff(filter="udp and port 53",prn=checkPacket)
