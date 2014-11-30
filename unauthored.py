import socket
import fcntl
import struct

def get_ip_address(ifname):
	# Below Code snippet modified from Martin Konecny's
	# Stack exchange response
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])
