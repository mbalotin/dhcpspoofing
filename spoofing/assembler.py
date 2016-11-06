#!/usr/bin/python3 -tt

import uuid
import fcntl, socket, struct

def createOffer(transaction_id, dest_MAC, dest_ip, adapter):
    #Ethernet
    packet = dest_MAC
    packet += getMyMAC(adapter)
    packet += b'\x08\x00'
    #IP
    packet += b'\x45'
    packet += b'\xc0'
    packet += b'\x01\x48'
    packet += b'\x00'
    packet += b'\xf0\xda'
    packet += b'\x00' * 2
    packet += b'\x40' #d64
    packet += b'\x11'
    #TODO ----------------
    packet += b'\x00' * 2 # checksum
    packet += getMyIP()
    packet += dest_ip
    #UDP
    packet += b'\x00\x43'
    packet += b'\x00\x44'
    packet += b'\x01\x34'	# length
    packet += b'\x00' * 2
    #Bootstrap
    packet += b'\x02' 	# msg type
    packet += b'\x01' 	# hardware type
    packet += b'\x06' 	# length
    packet += b'\x00' 	#hops
    packet += transaction_id
    packet += b'\x00' * 2 	#seconds elapsed
    packet += b'\x00' * 2 	# flags
    packet += b'\x00' + 4 	# client IP
    packet += dest_ip 	# YOUR IP
    packet += getMyIP() # Next server
    packet += b'\x00' * 4	# Relay
    packet += dest_MAC
    packet += b'\x00' * 202 
    packet += b'\x63\x82\x53\x63' # MAGIC TAG
    #DHCP Options
    
    #Mesage type
    packet += b'\x35'
    packet += b'\x01'
    packet += b'\x02'
    #DHCP Server Id
    packet += b'\x36'
    packet += b'\x04'
    packet += getMyIP()
    # Ip Lease Time
    packet += b'\x33'
    packet += b'\x04'
    packet += b'\xff' * 4
    # Renewal Time
    packet += b'\x3a'
    packet += b'\x04'
    packet += b'\xff' * 4
    # Rebind Time
    packet += b'\x3b'
    packet += b'\x04'
    packet += b'\xff' * 4
    # Subnet Mask
    packet += b'\x01'
    packet += b'\x04'
    packet += b'\xff' * 3
    packet += b'\x00'
    # Broadcast
    packet += b'\x1c'
    packet += b'\x04'
    packet += getMyIP() | b'\xff'
    # Domain Name Server
    packet += b'\x06'
    packet += b'\x04'
    packet += getMyIP()
    # Router
    packet += b'\x03'
    packet += b'\x04'
    packet += getMyIP()
    # End
    packet += b'\xff'
    packet += b'\x00' * 8 # padding 
 
    return packet

def getMyIP():
    s = socket(AF_INET, SOCK_DGRAM)
    s.connect(('8.8.8.8', 0))  # connecting to a UDP address doesn't send packets
    local_ip_address = s.getsockname()[0]
    splitted = local_ip_address.split('.')
    ip_hexadecimal = ""
    for byte in splitted:
        hexadecimal = str(hex(int(byte)))
        if len(hexadecimal) < 4:
            hexadecimal = "x0".join(hexadecimal.rsplit("x", 1))
        ip_hexadecimal += "\\" + hexadecimal[1:]
    return ip_hexadecimal #e.g \xc0\xa8\x0f\x05 = 192.168.15.5


#def getMyMAC():
    # e.g \xff\xff\xff\xff\xff\xff = ff:ff:ff:ff:ff:ff
    #mac_num = hex(uuid.getnode())
    #mac = '\\x'.join(mac_num[i : i + 2] for i in range(2, 13, 2))
    #mac = b'\\x'+mac
#    return hex(uuid.getnode())


def checksum(msg):
    s = 0
     
    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
        s = s + w
     
    s = (s>>16) + (s & 0xffff);
    s = s + (s >> 16);
     
    #complement and mask to 4 byte short
    s = ~s & 0xffff
     
    return s

