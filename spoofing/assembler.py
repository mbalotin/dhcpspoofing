#!/usr/bin/python3 -tt

import uuid
import socket, struct
from binascii import unhexlify
from socket import socket, inet_ntoa, AF_INET, SOCK_DGRAM



OFFER = 1 
ACK = 2 

class DhcpPacket:
    def __init__(self, option, transaction_id, client_MAC, requested_IP):
        #### Ethernet Header ##########
        ethernet = client_MAC
        ethernet += my_MAC()
        ethernet += b'\x08\x00'
        ### IP Header ################ ip_header
        ip_header = b'\x45' #version length
        ip_header += b'\x10' #tos
        ip_header += b'\x01\x48' #total length
        ip_header += b'\x00\x00' #identification
        ip_header += b'\x00' #flags
        ip_header += b'\x00' #frag offset
        ip_header += b'\x80' #ttl 
        ip_header += b'\x11' #protool (udp)
        ip_header += b'\x00\x00' #checksum
        ip_header += my_IP() #source
        ip_header += b'\xff\xff\xff\xff' #destination
        ip_header = ip_header[:10] + struct.pack('i',_checksum(ip_header))[:2] + ip_header[12:]

        ### UDP Header ############### udp_header
        udp_header = b'\x00\x43' #source port 
        udp_header += b'\x00\x44' #dest port
        udp_header += b'\x01\x34' #length
        udp_header += b'\x00\x00' #udp checksum
        ### Bootstrap Header ######## bootp
        bootp = b'\x02' #msg type
        bootp += b'\x01' #hw type
        bootp += b'\x06' #hw addr len
        bootp += b'\x00' #hops
        bootp += transaction_id
        bootp += b'\x00\x00' #seconds_elapsed
        bootp += b'\x00\x00' #bootp_flags
        bootp += b'\x00\x00\x00\x00' #client_ip
        bootp += requested_IP #your_ip_address
        bootp += b'\x00\x00\x00\x00' #next_server_ip
                                     #The Next Server IP address Option specifies a list of IP
                                     #addresses for secondary servers
        bootp += b'\x00\x00\x00\x00' #client_hwaddr_padding
        bootp += client_MAC
        bootp += b'\x00' * 10 #client_hwaddr_padding
        bootp += b'\x00' * 64 #contains server hostname which is not given
        bootp += b'\x00' * 128 #bootfile name
        bootp += b'\x63\x82\x53\x63'
        bootp += b'\x35' #option 53 
        bootp += b'\x01'
        if option == OFFER:
            bootp += b'\x02'
        elif option == ACK:
            bootp += b'\x05' #ACK 
        bootp += b'\x36' #option 54
        bootp += b'\x04'
        bootp += my_IP()
        bootp += b'\x33' #option 51
        bootp += b'\x04'
        bootp += b'\xff\xff\xff\xff' #4294962957 segundos
        bootp += b'\x3a' #option 58 
        bootp += b'\x04'
        bootp += b'\x00\x00\x0e\x10' #3600segundos
        bootp += b'\x3b' #option 59
        bootp += b'\x04'
        bootp += b'\x00\x00\x0e\x10' #3600 segundos
        bootp += b'\x01' #option 1 
        bootp += b'\x04'
        bootp += b'\xff\xff\xff\x00'
        bootp += b'\x1c' #option 28 
        bootp += b'\x04'
        bootp += b'\xc0\xa8\x0f\xff' #broadcast addr
        bootp += b'\x06'
        bootp += b'\x04'
        bootp += b'\x08\x08\x08\x08' #dns
        bootp += b'\x03' #option 3 
        bootp += b'\x04'
        bootp += my_IP() #router
        bootp += b'\xff'
        bootp += b'\x00' * 8 #padding
        self.packet = ethernet + ip_header + udp_header + bootp

def my_IP():
    s = socket(AF_INET, SOCK_DGRAM)
    s.connect(('8.8.8.8', 0))  # connecting to a UDP address doesn't send packets
    local_ip_address = s.getsockname()[0]
    splitted = local_ip_address.split('.')
    ip_hexadecimal = ""
    for byte in splitted:
        hexadecimal = str(hex(int(byte)))
        if len(hexadecimal) < 4:
            hexadecimal = "x0".join(hexadecimal.rsplit("x", 1))
        ip_hexadecimal += hexadecimal[2:]
    return unhexlify(ip_hexadecimal) #e.g b'\xc0\xa8\x0f\x05' = 192.168.15.5


def my_MAC():
    # e.g \xff\xff\xff\xff\xff\xff = ff:ff:ff:ff:ff:ff
    mac_num = str(hex(uuid.getnode()))
    mac_num = mac_num[2:]
    #mac_num = '\\x'.join(mac_num[i : i + 2] for i in range(2, 13, 2))
    #mac_num = '\\x'+mac_num
    #print (unhexlify(mac_num))
    return unhexlify(mac_num)


def _checksum(data):
    #calculate the header sum
    ip_header_sum = sum(struct.unpack_from("8H", data))
    #add the carry
    ip_header_sum = (ip_header_sum & 0xFFFF) + (ip_header_sum >> 16 & 0xFFFF)
    #invert the sum, python does not support inversion (~a is -a + 1) so we have to do
    #little trick: ~a is the same as 0xFFFF & ~a
    return ~ip_header_sum & 0xFFFF