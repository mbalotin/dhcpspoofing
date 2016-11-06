#!/usr/bin/python3 -tt
from struct import unpack
from binascii import hexlify, unhexlify
from collections import defaultdict
from socket import socket, inet_ntoa, AF_INET, SOCK_DGRAM
import uuid

IP_PROTOCOL = 0x11
UDP_PROTOCOL = b'0043'

class Packet:
    def __init__(self, buff):
        self.destination_mac, self.origin_mac, self.packet_type = unpack('!6s6sH', buff[0:14])
        self.ip = None
        if (buff[23] == IP_PROTOCOL):
            self.ip = IpPacket(buff)

class IpPacket:
    def __init__(self, buff):
        ip_header = unpack('!BBHHHBBH4s4s', buff[14:34])
        version_length = ip_header[0]
        self.version = version_length >> 4
        self.length = (version_length & 0xF) * 4
        self.ttl = ip_header[5]
        self.protocol = ip_header[6]
        self.source = inet_ntoa(ip_header[8]);
        self.destination = inet_ntoa(ip_header[9]);
        self.udp = None
        if (hexlify(buff[36:38]) == UDP_PROTOCOL):
            self.udp = UdpPacket(buff, 14 + self.length)

class UdpPacket:
    def __init__(self, buff, start):
        self.source, self.destination, self.length, self.checksum = unpack('!HHH2s', buff[start:start + 8])
        self.dhcp = None
        if self.destination == 67:
            self.dhcp = DhcpPacket(buff, start + 8)

class DhcpPacket:
    def __init__(self, buff, start):
        dhcp_header = unpack('!BBBB4sHH4s4s4s4s6s',buff[start:start + 34])
        self.type = dhcp_header[0]
        self.hrd_type = dhcp_header[1]
        self.hdr_addr_length = dhcp_header[2]
        self.hops = dhcp_header[3]
        self.transaction_id = dhcp_header[4]
        self.seconds_elapsed = dhcp_header[5]
        self.client_ip = inet_ntoa(dhcp_header[7])
        self.your_ip_address = inet_ntoa(dhcp_header[8])
        self.next_server_ip = inet_ntoa(dhcp_header[9])
        self.relay_agent_ip = inet_ntoa(dhcp_header[10])
        self.client_mac = dhcp_header[11]
        self.dhcpOptions = DhcpOtions(buff, start + 34)


class DhcpOtions:
    def __init__(self, buff, start):
        dhc_options_header = unpack('!206sBBB', buff[start: 285]) #206 useless bytes *202 of them are 0s* and 4 for Magic cookie
        self.option = dhc_options_header[1]
        self.length = dhc_options_header[2]
        self.dhcpType = dhc_options_header[3]

class DhcpOffer:
    def __init__(self, transaction_id, client_MAC, clientIP):
        #### Ethernet Header ##########
        ethernet = b'\xff\xff\xff\xff\xff\xff'
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

        ip_header[10:12] = checksum_IP(ip_header)

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
        bootp += b'\x00\x00\x00\x00' #your_ip_address
        bootp += b'\x0a\x2a\x00\x01' #next_server_ip
        bootp += b'\x00\x00\x00\x00' #client_hwaddr_padding
        bootp += client_MAC
        bootp += b'\x00' * 10 #client_hwaddr_padding
        bootp += b'\x00' * 64 #contains server hostname which is not given
        bootp += b'\x00' * 128 #bootfile name
        bootp += b'\x63\x82\x53\x63'
        bootp += b'\x35' #option 53 
        bootp += b'\x01'
        bootp += b'\x02' #offer 
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
        bootp += b'\x0a\x2a\x00\xff' #broadcast addr
        bootp += b'\x06'
        bootp += b'\x04'
        bootp += b'\x0a\x2a\x00\x01' #dns
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

def checksum_IP(msg):
    print(type(msg))
    s = 0
     
    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
        s = s + w
     
    s = (s>>16) + (s & 0xffff);
    s = s + (s >> 16);
     
    #complement and mask to 4 byte short
    s = ~s & 0xffff
     
    s = format(s,'#04x')


def parse(buff):
    return Packet(buff)
