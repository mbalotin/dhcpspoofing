#!/usr/bin/python3 -tt
from struct import unpack
from binascii import hexlify, unhexlify
from collections import defaultdict
from socket import socket, inet_ntoa, AF_INET, SOCK_DGRAM
import uuid
import struct
from datetime import datetime

IP_PROTOCOL = 0x0800
UDP_PROTOCOL = 0x11
TCP_PROTOCOL = 0x06

class Packet:
    def __init__(self, buff):
        self.destination_mac, self.origin_mac, self.packet_type = unpack('!6s6sH', buff[0:14])
        self.ip = None
        if (hex(self.packet_type) == hex(IP_PROTOCOL)):
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
        if ((hex(self.protocol)) == hex(UDP_PROTOCOL)):
            self.udp = UdpPacket(buff, 14 + self.length)
        self.tcp = None
        if((hex(self.protocol)) == hex(TCP_PROTOCOL)):
            self.tcp = TcpPacket(buff, 14 + self.length)

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
        dhc_options_header = unpack('!206sBBB9sBB4s', buff[start: 300]) #206 useless bytes *202 of them are 0s* and 4 for Magic cookie
        self.option = dhc_options_header[1]
        self.length = dhc_options_header[2]
        self.dhcpType = dhc_options_header[3]
        self.option2 = dhc_options_header[5]
        self.length2 = dhc_options_header[6]
        self.requested_ip = dhc_options_header[7]

class TcpPacket:
    def __init__(self, buff, start):
        tcp_header = unpack('!HH4s4sH', buff[start:start+14])
        self.dest_port = tcp_header[1]
        self.length_flags = tcp_header[4]
        if hex(self.length_flags) == hex(0x8018):
            self.length = 32
        else:
            self.length = 20
        if self.dest_port == 80 and (self.length_flags == 0x8018 or self.length_flags == 0x5018):
            self.http = HttpPacket(buff,start+self.length)
        if self.dest_port == 443 and self.length_flags == 0x8018:
            self.https = HttpsPacket(buff,start+self.length)

class HttpPacket:
    def __init__(self, buff, start):
        self.time = None
        self.URL = None
        buff_index = start
        if 0x47 == buff[buff_index]:
            buff_index += 4
            curr_byte = buff[buff_index]
            URI = (curr_byte).to_bytes(1, byteorder='big')
            buff_index += 1
            curr_byte = buff[buff_index]
            while hex(curr_byte) != hex(0x20):
                URI += (curr_byte).to_bytes(1, byteorder='big')
                buff_index += 1
                curr_byte = buff[buff_index]
            while curr_byte != 0x0a:
                buff_index += 1
                curr_byte = buff[buff_index]
            while curr_byte != 0x20:
                buff_index += 1
                curr_byte = buff[buff_index]
            buff_index += 1
            curr_byte = buff[buff_index]
            host = (curr_byte).to_bytes(1, byteorder='big')
            buff_index += 1
            curr_byte = buff[buff_index]
            while curr_byte != 0x0d:
                host += (curr_byte).to_bytes(1, byteorder='big')
                buff_index += 1
                curr_byte = buff[buff_index]
            self.time = datetime.now()
            self.URL = host + URI


class HttpsPacket:
    def __init__(self, buff, start):
        self.time = None
        self.domain = None
        buff_index = start
        if buff[buff_index] == 0x16:
            buff_index += 5
            if buff[buff_index] == 0x01:
                buff_index += 38
                buff_index += buff[buff_index] + 1
                buff_index += ((buff[buff_index] << 8) + buff[buff_index+1]) + 2
                buff_index += buff[buff_index] + 1
                buff_index += 9
                domain_length = (buff[buff_index] << 8) + buff[buff_index+1]
                buff_index += 2
                self.domain = (buff[buff_index]).to_bytes(1, byteorder='big')
                buff_index += 1
                domain_length -= 1
                while domain_length > 0:
                    self.domain += (buff[buff_index]).to_bytes(1, byteorder='big')
                    buff_index += 1
                    domain_length -= 1

                self.time = datetime.now()


def parse(buff):
    return Packet(buff)
