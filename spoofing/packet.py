#!/usr/bin/python3 -tt
from struct import unpack
from binascii import hexlify
from collections import defaultdict
from socket import inet_ntoa

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
        dhcp_header = unpack('!BBBBIHH4s4s4s4s6s',buff[start:start + 34])
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

def parse(buff):
    return Packet(buff)
