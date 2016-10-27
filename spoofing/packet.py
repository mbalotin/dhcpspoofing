#!/usr/bin/python3 -tt
from struct import unpack
from binascii import hexlify
from collections import defaultdict
from socket import inet_ntoa

IP_PROTOCOL = 0x11

def parse(buff):
    pck = defaultdict(int)
    dest, orig, type = unpack('!6s6sH', buff[0:14])
    pck['destination_mac'] = hexlify(dest)
    pck['origin_mac'] = hexlify(orig)
    pck['type'] = type

    if (buff[23] == IP_PROTOCOL):
        pck['ip'] = parse_ip(buff)
    return pck

def parse_ip(buff):
    ip_header = unpack('!BBHHHBBH4s4s', buff[14:34])

    ip = dict()
    version_ihl = ip_header[0]
    ip['version'] = version_ihl >> 4
    ip['ihl'] = version_ihl & 0xF
    ip['ttl'] = ip_header[5]
    ip['protocol'] = ip_header[6]
    ip['source'] = inet_ntoa(ip_header[8]);
    ip['destination'] = inet_ntoa(ip_header[9]);

    print (ip)
    return ip