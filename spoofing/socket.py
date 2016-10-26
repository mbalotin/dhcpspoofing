#!/usr/bin/python3 -tt
import argparse

def spoof_init():
    parser = argparse.ArgumentParser(prog='dhcpspoof', description='DHCP spoofing attack application')

    parser.add_argument('-v', '--verbose', action='store_true', help='Runs in verbose mode')
    parser.add_argument('sourceMachine', help='Attacked machine')

    options = parser.parse_args()

    if options.verbose:
        print('spoof started with verbose mode')
    else:
        print('spoof started')
