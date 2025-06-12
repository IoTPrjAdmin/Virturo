#----------------------------------------------------------------------------
# Copyright (c) 2025 LeoxTec https://leoxtec.com.
# Licensed under the MIT License.
#----------------------------------------------------------------------------
# UDP echo server, receives packet on given IP address and port and response with OK
# Used as server to forward
# 
# Parameters to --serverip [IP address] --port [PORT]
# Example: python3 fwd_udp_server.py --serverip 127.0.0.1 --port 6235
# 
# Tested with python 3.12
#
import datetime
import binascii
import socket
from datetime import datetime
from array import *
import time
import argparse

# IP address of server to forward
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 6235

# ########## MAIN ##########

parser = argparse.ArgumentParser(description="UDP listen server, requires port number")

# Define the 'port' argument with a default value of 8000
parser.add_argument('--serverip', type=str, default=SERVER_HOST, help='IP Address of interface to listen on (default: {SERVER_HOST})')
parser.add_argument('--port', type=int, default=SERVER_PORT, help='Port number to use (default: {SERVER_PORT})')
args = parser.parse_args()

listen_port = args.port
listen_intf = args.serverip
srvr = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
srvr.bind((listen_intf, listen_port))
srvr_run = True
print(f'UDP Server listening on {listen_intf}:{listen_port}')

# server start
try:
    while srvr_run:
        message, address = srvr.recvfrom(1024)
        print("\n" + datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        print("Client IP Address:{}".format(address))
        print("Raw Message")
        hex_str = binascii.hexlify(bytearray(message))
        print(hex_str)
        # forward to data server
        time.sleep(0.5)
        response_bin = bytes("OK",'utf-8')
        print(f'Sending OK to {address}')
        srvr.sendto(response_bin, address);

except KeyboardInterrupt:
    srvr_run = False
    pass

srvr.close()

print("Exiting...")
