# Proxy service to log real hasp transactions between the client and aksusbd.
# Note: Must either hook connect() or hardcode change the port to this tcp port.
# Note2: Designed to run on localhost.
# Note3: TODOs... one fun thing might be to modify the login port and spoof username,machine name, etc.

import HaspCore.HaspConst as HaspConst
import socket,struct,binascii
import string

DEBUG_PRINT = True
AKSUSBD_HOST = "127.0.0.1"
AKS_USBD_PORT = 1947
PROXY_PORT = 1945

def connect_to_aksusbd():
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.connect((AKSUSBD_HOST,AKS_USBD_PORT))
    return sock

def read_packet(cc):
    header = cc.recv(HaspConst.HEADER_SZ)
    packet_size = struct.unpack("<I", header[0:4])[0]
    body = cc.recv(packet_size - HaspConst.HEADER_SZ)

    return header+body

def write_packet(cc,data):
    cc.send(data)

def is_printable(indata):
    return all(c in string.printable for c in indata)

if(__name__=="__main__"):
    # Set up the Proxy Endpoint
    connection = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    connection.bind(('0.0.0.0',PROXY_PORT))
    connection.listen(10)

    aksusbd_conn = connect_to_aksusbd()
    if(aksusbd_conn == None):
        print("Connection to AKSUSBD Failed, Check Service...")
        exit(1)
    print("Waiting for Clients...")
    while True:
        ccon,addr = connection.accept()
        preq = read_packet(ccon)
        if (DEBUG_PRINT == True):
            if(is_printable(preq)):
                print("Request: %s" % preq)
            else:
                print("Request: %s" % binascii.hexlify(preq))

        # Send to AKSUSBD
        write_packet(aksusbd_conn,preq)
        # Get Response from AKSUSBD
        pres = read_packet(aksusbd_conn)
        if(DEBUG_PRINT == True):
            if(is_printable(pres)):
                print("Response: %s" % pres)
            else:
                print("Response: %s" % binascii.hexlify(pres))
        write_packet(ccon,pres)
        ccon.close()
