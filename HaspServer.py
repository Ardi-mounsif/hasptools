# Hasp Server -- Effectively, an AKSUSBD Replacement Daemon
import socket,struct,binascii
import HaspCore.AKSHandler as AKSHandler
import HaspCore.HaspConst as HaspConst

DEBUG_PRINT = True
AKS_HOST = "0.0.0.0"
AKS_PORT = 1945

def read_packet(cc):
    header = ""
    while(len(header) < HaspConst.HEADER_SZ):
        header = cc.recv(HaspConst.HEADER_SZ)
    packet_size = struct.unpack("<I", header[0:4])[0]
    body = cc.recv(packet_size - HaspConst.HEADER_SZ)

    return header+body

def write_packet(cc,data):
    packet_size = struct.unpack("<I",data[0:4])[0]
    cc.send(data[0:24])
    cc.send(data[24:])

class HaspServer(object):
    def __init__(self,aks_handler):
        self.aks = aks_handler
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection.bind((AKS_HOST, AKS_PORT))
        self.connection.listen(10)

    def start(self):
        print("HaspServer Started...")
        ccon, addr = self.connection.accept()
        while True:

            preq = read_packet(ccon)
            if (DEBUG_PRINT == True):
                print("Request: %s" % binascii.hexlify(preq))

            # Process Packet
            if("cdata.txt" in preq):
                write_packet(ccon,tr)
                continue
            pres = self.aks.process_request(preq)
            if (DEBUG_PRINT == True):
                print("Response: %s" % binascii.hexlify(pres))

            write_packet(ccon, pres)
        ccon.close()


if(__name__=="__main__"):
    hs = HaspServer(AKSHandler.AKSHandler("Dongles","APIs"))
    hs.start()

