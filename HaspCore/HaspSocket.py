import socket, binascii, struct
import HaspConst


class HaspSocket(object):

    def read(self):
        header = self.sock.recv(HaspConst.HEADER_SZ)

        packet_size = struct.unpack("<I", header[0:4])[0]
        body = self.sock.recv(packet_size - HaspConst.HEADER_SZ)
        data = header + body
        print("Received %d Bytes: %s" % (len(data), binascii.hexlify(data)))
        return data

    def write(self, data):
        print("Sent %d Bytes: %s" % (len(data), binascii.hexlify(data)))
        return self.sock.sendall(data)


class HaspSocketClient(object):
    def __init__(self,is_debug=False):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(('127.0.0.1', 1947))
        self.is_debug = is_debug

    def read(self):
        header = self.sock.recv(HaspConst.HEADER_SZ)
        packet_size = struct.unpack("<I", header[0:4])[0]
        body = self.sock.recv(packet_size - HaspConst.HEADER_SZ)
        data = header + body
        if(self.is_debug == True):
            print("Received %d Bytes: %s" % (len(data), binascii.hexlify(data)))
        return data

    def write(self, data):
        if(self.is_debug == True):
            print("Sent %d Bytes: %s" % (len(data), binascii.hexlify(data)))
        return self.sock.sendall(data)


class HaspSocketServer(HaspSocket):
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(('0.0.0.0', 1947))
        self.sock.listen(1)

    def process_loop(self):
        conn, addr = self.sock.accept()
        print ('Connection address:', addr)


"""
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((TCP_IP, TCP_PORT))
s.listen(1)


while 1:
    data = conn.recv(BUFFER_SIZE)
    if not data: break
    print "received data:", data
    conn.send(data)  # echo
conn.close()
"""