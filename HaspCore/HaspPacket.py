import struct
import HaspConst
import HaspObject

"""
Terminology:
    client_id - This is pulled once per process... it's basically a context instance.
    session_id/instance_id - This is per login to denote a specific session, a client gets this after login.
    packet_type - the type of operation in which the payload will be used, blank on response as it's implicit
    transaction_id - 4 byte counter value, starts at 1 and increments with every req/resp - client increments
    
Packet Structural Breakdown:
    A packet to/from the license manager comprises two major components:
        - A packet header
        - Object Payload

Packet Header Structural Breakdown:
    The packet header is a static 24 byte set of values used to process the packet.
    - Total Packet Size (4 bytes): Length of the rest of the packet (yes counting these 4 bytes).
    - DER Object Header (always 34120100): denotes that the packet information follows.
    - Transaction ID: Denotes which transaction number for the given client this belongs to.
    - Client ID: Which client this packet is from (via clientid - aka apiuid).
    - Packet Type: What kind of operation will consume the packet payload.
    - Tail Value: The only unknown, most of the time, it's zero.
"""

class HaspPacket(object):
    def __init__(self):
        self.transaction_id = 0
        self.client_id = 0
        self.packet_type = 0
        self.tail_value = 0
        self.payload_object = None

    def populate(self,transaction_id,client_id,payload_object,packet_type=0,tail_value=0):
        self.transaction_id = transaction_id
        self.client_id = client_id
        self.payload_object = payload_object
        self.packet_type = packet_type
        self.tail_value = tail_value

    def serialize_header(self,payload_len):
        header  = struct.pack("<I",HaspConst.HEADER_SZ+payload_len)
        header += b"\x34"+struct.pack("B",HaspConst.HEADER_SZ-6)+b"\x01\x00"
        header += struct.pack("<I",self.transaction_id)
        header += struct.pack("<I",self.client_id)
        header += struct.pack("<I",self.packet_type)
        header += struct.pack("<I",self.tail_value)
        return header

    def parse(self,data):
        total_size = struct.unpack("<I",data[0:4])[0]
        # Skip the DER Item Declaration
        self.transaction_id = struct.unpack("<I",data[8:12])[0]
        self.client_id = struct.unpack("<I",data[12:16])[0]
        self.packet_type = struct.unpack("<I",data[16:20])[0]
        self.tail_value = struct.unpack("<I",data[20:24])[0]
        self.payload_object = HaspObject.DeriveObject(data[24:])

    def serialize(self):
        payload_data = self.payload_object.serialize()
        return self.serialize_header(len(payload_data)) + payload_data

