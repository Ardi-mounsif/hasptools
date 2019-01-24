# AKS Engine
# Consumes Dongle Objects and processes client side requests.
import struct
import HaspDongle
import HaspAPI
import HaspPacket
import HaspObject
import HaspUtils
import HaspConst
import binascii
class AKSHandler(object):
    def __init__(self,dongles_root,apis_root):
        self.dongles = {}
        self.session_id_counter = 1
        self.sc_id_counter = 0x45
        self.dongles = HaspUtils.LoadDongles(dongles_root)
        self.apis = HaspAPI.Load_Server_APIS(apis_root,is_server=True)
        self.client_db = {}


    # Utility Methods
    def find_dongle(self,vendor_id,feature_id):
        if(not vendor_id in self.dongles.keys()):
            return None
        if(not feature_id in self.dongles[vendor_id].features.keys()):
            return None
        return self.dongles[vendor_id]

    def find_dongle_by_serial(self,serial):
        for cs in self.dongles.keys():
            if(self.dongles[cs].serial == serial):
                return self.dongles[cs]
        return None

    def find_dongle_id_by_serial(self,serial):
        for cs in self.dongles.keys():
            if(self.dongles[cs].serial == serial):
                return cs
        return None

    def find_client_entry(self,cid):
        if(not cid in self.client_db.keys()):
            return None
        return self.client_db[cid]

    def find_session_entry(self,cid,sid):
        if(not cid in self.client_db.keys()):
            return None
        ce = self.client_db[cid]
        if(not sid in ce["sessions"].keys()):
            return None

        return ce["sessions"][sid]


    def process_request(self,request_data):
        # Parse the Packet and objects.
        request_packet = HaspPacket.HaspPacket()
        request_packet.parse(request_data)

        if(request_packet.packet_type == HaspConst.OPERATION_ID_GETAPIUID):
            response_object = self.get_client_id_handler(request_packet)
        elif(request_packet.packet_type == HaspConst.OPERATION_ID_LOGIN):
            response_object = self.login_handler(request_packet)
        elif(request_packet.packet_type == HaspConst.OPERATION_ID_LOGINSCOPE):
            response_object = self.login_scope_handler(request_packet)
        elif(request_packet.packet_type == HaspConst.OPERATION_ID_LOGOUT):
            response_object = self.logout_handler(request_packet)
        elif(request_packet.packet_type == HaspConst.OPERATION_ID_SETUPSCHANNEL):
            response_object = self.setup_schannel_handler(request_packet)
        elif(request_packet.packet_type == HaspConst.OPERATION_ID_READ):
            response_object = self.read_handler(request_packet)
        elif(request_packet.packet_type == HaspConst.OPERATION_ID_WRITE):
            response_object = self.write_handler(request_packet)
        elif(request_packet.packet_type == HaspConst.OPERATION_ID_GETSIZE):
            response_object = self.get_size_handler(request_packet)
        elif(request_packet.packet_type == HaspConst.OPERATION_ID_GETRTC):
            response_object = self.get_rtc_handler(request_packet)
        elif(request_packet.packet_type == HaspConst.OPERATION_ID_GETINFO):
            response_object = self.get_info_handler(request_packet)
        elif(request_packet.packet_type == HaspConst.OPERATION_ID_ENCRYPT):
            response_object = self.encrypt_handler(request_packet)
        elif(request_packet.packet_type == HaspConst.OPERATION_ID_DECRYPT):
            response_object = self.decrypt_handler(request_packet)
        else:
            print("Error: Unknown Operation Type: %04X" % request_packet.packet_type)
            return b"\x00" * 24

        response_packet = HaspPacket.HaspPacket()
        response_packet.populate(request_packet.transaction_id,request_packet.client_id,response_object)
        return response_packet.serialize()


    #Operation Handling Methods
    def get_client_id_handler(self,request_packet):
        rp = request_packet.payload_object

        client_id = HaspUtils.make_fake_handle_value()
        client_id_response = HaspObject.HO_Client_ID_Response()
        client_id_response.populate(HaspConst.HASP_STATUS_OK,client_id)

        self.client_db[client_id] = {
            "hasp_serial":0,
            "sessions":{}
        }

        return client_id_response

    def login_handler(self,request_packet):
        rp = request_packet.payload_object

        login_response = HaspObject.HO_Login_Response()
        cd = self.find_dongle(rp.vendor_id, rp.feature_id)
        cid = request_packet.client_id
        client_entry = self.find_client_entry(cid)
        if(client_entry == None or cd == None):
            login_response.populate(HaspConst.HASP_ERR_BROKEN_SESSION,0,0,0)
            return login_response

        sc_id = self.sc_id_counter
        session_id = self.session_id_counter
        self.sc_id_counter+=1
        self.session_id_counter+=1

        self.client_db[request_packet.client_id]["sessions"][session_id] = {
            "sc_id":sc_id,
            "serial":cd.serial,
            "sc_active":False,
            "feature_id":rp.feature_id
        }

        login_response.populate(HaspConst.HASP_STATUS_OK,session_id,cd.serial,sc_id)

        return login_response

    def login_scope_handler(self,request_packet):
        rp = request_packet.payload_object
        login_response = HaspObject.HO_Login_Scope_Response()
        # Find feature ID
        print("Spec: %s" % rp.spec)
        fid_offset_start = rp.spec.find("<feature id=\"")+len("<feature id=\"")
        fid_offset_end = rp.spec[fid_offset_start:].find("\"") + fid_offset_start
        feature_id = int(rp.spec[fid_offset_start:fid_offset_end])

        cd = self.find_dongle(rp.vendor_id, feature_id)
        cid = request_packet.client_id
        client_entry = self.find_client_entry(cid)
        if(client_entry == None or cd == None):
            login_response.populate(HaspConst.HASP_ERR_BROKEN_SESSION,0,0,0)
            return login_response

        sc_id = self.sc_id_counter
        session_id = self.session_id_counter
        self.sc_id_counter+=1
        self.session_id_counter+=1

        self.client_db[request_packet.client_id]["sessions"][session_id] = {
            "sc_id":sc_id,
            "serial":cd.serial,
            "sc_active":False,
            "feature_id":feature_id
        }

        login_response.populate(HaspConst.HASP_STATUS_OK,session_id,cd.serial,sc_id)

        return login_response

    def logout_handler(self,request_packet):
        rp = request_packet.payload_object
        response_obj = HaspObject.HO_Logout_Response()
        cid = request_packet.client_id
        sid = rp.session_id
        client_entry = self.find_client_entry(cid)
        session_entry = self.find_session_entry(cid,sid)
        if(client_entry == None or session_entry == None):
            response_obj.populate(HaspConst.HASP_ERR_BROKEN_SESSION)
            return response_obj

        # Delete the session with the given session id
        self.client_db[request_packet.client_id]["sessions"].pop(request_packet.payload_object.session_id)
        response_obj.populate(HaspConst.HASP_STATUS_OK)

        return response_obj


    def setup_schannel_handler(self,request_packet):
        rp = request_packet.payload_object
        response_object = HaspObject.HO_Setup_Schannel_Response()
        cid = request_packet.client_id
        sid = rp.session_id
        client_entry = self.find_client_entry(cid)
        session_entry = self.find_session_entry(cid,sid)
        if(client_entry == None or session_entry == None):
            print("Schannel Setup Failed: No Client or Session Entry Found")
            response_object.populate(HaspConst.HASP_ERR_BROKEN_SESSION, 0)
            return response_object


        response_object.populate(HaspConst.HASP_STATUS_OK,session_entry['sc_id'])
        self.client_db[cid]["sessions"][sid]["sc_active"] = True

        return response_object


    def read_handler(self,request_packet):
        rp = request_packet.payload_object
        response_object = HaspObject.HO_Read_Response()
        cid = request_packet.client_id
        sid = rp.session_id
        session_entry = self.find_session_entry(cid, sid)
        # Check the session.
        if(session_entry == None):
            response_object.populate(HaspConst.HASP_ERR_BROKEN_SESSION,b"\x00")
            return response_object

        # Check if dongle exists
        dongle_serial = session_entry["serial"]
        cd = self.find_dongle_by_serial(dongle_serial)
        if(cd == None):
            response_object.populate(HaspConst.HASP_DEVICE_ERR,b"\x00")
            return response_object

        # Check if SChannel is Active
        if(session_entry["sc_active"] == False):
            response_object.populate(HaspConst.HASP_SCHAN_ERR,b"\x00")
            return response_object

        status,decoded_data = cd.read_memory(rp.file_id,rp.offset,rp.amount)
        if(status != HaspConst.HASP_STATUS_OK):
            response_object.populate(status, b"\x00")
            return response_object

        # Encode Data
        encoded_data = self.apis[cd.vendor_id].encode_read_data(decoded_data,rp.seedvals)

        # Construct Response
        response_object.populate(HaspConst.HASP_STATUS_OK,encoded_data)
        return response_object

    def write_handler(self,request_packet):
        rp = request_packet.payload_object

        response_object = HaspObject.HO_Write_Response()

        # Ensure we aren't trying to write to the read-only page.
        if(rp.file_id == 65525):
            response_object.populate(HaspConst.HASP_DEVICE_ERR,0,b"\x00")
            return response_object

        cid = request_packet.client_id
        sid = rp.session_id
        session_entry = self.find_session_entry(cid, sid)
        # Check the session.
        if(session_entry == None):
            response_object.populate(HaspConst.HASP_ERR_BROKEN_SESSION,0,b"\x00")
            return response_object

        # Check if dongle exists
        dongle_serial = session_entry["serial"]

        cd = self.find_dongle_by_serial(dongle_serial)
        if(cd == None):
            response_object.populate(HaspConst.HASP_DEVICE_ERR,0,b"\x00")
            return response_object

        dongle_id = self.find_dongle_id_by_serial(dongle_serial)

        # Check if SChannel is Active
        if(session_entry["sc_active"] == False):
            response_object.populate(HaspConst.HASP_SCHAN_ERR,0,b"\x00")
            return response_object

        # Decode Data
        decoded_data = self.apis[cd.vendor_id].decode_write_data(rp.data,rp.seedvals,session_entry["sc_id"])
        status = cd.write_memory(rp.file_id,rp.offset,len(decoded_data))
        if(status != HaspConst.HASP_STATUS_OK):
            response_object.populate(status, 0, rp.seedvals)
            return response_object

        # Construct Response
        response_object.populate(HaspConst.HASP_STATUS_OK,len(decoded_data),rp.seedvals)
        return response_object

    def get_size_handler(self,request_packet):
        rp = request_packet.payload_object
        response_object = HaspObject.HO_Get_Size_Response()

        cid = request_packet.client_id
        sid = rp.session_id
        session_entry = self.find_session_entry(cid, sid)
        # Check the session.
        if(session_entry == None):
            response_object.populate(HaspConst.HASP_ERR_BROKEN_SESSION,0)
            return response_object

        # Check if dongle exists
        dongle_serial = session_entry["serial"]
        cd = self.find_dongle_by_serial(dongle_serial)
        if(cd == None):
            response_object.populate(HaspConst.HASP_DEVICE_ERR,0)
            return response_object

        # Check if memory file id exists
        if(not rp.file_id in cd.memory_info.keys()):
            response_object.populate(HaspConst.HASP_DEVICE_ERR,0)
            return response_object

        response_object.populate(HaspConst.HASP_STATUS_OK,cd.memory_info[rp.file_id]["size"])
        return response_object

    def get_rtc_handler(self,request_packet):
        rp = request_packet.payload_object
        response_object = HaspObject.HO_Get_RTC_Response()

        cid = request_packet.client_id
        sid = rp.session_id
        session_entry = self.find_session_entry(cid, sid)
        # Check the session.
        if(session_entry == None):
            response_object.populate(HaspConst.HASP_ERR_BROKEN_SESSION,0)
            return response_object

        # Check if dongle exists
        dongle_serial = session_entry["serial"]
        cd = self.find_dongle_by_serial(dongle_serial)
        if(cd == None):
            response_object.populate(HaspConst.HASP_DEVICE_ERR,0)
            return response_object

        # Check if dongle supports RTC
        if(cd.has_rtc == 0):
            response_object.populate(HaspConst.HASP_NO_TIME,0)
            return response_object

        response_object.populate(HaspConst.HASP_STATUS_OK,HaspUtils.GetTimestamp())
        return response_object

    # TODO: Make this not a bullshit handler.
    def get_info_handler(self,request_packet):
        rp = request_packet.payload_object
        cd = self.dongles[rp.vendor_id]
        if("si_feature" in rp.format):
            # TODO: Fix This to point to the right fid you're logged in with.
            fid = rp.feature_id # I believe in this case, it's the feature id.
            info = "<hasp_info><feature><featureid>%d</featureid><maxlogins>unlimited</maxlogins><concurrency><export>local</export><count>station</count></concurrency><vmenabled>true</vmenabled><currentlogins>1</currentlogins><license><license>perpetual</license></license></feature></hasp_info>" % fid
        elif("si_container" == HaspConst.FORMAT_GETKEYINFO):
            info = cd.get_key_info()
        else:
            info = cd.get_hasp_info()
        response_object = HaspObject.HO_Get_Info_Response()
        response_object.populate(HaspConst.HASP_STATUS_OK,info)
        return response_object

    def encrypt_handler(self,request_packet):
        rp = request_packet.payload_object
        response_object = HaspObject.HO_Crypt_Response()

        cid = request_packet.client_id
        sid = rp.session_id
        session_entry = self.find_session_entry(cid, sid)
        # Check the session.
        if(session_entry == None):
            response_object.populate(HaspConst.HASP_ERR_BROKEN_SESSION,b"\x00")
            return response_object

        # Check if dongle exists
        dongle_serial = session_entry["serial"]
        cd = self.find_dongle_by_serial(dongle_serial)
        if(cd == None):
            response_object.populate(HaspConst.HASP_DEVICE_ERR,b"\x00")
            return response_object

        # Check if SChannel is Active
        if(session_entry["sc_active"] == False):
            response_object.populate(HaspConst.HASP_SCHAN_ERR,b"\x00")
            return response_object

        # Decode the request data
        decoded_request_data = self.apis[cd.vendor_id].decode_crypt_data(rp.data,rp.seedvals)

        # Check the Keytable
        decoded_response_data = cd.crypt_lookup(session_entry['feature_id'],decoded_request_data)
        if(decoded_response_data == None):
            response_object.populate(HaspConst.HASP_DEVICE_ERR,b"\x00")
            return response_object

        # Encode the response data
        encoded_response_data = self.apis[cd.vendor_id].encode_crypt_data(decoded_response_data,rp.seedvals)
        response_object.populate(HaspConst.HASP_STATUS_OK,encoded_response_data)

        return response_object

    def decrypt_handler(self,request_packet):
        rp = request_packet.payload_object
        response_object = HaspObject.HO_Crypt_Response()

        cid = request_packet.client_id
        sid = rp.session_id
        session_entry = self.find_session_entry(cid, sid)
        # Check the session.
        if(session_entry == None):
            response_object.populate(HaspConst.HASP_ERR_BROKEN_SESSION,b"\x00")
            return response_object

        # Check if dongle exists
        dongle_serial = session_entry["serial"]
        cd = self.find_dongle_by_serial(dongle_serial)
        if(cd == None):
            response_object.populate(HaspConst.HASP_DEVICE_ERR,b"\x00")
            return response_object

        # Check if SChannel is Active
        if(session_entry["sc_active"] == False):
            response_object.populate(HaspConst.HASP_SCHAN_ERR,b"\x00")
            return response_object

        # Decode the request data
        decoded_request_data = self.apis[cd.vendor_id].decode_crypt_data(rp.data,rp.seedvals)

        # Check the Keytable
        decoded_response_data = cd.crypt_lookup(session_entry['feature_id'], decoded_request_data)
        if(decoded_response_data == None):
            response_object.populate(HaspConst.HASP_DEVICE_ERR,b"\x00")
            return response_object

        # Encode the response data
        encoded_response_data = self.apis[cd.vendor_id].encode_crypt_data(decoded_response_data, rp.seedvals)
        response_object.populate(HaspConst.HASP_STATUS_OK,encoded_response_data)
        return response_object