# Object representing Hasp API Connection Metadata and transactional items.
import os,json,binascii,base64,struct
import HaspVendor
import HaspUtils
import HaspConst

# Client Specific Dependencies
import HaspPacket
import HaspObject


def Load_Server_APIS(api_root,is_server=True):
    api_db = {}
    for root,dirs,files in os.walk(api_root):
        for f in files:
            mpath = os.path.join(root,f)
            if(not mpath.endswith(".json")):
                continue

            ao = HaspAPIServer(mpath)


            if(ao.is_valid == True):
                api_db[ao.id] = ao
                print("Loaded API: ")
                print(ao)
                print(" ")
            else:
                print("API: [%s] is invalid" % mpath)
                continue
    return api_db


class APIBase(object):
    def __init__(self,api_meta_path):
        self.name = ""
        self.meta_path = api_meta_path
        self.id = 0
        self.client_id = 0 # Also called API UID.
        self.hmk = b""
        self.hrsapub = b""
        self.version_major = 0
        self.version_minor = 0
        self.build_number = 0
        self.license = None
        self.license_blob = b""
        self.license_key = b""
        self.is_valid = False
        self.parse()

    def __str__(self):
        rstr = ""
        rstr +="API: %s\n" % self.name
        rstr +="Vendor ID: %d\n" % self.id
        rstr +="API Master Key: %s\n" % binascii.hexlify(self.hmk)
        rstr +="Version %d.%d.%d\n" % (self.version_major,self.version_minor,self.build_number)
        return rstr

    def parse(self):
        jdb = {}
        with open(self.meta_path,"rb") as f:
            jdb = json.load(f)
        self.name = jdb["name"]
        self.license_blob = jdb["hvc"]
        self.license_key = binascii.unhexlify(jdb["hvc_aes_key"])
        self.hrsapub = base64.b64decode(jdb["hvc_pub_key"])
        self.hmk = binascii.unhexlify(jdb["hmk"])
        self.version_major = jdb["version_major"]
        self.version_minor = jdb["version_minor"]
        self.build_number  = jdb["build_number"]
        self.license = HaspVendor.HaspVendor(self.license_blob,self.license_key)
        if(self.license.is_valid == False):
            return
        self.id = self.license.vendor_id
        self.is_valid = True


    def derive_session_key(self,seedvals,is_writekey=False,sc_id=None):
        indata = seedvals[0:4]
        if(is_writekey==True):
            indata = seedvals[0:4] + b"\x00\x00"+struct.pack("B",sc_id)
        indata = HaspUtils.pad_data(indata)
        return HaspUtils.aes_ecb_encrypt(indata, self.hmk)

    def encode_read_data(self,read_data,seedvals):
        session_key = self.derive_session_key(seedvals)
        iv = HaspUtils.pad_data(seedvals[4:8])
        return HaspUtils.aes_cbc_encrypt(read_data,session_key,iv)

    def decode_read_data(self,read_data,seedvals):
        session_key = self.derive_session_key(seedvals)
        iv = HaspUtils.pad_data(seedvals[4:8])
        return HaspUtils.aes_cbc_decrypt(read_data,session_key,iv)

    def encode_write_data(self,write_data,seedvals,sc_id):
        session_key = self.derive_session_key(seedvals,is_writekey=True,sc_id=sc_id)
        return HaspUtils.aes_cbc_encrypt(write_data,session_key,seedvals[4:8])

    def decode_write_data(self,write_data,seedvals,sc_id):
        session_key = self.derive_session_key(seedvals,is_writekey=True,sc_id=sc_id)
        return HaspUtils.aes_cbc_decrypt(write_data,session_key,seedvals[4:8])

    def encode_crypt_data(self,in_data,seedvals):
        session_key = self.derive_session_key(seedvals)
        return HaspUtils.aes_cbc_encrypt(in_data,session_key,seedvals[4:8])

    def decode_crypt_data(self,in_data,seedvals):
        session_key = self.derive_session_key(seedvals)
        return HaspUtils.aes_cbc_decrypt(in_data,session_key,seedvals[4:8])


    def decode_crypt_data_type0(self,in_data,seedvals,encoded_request_data):
        session_key = self.derive_session_key(seedvals)
        return HaspUtils.aes_cbc_decrypt(in_data,session_key,encoded_request_data[-16:])

    def decode_crypt_data_type3(self,in_data,seedvals):
        session_key = self.derive_session_key(seedvals)
        return HaspUtils.aes_cbc_decrypt(in_data,session_key)

    def encode_crypt_data_type3(self,in_data,seedvals):
        session_key = self.derive_session_key(seedvals)
        return HaspUtils.aes_cbc_encrypt(in_data,session_key)

    def encrypt_operation_prologue(self,in_data):
        orig_len = len(in_data)
        if(orig_len < 16 or orig_len > 1024):
            print("Enc: Error - Data must be between 16 and 1024 bytes.")
            return HaspConst.HASP_TOO_SHORT,b"",0,0

        crypt_len = 0
        crypt_type = 0
        if(orig_len > 32):
            crypt_type = 3
            crypt_len = 0x10
            head_hash = HaspUtils.ripemd160(in_data[16:])
            xor_header = HaspUtils.xor_data(in_data[:16], head_hash)
            return HaspConst.HASP_STATUS_OK,xor_header,crypt_len,crypt_type
        else:
            crypt_type = 0
            crypt_len = orig_len
            # If the input is > 16 bytes, we have to pad out to another 16 bytes.
            if(orig_len > 16):
                in_data = HaspUtils.pad_data(in_data,plen=32)
            return HaspConst.HASP_STATUS_OK,in_data,crypt_len,crypt_type

    def decrypt_operation_prologue(self,in_data):
        orig_len = len(in_data)
        if(orig_len < 16 or orig_len > 1024):
            print("Enc: Error - Data must be between 16 and 1024 bytes.")
            return HaspConst.HASP_TOO_SHORT,b"",0,0

        crypt_len = 0
        crypt_type = 0
        if(orig_len > 32):
            crypt_type = 3
            crypt_len = 0x10
            return HaspConst.HASP_STATUS_OK,in_data[:16],crypt_len,crypt_type
        else:
            crypt_type = 0
            crypt_len = orig_len
            # If the input is > 16 bytes, we have to pad out to another 16 bytes.
            if(orig_len > 16):
                in_data = HaspUtils.pad_data(in_data,plen=32)
            return HaspConst.HASP_STATUS_OK,in_data,crypt_len,crypt_type

    def encrypt_operation_epilogue(self,in_data,crypt_type,decoded_response_data,encoded_request_data):
        if(crypt_type == 0):
            return decoded_response_data
        elif(crypt_type == 3):
            enc_header = decoded_response_data[16:32]
            body_key = bytearray(decoded_response_data[:16])
            body_key = HaspUtils.xor_data(body_key,encoded_request_data)
            body_len = len(in_data[16:])
            body_enc = HaspUtils.aes_cbc_encrypt(in_data[16:], str(body_key))[:body_len]

            final_enc_data = enc_header + body_enc

            return final_enc_data
        else:
            print("Error - Unknown Crypt Operation Type")
            return b""

    def decrypt_operation_epilogue(self,in_data,crypt_type,decoded_response_data,encoded_request_data):
        if(crypt_type == 0):
            return decoded_response_data[:len(in_data)]
        elif(crypt_type == 3):
            body_len = len(in_data) - 16
            enc_header = bytearray(decoded_response_data[16:32])
            body_key = bytearray(decoded_response_data[:16])
            body_key = HaspUtils.xor_data(body_key,encoded_request_data)
            body_dec = HaspUtils.aes_cbc_decrypt(in_data[16:],str(body_key))[:body_len]
            body_hash = HaspUtils.ripemd160(body_dec[:body_len])
            dec_header = HaspUtils.xor_data(enc_header,body_hash)
            final_dec_data = dec_header + body_dec
            return final_dec_data
        else:
            print("Error - Unknown Crypt Operation Type")
            return b""

# Client API
class HaspAPIClient(APIBase):
    def __init__(self, api_meta_path,sock):
        super(HaspAPIClient, self).__init__(api_meta_path)
        self.client_id = 0
        self.sock = sock
        self.sessions = {}
        self.transaction_num = 1

    #TODO: Actually generate it like the library does.
    def get_seedvals(self):
        #return binascii.unhexlify("FBB98A8500004600")
        return binascii.unhexlify("F45998890000AE00")

    def get_session(self,session_handle):
        if(not session_handle in self.sessions.keys()):
            return None
        return self.sessions[session_handle]

    def send_recv(self,request_payload,packet_type):
        request_packet = HaspPacket.HaspPacket()
        request_packet.populate(self.transaction_num,self.client_id,request_payload,packet_type)
        self.sock.write(request_packet.serialize())
        self.transaction_num+=1
        response_packet = HaspPacket.HaspPacket()
        response_packet.parse(self.sock.read())
        return response_packet

    def get_client_id(self):
        request_object = HaspObject.HO_Client_ID_Request()
        request_object.populate(self.version_major,self.version_minor)

        response_packet = self.send_recv(request_object,HaspConst.OPERATION_ID_GETAPIUID)
        rp = response_packet.payload_object

        if (rp.status == 0):
            self.client_id = rp.client_id
        return rp.status

    def get_size(self,session_handle,file_id):
        sess = self.get_session(session_handle)
        if(sess == None):
            return HaspConst.HASP_ERR_BROKEN_SESSION,0

        ro = HaspObject.HO_Get_Size_Request()
        ro.populate(sess['session_id'],file_id)
        response_packet = self.send_recv(ro,HaspConst.OPERATION_ID_GETSIZE)
        rp = response_packet.payload_object
        if(rp.status != 0):
            return rp.status,0
        return rp.status, rp.file_size

    def get_info(self,scope,format):
        ro = HaspObject.HO_Get_Info_Request()
        ro.populate(self.id,self.version_major,self.version_minor,self.build_number,scope,format)
        response_packet = self.send_recv(ro,HaspConst.OPERATION_ID_GETINFO)
        rp = response_packet.payload_object
        if(rp.status != 0):
            return rp.status,""
        return rp.status,rp.info

    def get_session_info(self,session_handle,scope,format):
        sess = self.get_session(session_handle)
        if(sess == None):
            return HaspConst.HASP_ERR_BROKEN_SESSION,0

        ro = HaspObject.HO_Get_Info_Request()
        ro.populate(self.id, self.version_major, self.version_minor, self.build_number, scope, format,sess['feature_id'])
        response_packet = self.send_recv(ro, HaspConst.OPERATION_ID_GETINFO)
        rp = response_packet.payload_object
        if (rp.status != 0):
            return rp.status, ""
        return rp.status, rp.info

    def get_rtc(self,session_handle):
        sess = self.get_session(session_handle)
        if(sess == None):
            return HaspConst.HASP_ERR_BROKEN_SESSION,0

        ro = HaspObject.HO_Get_RTC_Request()
        ro.populate(sess['session_id'])
        response_packet = self.send_recv(ro,HaspConst.OPERATION_ID_GETRTC)
        rp = response_packet.payload_object
        if(rp.status != 0):
            return rp.status,0
        return rp.status, rp.rtc_timestamp

    def login(self,feature_id):
        # First order of business, get the client id (aka APIUID) from LMS
        # We need this to do pretty much anything...
        if(self.client_id == 0):
            status = self.get_client_id()
            if (status != 0):
                print("GetAPIUID Error: %04X" % status)
                return status
        session_handle = HaspUtils.make_fake_handle_value()
        request_object = HaspObject.HO_Login_Request()
        request_object.populate(self.id,feature_id,session_handle,self.version_major,self.version_minor)

        response_packet = self.send_recv(request_object,HaspConst.OPERATION_ID_LOGIN)
        rp = response_packet.payload_object

        if (rp.status != 0):
            return rp.status

        self.sessions[session_handle] = {
            'session_id':rp.session_id,
            'feature_id':feature_id,
            'serial':rp.hasp_serial,
            'sc_id':rp.sc_id,
            'schannel_active':False
        }

        return HaspConst.HASP_STATUS_OK,session_handle

    def login_scope(self,feature_id,scope):
        # First order of business, get the client id (aka APIUID) from LMS
        # We need this to do pretty much anything...
        if(self.client_id == 0):
            status = self.get_client_id()
            if (status != 0):
                print("GetAPIUID Error: %04X" % status)
                return status
        session_handle = HaspUtils.make_fake_handle_value()
        request_object = HaspObject.HO_Login_Scope_Request()
        spec = HaspConst.SPEC_FEATURE_ID % feature_id
        request_object.populate(self.id,session_handle,spec,scope,self.version_major,self.version_minor)

        response_packet = self.send_recv(request_object,HaspConst.OPERATION_ID_LOGINSCOPE)
        rp = response_packet.payload_object

        if (rp.status != 0):
            return rp.status

        self.sessions[session_handle] = {
            'session_id':rp.session_id,
            'feature_id':feature_id,
            'serial':rp.hasp_serial,
            'sc_id':rp.sc_id,
            'schannel_active':False
        }

        return HaspConst.HASP_STATUS_OK,session_handle

    def logout(self,session_handle):
        sess = self.get_session(session_handle)
        if(sess == None):
            return HaspConst.HASP_ERR_BROKEN_SESSION

        request_object = HaspObject.HO_Logout_Request()
        request_object.populate(sess['session_id'])
        response_packet = self.send_recv(request_object,HaspConst.OPERATION_ID_LOGOUT)
        rp = response_packet.payload_object
        if(rp.status != 0):
            return rp.status
        self.sessions.pop(session_handle)
        return rp.status

    def setup_schannel(self,session_handle):
        sess = self.get_session(session_handle)
        if (sess == None):
            return HaspConst.HASP_ERR_BROKEN_SESSION

        request_object = HaspObject.HO_Setup_Schannel_Request()
        request_object.populate(sess["session_id"])
        response_packet = self.send_recv(request_object,HaspConst.OPERATION_ID_SETUPSCHANNEL)
        rp = response_packet.payload_object
        if(rp.status != 0):
            return rp.status

        self.sessions[session_handle]['schannel_active'] = True
        return rp.status


    def read(self,session_handle,file_id,offset,amt):
        sess = self.get_session(session_handle)
        if (sess == None):
            return HaspConst.HASP_ERR_BROKEN_SESSION,b""
        if(sess['schannel_active'] == False):
            status = self.setup_schannel(session_handle)
            if (status != 0):
                print("Error Setting up Secure Channel: %04X\n", status)
                return status, b""

        request_object = HaspObject.HO_Read_Request()
        seedvals = self.get_seedvals()
        # We can't read non multiples of 16... doesn't like it.
        # Instead, we have to do a bullshit dance of reading it padded.
        r_16 = amt % 16
        f_amt = amt
        if(r_16 != 0):
            f_amt +=r_16
        request_object.populate(sess['session_id'],file_id,offset,f_amt,seedvals)
        response_packet = self.send_recv(request_object,HaspConst.OPERATION_ID_READ)
        rp = response_packet.payload_object

        if (rp.status != HaspConst.HASP_STATUS_OK):
            return rp.status, b""
        decoded_data = self.decode_read_data(rp.data,seedvals)
        return HaspConst.HASP_STATUS_OK, decoded_data[:amt]

    def write(self,session_handle,file_id,offset,data):
        sess = self.get_session(session_handle)
        if (sess == None):
            return HaspConst.HASP_ERR_BROKEN_SESSION, b""
        if (sess['schannel_active'] == False):
            status = self.setup_schannel(session_handle)
            if (status != 0):
                print("Error Setting up Secure Channel: %04X\n", status)
                return status, b""

        r_16 = len(data) % 16
        if(r_16 == 0):
            seedvals = self.get_seedvals()
            request_object = HaspObject.HO_Write_Request()
            encoded_data = self.encode_write_data(data,seedvals,sess['sc_id'])
            request_object.populate(sess['session_id'],file_id,offset,encoded_data,seedvals)
            response_packet = self.send_recv(request_object,HaspConst.OPERATION_ID_WRITE)
            rp = response_packet.payload_object
            return rp.status
        else:
            # If the write request isn't a multiple of 16, the dongle can't do it directly.
            # As a result, we have to kind of bullshit do it.
            l_data = len(data)+r_16
            status,read_data = self.read(session_handle,file_id,offset,l_data)
            if(status != 0):
                return status
            read_data = bytearray(read_data)
            read_data[:len(data)] = data
            return self.write(session_handle,file_id,offset,read_data)


    def encrypt(self,session_handle,in_data,print_qapair=True):
        sess = self.get_session(session_handle)
        if (sess == None):
            return HaspConst.HASP_ERR_BROKEN_SESSION, b""

        if (sess['schannel_active'] == False):
            status = self.setup_schannel(session_handle)
            if (status != 0):
                print("Error Setting up Secure Channel: %04X\n", status)
                return status, b""

        ro = HaspObject.HO_Crypt_Request()
        seedvals = self.get_seedvals()
        status,decoded_request_data,enc_len,crypt_type = self.encrypt_operation_prologue(in_data)
        if(status != HaspConst.HASP_STATUS_OK):
            return status,b""

        encoded_request_data = self.encode_crypt_data(decoded_request_data,seedvals)
        print("Encoded Request Data: %s\n\n" % binascii.hexlify(encoded_request_data))

        ro.populate(sess['session_id'],0,enc_len,encoded_request_data,seedvals,crypt_type)
        response_packet = self.send_recv(ro,HaspConst.OPERATION_ID_ENCRYPT)
        rp = response_packet.payload_object
        if(rp.status != 0):
            return rp.status,b""
        if(crypt_type == 0):
            decoded_response_data = self.decode_crypt_data_type0(rp.data,seedvals,encoded_request_data)
        else:
            decoded_response_data = self.decode_crypt_data_type3(rp.data,seedvals)

        final_encrypted_data = self.encrypt_operation_epilogue(in_data,crypt_type,decoded_response_data,encoded_request_data)

        if(print_qapair == True):
            print("QA Captured (Encrypt): %s:%s" % (binascii.hexlify(decoded_request_data),binascii.hexlify(decoded_response_data)))

        return rp.status,final_encrypted_data[:len(in_data)]


    def decrypt(self,session_handle,in_data,print_qapair=True):
        sess = self.get_session(session_handle)
        if (sess == None):
            return HaspConst.HASP_ERR_BROKEN_SESSION, b""

        if (sess['schannel_active'] == False):
            status = self.setup_schannel(session_handle)
            if (status != 0):
                print("Error Setting up Secure Channel: %04X\n", status)
                return status, b""

        ro = HaspObject.HO_Crypt_Request()
        seedvals = self.get_seedvals()
        status,decoded_request_data,enc_len,crypt_type = self.decrypt_operation_prologue(in_data)
        if(status != HaspConst.HASP_STATUS_OK):
            return status,b""

        encoded_request_data = self.encode_crypt_data(decoded_request_data,seedvals)

        ro.populate(sess['session_id'],1,enc_len,encoded_request_data,seedvals,crypt_type)
        response_packet = self.send_recv(ro,HaspConst.OPERATION_ID_DECRYPT)
        rp = response_packet.payload_object
        if(rp.status != 0):
            return rp.status,b""

        if(crypt_type == 0):
            decoded_response_data = self.decode_crypt_data_type0(rp.data,seedvals,encoded_request_data)
        else:
            decoded_response_data = self.decode_crypt_data_type3(rp.data,seedvals)

        final_decrypted_data = self.decrypt_operation_epilogue(in_data,crypt_type,decoded_response_data,encoded_request_data)

        if(print_qapair == True):
            print("QA Captured (Decrypt): %s:%s" % (binascii.hexlify(decoded_request_data),binascii.hexlify(decoded_response_data)))

        return rp.status,final_decrypted_data[:len(in_data)]


# Server Stub


class HaspAPIServer(APIBase):
    def __init__(self, api_meta_path):
        super(HaspAPIServer, self).__init__(api_meta_path)