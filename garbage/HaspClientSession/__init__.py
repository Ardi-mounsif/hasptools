import HaspCore.HaspConst as HaspConst
import HaspCore.HaspVendor as HaspVendor
import HaspCore.HaspUtils as HaspUtils
import garbage.HaspProtocol as HaspProtocol
import HaspCore.HaspPacket as HaspPacket
import binascii

class HaspClientSession(object):
    def __init__(self, apis_root):
        self.handle = HaspUtils.make_fake_handle_value()
        self.session_key = session_key
        self.api_uid = 0
        self.transaction_num = 0
        self.instance_id = 0
        self.vendor_code = HaspVendor.HaspVendor(vendor_blob)
        self.logged_in = False
        self.feature_id = 0
        self.schannel_active = False
        self.schannel_id = 0

    #TODO: Actually generate it like the library does.
    def get_seedvals(self):
        return binascii.unhexlify("FBB98A8500004600")



    def generate_sessionkey(self,seedvals):
        indata = seedvals[0:4] + b"\x00" * 12
        return HaspUtils.aes_ecb_encrypt(indata,self.session_key)

    def generate_sessionkey_2(self,seedvals):
        indata = seedvals[4:8] + b"\x00" * 12
        return HaspUtils.aes_ecb_encrypt(indata,self.session_key)

    def generate_sessionkey_3(self,seedvals):
        indata = seedvals + b"\x00" * 8
        return HaspUtils.aes_ecb_encrypt(indata,self.session_key)

    def decode_responsedata(self,indata,seedvals):
        dkey = self.generate_sessionkey(seedvals[0:4])
        return HaspUtils.aes_cbc_decrypt(indata,dkey,seedvals[4:8])

    def encode_requestdata(self,indata,seedvals):
        dkey = self.generate_sessionkey(seedvals[0:4])
        return HaspUtils.aes_cbc_encrypt(indata,dkey,seedvals[4:8])

    # This is where the packet operations will happen (within the session)
    def session_logout(self, sock):
        logout_request = HaspProtocol.xlm_api_logout_request(HaspConst.PK_TYPE_LOGOUT)
        logout_request.init(self.instance_id)
        rp = HaspPacket.HaspPacket().generate(self.transaction_num, self.api_uid, logout_request)
        sock.write(rp)
        self.transaction_num += 1
        logout_response = HaspPacket.HaspPacket().parse(sock.read(), HaspProtocol.xlm_api_logout_reply())
        return logout_response.status

    def setup_schannel(self,sock):
        if(self.schannel_active == True):
            return 0
        sc_request = HaspProtocol.xlm_api_setup_schan_request()
        sc_request.init(self.instance_id)
        rp = HaspPacket.HaspPacket().generate(self.transaction_num, self.api_uid, sc_request)
        sock.write(rp)
        self.transaction_num += 1
        sc_reply = HaspPacket.HaspPacket().parse(sock.read(), HaspProtocol.xlm_api_setup_schan_reply())
        self.schannel_active = True
        return sc_reply.status

    def get_apiuid(self, sock):
        apiuid_request = HaspProtocol.xlm_apiuid_request(HaspConst.PK_TYPE_APIUID)
        rp = HaspPacket.HaspPacket().generate(self.transaction_num, self.api_uid, apiuid_request)
        sock.write(rp)
        self.transaction_num += 1
        logout_response = HaspPacket.HaspPacket().parse(sock.read(), HaspProtocol.xlm_apiuid_reply())
        if (logout_response.status == 0):
            self.api_uid = logout_response.apiuid
        return logout_response.status

    def session_login(self, sock,feature_id):
        # First order of business, get an APIUID... we need this to do pretty much everything...
        status = self.get_apiuid(sock)
        if (status != 0):
            print("GetAPIUID Error: %04X" % status)
            return status

        login_request = HaspProtocol.xlm_api_login_request(HaspConst.PK_TYPE_LOGIN)
        login_request.init(self.vendor_code.vendor_id, feature_id, self.handle)
        rp = HaspPacket.HaspPacket().generate(self.transaction_num, self.api_uid, login_request)
        sock.write(rp)
        self.transaction_num += 1
        login_response = HaspPacket.HaspPacket().parse(sock.read(), HaspProtocol.xlm_api_login_reply())
        if (login_response.status != 0):
            return login_response.status

        self.instance_id = login_response.instance_id
        self.feature_id = feature_id
        self.hasp_serial = login_response.hasp_serial
        self.logged_in = True
        return HaspConst.HASP_STATUS_OK

    def session_login_scope(self,sock,feature_id,scope):
        # First order of business, get an APIUID... we need this to do pretty much everything...
        status = self.get_apiuid(sock)
        if (status != 0):
            print("GetAPIUID Error: %04X" % status)
            return status

        login_scope_request = HaspProtocol.xlm_api_login_scope_request()
        login_scope_request.init(self.vendor_code.vendor_id,self.handle,HaspConst.SPEC_FEATURE_ID % feature_id,scope)

        rp = HaspPacket.HaspPacket().generate(self.transaction_num, self.api_uid, login_scope_request)
        sock.write(rp)
        self.transaction_num += 1
        login_response = HaspPacket.HaspPacket().parse(sock.read(), HaspProtocol.xlm_api_login_scope_reply())
        if (login_response.status != 0):
            return login_response.status

        self.instance_id = login_response.instance_id
        self.feature_id = feature_id
        self.hasp_serial = login_response.hasp_serial
        self.schannel_id = login_response.schannel_id
        self.logged_in = True
        return HaspConst.HASP_STATUS_OK

    def session_read(self,sock,file_id,offset,amount):
        status = self.setup_schannel(sock)
        if(status != 0):
            print("Error Setting up Secure Channel: %04X\n",status)
            return status,""
        read_request = HaspProtocol.xlm_api_read_request()
        seedvals = self.get_seedvals()
        read_request.init(self.instance_id,file_id,offset,amount,seedvals)
        rp = HaspPacket.HaspPacket().generate(self.transaction_num,self.api_uid,read_request)
        sock.write(rp)
        self.transaction_num+=1
        read_response = HaspPacket.HaspPacket().parse(sock.read(), HaspProtocol.xlm_api_read_reply())
        if(read_response.status != HaspConst.HASP_STATUS_OK):
            return read_response.status,""
        decoded_data = self.decode_responsedata(read_response.data,seedvals)
        return HaspConst.HASP_STATUS_OK,decoded_data

    def session_write(self,sock,indata,file_id,offset):
        status = self.setup_schannel(sock)
        if(status != 0):
            print("Error Setting up Secure Channel: %04X\n",status)
            return status,""
        seedvals = self.get_seedvals()
        dkey = self.generate_sessionkey_3(seedvals)
        print("Derived Key: %s" % binascii.hexlify(dkey))

        enc_data = HaspUtils.aes_cbc_encrypt(indata,dkey,seedvals[4:8])

        write_request = HaspProtocol.xlm_api_write_request()
        write_request.init(self.instance_id,file_id,offset,enc_data,seedvals)
        rp = HaspPacket.HaspPacket().generate(self.transaction_num,self.api_uid,write_request)
        sock.write(rp)
        self.transaction_num+=1
        write_response = HaspPacket.HaspPacket().parse(sock.read(), HaspProtocol.xlm_api_write_reply())
        return write_response.status


    def get_size(self,sock,file_id):
        status = 0
        file_size = 0
        info_get_size = HaspProtocol.xlm_api_get_size_request()
        info_get_size.init(self.instance_id,file_id)
        rp = HaspPacket.HaspPacket().generate(self.transaction_num,self.api_uid,info_get_size)
        sock.write(rp)
        self.transaction_num+=1
        info_response = HaspPacket.HaspPacket().parse(sock.read(), HaspProtocol.xlm_api_get_size_reply())
        if(info_response.status != HaspConst.HASP_STATUS_OK):
            return info_response.status,0
        return info_response.status,info_response.file_size


    def get_rtc(self,sock):
        status = 0
        timestamp = 0
        rtc_req = HaspProtocol.xlm_api_get_rtc_request()
        rtc_req.init(self.instance_id)
        rp = HaspPacket.HaspPacket().generate(self.transaction_num,self.api_uid,rtc_req)
        sock.write(rp)
        self.transaction_num+=1
        rtc_rep = HaspPacket.HaspPacket().parse(sock.read(), HaspProtocol.xlm_api_get_rtc_reply())
        if(rtc_rep.status != HaspConst.HASP_STATUS_OK):
            return rtc_rep.status,0
        return rtc_rep.status,rtc_rep.timestamp


    def session_info(self,sock,scope,format):
        info_request = HaspProtocol.xlm_api_get_info_xml_request()
        info_request.init(self.vendor_code.vendor_id,scope,format)
        rp = HaspPacket.HaspPacket().generate(self.transaction_num,self.api_uid,info_request)
        sock.write(rp)
        self.transaction_num+=1
        info_response = HaspPacket.HaspPacket().parse(sock.read(), HaspProtocol.xlm_api_get_info_xml_reply())
        if(info_response.status != HaspConst.HASP_STATUS_OK):
            return info_response.status,""
        return info_response.status,info_response.info

    def session_encrypt(self,sock,indata,return_raw=False):
        status = self.setup_schannel(sock)
        if(status != 0):
            print("Error Setting up Secure Channel: %04X\n",status)
            return status,""
        orig_indata_len = len(indata)
        if(orig_indata_len< 16 or orig_indata_len > 1024):
            print("Enc: Error - Data must be between 16 and 1024 bytes.")
            return HaspConst.HASP_TOO_SHORT

        seedvals = self.get_seedvals()
        dkey = self.generate_sessionkey(seedvals)

        if(orig_indata_len < 32):
            print("Encrypt Operation: Small")
            crypt_type = 0
            enc_len = orig_indata_len
            if(orig_indata_len > 16):
                # We have to pad the input if it's between 17-31 bytes
                pad_len = 32 - orig_indata_len
                indata+= b"\x00"*pad_len
            encoded_data = self.encode_requestdata(indata,seedvals)
            print("Encoded Data (Encrypt): %s " % binascii.hexlify(encoded_data))
        else:
            print("Encrypt Operation - Big")
            # Larger Encrypt Operation
            crypt_type = 3
            enc_len = 0x10
            head_hash = HaspUtils.ripemd160(indata[16:])
            xor_header = HaspUtils.xor_data(indata[:16],head_hash)
            # TODO: Check if this has to be encoded?
            encoded_data = self.encode_requestdata(xor_header,seedvals)

        encrypt_request = HaspProtocol.xlm_api_crypt_request(HaspConst.PK_TYPE_ENCRYPT)
        encrypt_request.init(self.instance_id,0,enc_len,encoded_data,seedvals,crypt_type)
        rp = HaspPacket.HaspPacket().generate(self.transaction_num,self.api_uid,encrypt_request)
        sock.write(rp)
        self.transaction_num+=1
        encrypt_response = HaspPacket.HaspPacket().parse(sock.read(), HaspProtocol.xlm_api_crypt_reply())
        if(encrypt_response.status != HaspConst.HASP_STATUS_OK):
            return encrypt_response.status,""

        response_data_encoded = encrypt_response.data
        hasp_response_decoded = ""
        print("Response Data - Encoded (Encrypt): %s" % binascii.hexlify(response_data_encoded))
        if(crypt_type == 0):
            response_data = HaspUtils.aes_cbc_decrypt(response_data_encoded,dkey,iv=encoded_data[0:16])
            print("Decoded Response (Encrypt): %s" % binascii.hexlify(response_data))
        elif(crypt_type == 3):
            print("Orig Indata Len : %d" % orig_indata_len)
            rd = bytearray(HaspUtils.aes_cbc_decrypt(response_data_encoded,dkey))
            print("Decoded Response (Encrypt): %s" % binascii.hexlify(rd))
            response_data = rd[16:32]
            rd[:16] = HaspUtils.xor_data(rd[:16],encoded_data)
            body_key = rd[:16]
            body_iv = b"\x00" * 16
            # TODO: Might have to pad this for CBC
            body_len = len(indata[16:])
            body_enc = HaspUtils.aes_cbc_encrypt(indata[16:],str(body_key))[:body_len]
            response_data += body_enc

        if(return_raw == True):
            return encrypt_response.status, response_data[:orig_indata_len],hasp_response_decoded
        else:
            return encrypt_response.status,response_data[:orig_indata_len]


    def session_decrypt(self,sock,indata,return_raw=False):
        print("SESSION DECRYPT")
        status = self.setup_schannel(sock)
        if(status != 0):
            print("Error Setting up Secure Channel: %04X\n",status)
            return status,""
        orig_indata_len = len(indata)
        if(orig_indata_len< 16 or orig_indata_len > 1024):
            print("Dec: Error - Data must be between 16 and 1024 bytes.")
            return HaspConst.HASP_TOO_SHORT

        seedvals = self.get_seedvals()
        dkey = self.generate_sessionkey(seedvals)
        if(orig_indata_len < 32):
            crypt_type = 0
            enc_len = orig_indata_len
            if(orig_indata_len > 16):
                # We have to pad the input if it's between 17-31 bytes
                pad_len = 32 - orig_indata_len
                indata+= b"\x00"*pad_len
            encoded_data = self.encode_requestdata(indata,seedvals)
        else:
            crypt_type = 3
            enc_len = 0x10
            encoded_data = self.encode_requestdata(indata[0:16], seedvals)


        decrypt_request = HaspProtocol.xlm_api_crypt_request(HaspConst.PK_TYPE_DECRYPT)
        decrypt_request.init(self.instance_id,0,enc_len,encoded_data,seedvals,crypt_type)
        rp = HaspPacket.HaspPacket().generate(self.transaction_num,self.api_uid,decrypt_request)
        sock.write(rp)
        self.transaction_num+=1
        decrypt_response = HaspPacket.HaspPacket().parse(sock.read(), HaspProtocol.xlm_api_crypt_reply())
        if(decrypt_response.status != HaspConst.HASP_STATUS_OK):
            return decrypt_response.status,""

        response_data_encoded = decrypt_response.data
        hasp_response_decoded = ""
        if(crypt_type == 0):
            response_data_decoded = HaspUtils.aes_cbc_decrypt(response_data_encoded, dkey, iv=encoded_data[0:16])
            response_data = response_data_decoded[:orig_indata_len]
        elif(crypt_type == 3):
            response_data_decoded = bytearray(HaspUtils.aes_cbc_decrypt(response_data_encoded,dkey))
            #response_data_decoded = bytearray(self.decode_responsedata(response_data_encoded,seedvals))
            response_data_decoded[:16] = HaspUtils.xor_data(response_data_decoded[:16],encoded_data)

            iv = b"\x00"*16
            pt_body = HaspUtils.aes_cbc_decrypt(indata[16:],str(response_data_decoded[:16]),iv)
            header_key = HaspUtils.ripemd160(pt_body)
            pt_header = HaspUtils.xor_data(response_data_decoded[16:32],header_key)
            response_data = pt_header+pt_body


        return decrypt_response.status,response_data