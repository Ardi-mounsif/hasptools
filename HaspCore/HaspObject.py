# This comprises all of the operational object payloads that correlate to
# various operations the client requests and server fulfills.

import struct
import HaspConst
import HaspUtils
import HaspASN1

def DeriveObject(data):
    # TODO: Detect the object id and return the proper object.
    offset = 0
    # Peek at the object ID to determine what object to load.
    if(data[0] == b"\x7F"):
        oid = struct.unpack(">H",data[0:2])[0]
        offset=2
    else:
        oid = struct.unpack("B",data[0])[0]
        offset=1

    obj = HaspObject()
    if(oid == HaspConst.OID_CLIENTID_REQ):
        obj = HO_Client_ID_Request()
    elif(oid == HaspConst.OID_CLIENTID_REP):
        obj = HO_Client_ID_Response()
    elif(oid == HaspConst.OID_LOGIN_REQ):
        obj = HO_Login_Request()
    elif(oid == HaspConst.OID_LOGIN_REP):
        obj = HO_Login_Response()
    elif(oid == HaspConst.OID_LOGOUT_REQ):
        obj = HO_Logout_Request()
    elif(oid == HaspConst.OID_LOGOUT_REP):
        obj = HO_Logout_Response()
    elif(oid == HaspConst.OID_LOGINSCOPE_REQ):
        obj = HO_Login_Scope_Request()
    elif(oid == HaspConst.OID_LOGINSCOPE_REP):
        obj = HO_Login_Scope_Response()
    elif(oid == HaspConst.OID_INFO_REQ):
        obj = HO_Get_Info_Request()
    elif(oid == HaspConst.OID_INFO_REP):
        obj = HO_Get_Info_Response()
    elif(oid == HaspConst.OID_READ_REQ):
        obj = HO_Read_Request()
    elif(oid == HaspConst.OID_READ_REP):
        obj = HO_Read_Response()
    elif(oid == HaspConst.OID_WRITE_REQ):
        obj = HO_Write_Request()
    elif(oid == HaspConst.OID_WRITE_REP):
        obj = HO_Write_Response()
    elif(oid == HaspConst.OID_GETSIZE_REQ):
        obj = HO_Get_Size_Request()
    elif(oid == HaspConst.OID_GETSIZE_REP):
        obj = HO_Get_Size_Response()
    elif(oid == HaspConst.OID_GETRTC_REQ):
        obj = HO_Get_RTC_Request()
    elif(oid == HaspConst.OID_GETRTC_REP):
        obj = HO_Get_RTC_Response()
    elif(oid == HaspConst.OID_SCHANNEL_REQ):
        obj = HO_Setup_Schannel_Request()
    elif(oid == HaspConst.OID_SCHANNEL_REP):
        obj = HO_Setup_Schannel_Response()
    elif(oid == HaspConst.OID_CRYPT_REQ):
        obj = HO_Crypt_Request()
    elif(oid == HaspConst.OID_CRYPT_REP):
        obj = HO_Crypt_Response()
    else:
        print("Error: Could not derive object from packet.")
        return obj
    obj.parse(data)
    return obj


# Base Object for Code Hinting
class HaspObject(object):
    def serialize(self):
        pass
    def parse(self,data):
        pass


# Client ID Operation Objects
class HO_Client_ID_Request(HaspObject):
    def __init__(self):
        self.oid = HaspConst.OID_CLIENTID_REQ
        self.val_80 = 0
        self.api_version_major = 0
        self.api_version_minor = 0
        self.timestamp = 0

    def populate(self,api_version_major,api_version_minor,val_80=0):
        # Note: We won't populate the timestamp until serialization.
        self.val_80 = val_80
        self.api_version_major = api_version_major
        self.api_version_minor = api_version_minor

    def serialize(self):
        sd = {
            self.oid:{
                0x80: {'value': self.val_80, 'type': 'intval'},
                0x81: {'value': self.api_version_major, 'type': 'intval'},
                0x82: {'value': self.api_version_minor, 'type': 'intval'},
                0x84: {'value': HaspUtils.GetTimestamp(), 'type': 'intval', 'blen': 5}
            }
        }
        return HaspASN1.encode(sd)

    def parse(self,data):
        rb = HaspASN1.decode(data)[self.oid]
        self.val_80 = HaspASN1.get_intval(rb[0x80])
        self.api_version_major = HaspASN1.get_intval(rb[0x81])
        self.api_version_minor = HaspASN1.get_intval(rb[0x82])
        self.timestamp = HaspASN1.get_intval(rb[0x84])

class HO_Client_ID_Response(HaspObject):
    def __init__(self):
        self.oid = HaspConst.OID_CLIENTID_REP
        self.status = 0
        self.client_id = 0

    def populate(self,status,client_id):
        self.status = status
        self.client_id = client_id

    def serialize(self):
        sd = {
            self.oid:{
                0x80: {'value': self.status, 'type': 'intval'},
                0x81: {'value': self.client_id, 'type': 'intval'}
            }
        }
        return HaspASN1.encode(sd)

    def parse(self,data):
        rb = HaspASN1.decode(data)[self.oid]
        self.status = HaspASN1.get_intval(rb[0x80])
        self.client_id = HaspASN1.get_intval(rb[0x81])

# Login Operation Objects
class HO_Login_Request(HaspObject):
    def __init__(self):
        self.oid = HaspConst.OID_LOGIN_REQ
        self.pid = 0
        self.tid = 0
        self.hasp_uid = 0
        self.vendor_id = 0
        self.feature_id = 0
        self.username = ""
        self.machine_name = ""
        self.login_type = ""
        self.api_version_major = 0
        self.api_version_minor = 0
        self.timestamp = 0
        self.val_8b = 0
        self.val_8c = 0
        self.val_8d = 0
        self.val_8e = 0
        self.volume_serial = ""
        self.val_90 = 0
        self.hasp_handle = 0

    def populate(self, vendor_id, feature_id, hasp_handle, api_version_major, api_version_minor, hasp_uid=0x3E9, val_8b=12, val_8c=0,
             val_8d=1, val_8e=0x12B, val_90=0):
        self.pid = HaspUtils.GetPID()
        self.tid = HaspUtils.GetMTID()
        self.hasp_uid = hasp_uid
        self.vendor_id = vendor_id
        self.feature_id = feature_id
        self.username = HaspUtils.GetUserName()
        self.machine_name = HaspUtils.GetMachineName()
        self.login_type = HaspUtils.GetScreenID()
        self.api_version_major = api_version_major
        self.api_version_minor = api_version_minor
        self.timestamp = 0
        self.val_8b = val_8b
        self.val_8c = val_8c
        self.val_8d = val_8d
        self.val_8e = val_8e
        self.volume_serial = HaspUtils.GetVolumeSerial()
        self.val_90 = val_90
        self.hasp_handle = hasp_handle

    def serialize(self):
        rb = {
            self.oid: {
                0x80: {'value': self.pid, 'type': 'intval', 'blen': 2},
                0x81: {'value': self.tid, 'type': 'intval', 'blen': 2},
                0x82: {'value': self.hasp_uid, 'type': 'intval', 'blen': 2},
                0x83: {'value': self.vendor_id, 'type': 'intval', 'blen': 3},
                0x84: {'value': self.feature_id, 'type': 'intval'},
                0x85: {'value': self.username, 'type': 'strval'},
                0x86: {'value': self.machine_name, 'type': 'strval'},
                0x87: {'value': self.login_type, 'type': 'strval'},
                0x88: {'value': self.api_version_major, 'type': 'intval'},
                0x89: {'value': self.api_version_minor, 'type': 'intval'},
                0x8A: {'value': HaspUtils.GetTimestamp(), 'type': 'intval', 'blen': 5},
                0x8B: {'value': self.val_8b, 'type': 'intval'},
                0x8C: {'value': self.val_8c, 'type': 'intval'},
                0x8D: {'value': self.val_8d, 'type': 'intval'},
                0x8E: {'value': self.val_8e, 'type': 'intval'},
                0x8F: {'value': self.volume_serial, 'type': 'intval', 'blen': 4},
                0x90: {'value': self.val_90, 'type': 'intval'},
                0x91: {'value': self.hasp_handle, 'type': 'intval', 'blen': 5}
            }
        }
        return HaspASN1.encode(rb)

    def parse(self, data):
        rb = HaspASN1.decode(data)[self.oid]
        self.pid = HaspASN1.get_intval(rb[0x80])
        self.tid = HaspASN1.get_intval(rb[0x81])
        self.hasp_uid = HaspASN1.get_intval(rb[0x82])
        self.vendor_id = HaspASN1.get_intval(rb[0x83])
        self.feature_id = HaspASN1.get_intval(rb[0x84])
        self.username = HaspASN1.get_strval(rb[0x85])
        self.machine_name = HaspASN1.get_strval(rb[0x86])
        self.login_type = HaspASN1.get_strval(rb[0x87])
        self.api_version_major = HaspASN1.get_intval(rb[0x88])
        self.api_version_minor = HaspASN1.get_intval(rb[0x89])
        self.timestamp = HaspASN1.get_intval(rb[0x8A])
        self.val_8b = HaspASN1.get_intval(rb[0x8B])
        self.val_8c = HaspASN1.get_intval(rb[0x8C])
        self.val_8d = HaspASN1.get_intval(rb[0x8D])
        self.val_8e = HaspASN1.get_intval(rb[0x8E])
        self.volume_serial = HaspASN1.get_intval(rb[0x8F])
        self.val_90 = HaspASN1.get_intval(rb[0x90])
        self.hasp_handle = HaspASN1.get_intval(rb[0x91])


class HO_Login_Response(HaspObject):
    def __init__(self):
        self.oid = HaspConst.OID_LOGIN_REP
        self.status = 0
        self.session_id = 0
        self.hasp_serial = 0
        self.val_83 = 0
        self.val_84 = 0
        self.val_85 = 0
        self.val_86 = 0
        self.val_87 = 0
        self.val_88 = 0
        self.val_89 = 0
        self.val_8a = 0
        self.val_8b = 0
        self.sc_id = 0
        self.val_8d = 0
        self.val_8e = ""
        self.val_8f = 0


    def populate(self, status,session_id, hasp_serial,sc_id, val_83=0, val_84=0, val_85=0, val_86=0, val_87=0, val_88=0,
             val_89=0, val_8a=0, val_8b=2, val_8d=0, val_8e=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", val_8f=0):
        self.status = status
        self.session_id = session_id
        self.hasp_serial = hasp_serial
        self.val_83 = val_83
        self.val_84 = val_84
        self.val_85 = val_85
        self.val_86 = val_86
        self.val_87 = val_87
        self.val_88 = val_88
        self.val_89 = val_89
        self.val_8a = val_8a
        self.val_8b = val_8b
        self.sc_id = sc_id
        self.val_8d = val_8d
        self.val_8e = val_8e
        self.val_8f = val_8f

    def serialize(self):
        rb = {
            self.oid: {
                0x80: {'value': self.status, 'type': 'intval'},
                0x81: {'value': self.session_id,'type':'intval'},
                0x82: {'value': self.hasp_serial, 'type': 'intval'},
                0x83: {'value': self.val_83, 'type': 'intval'},
                0x84: {'value': self.val_84, 'type': 'intval'},
                0x85: {'value': self.val_85, 'type': 'intval'},
                0x86: {'value': self.val_86, 'type': 'intval'},
                0x87: {'value': self.val_87, 'type': 'intval'},
                0x88: {'value': self.val_88, 'type': 'intval'},
                0x89: {'value': self.val_89, 'type': 'intval'},
                0x8A: {'value': self.val_8a, 'type': 'intval'},
                0x8B: {'value': self.val_8b, 'type': 'intval'},
                0x8C: {'value': self.sc_id, 'type': 'intval'},
                0x8D: {'value': self.val_8d, 'type': 'intval'},
                0x8E: {'value': self.val_8e},
                0x8F: {'value': self.val_8f, 'type': 'intval'}
            }
        }
        return HaspASN1.encode(rb)

    def parse(self, data):
        rb = HaspASN1.decode(data)[self.oid]
        self.status = HaspASN1.get_intval(rb[0x80])
        self.session_id = HaspASN1.get_intval(rb[0x81])
        self.hasp_serial = HaspASN1.get_intval(rb[0x82])
        self.val_83 = HaspASN1.get_intval(rb[0x83])
        self.val_84 = HaspASN1.get_intval(rb[0x84])
        self.val_85 = HaspASN1.get_intval(rb[0x85])
        self.val_86 = HaspASN1.get_intval(rb[0x86])
        self.val_87 = HaspASN1.get_intval(rb[0x87])
        self.val_88 = HaspASN1.get_intval(rb[0x88])
        self.val_89 = HaspASN1.get_intval(rb[0x89])
        self.val_8a = HaspASN1.get_intval(rb[0x8A])
        self.val_8b = HaspASN1.get_intval(rb[0x8B])
        self.sc_id = HaspASN1.get_intval(rb[0x8C])
        self.val_8d = HaspASN1.get_intval(rb[0x8D])
        self.val_8e = rb[0x8E]
        self.val_8f = HaspASN1.get_intval(rb[0x8F])

# Login Scope Operation Objects
class HO_Login_Scope_Request(HaspObject):
    def __init__(self):
        self.oid = HaspConst.OID_LOGINSCOPE_REQ
        self.pid = 0
        self.tid = 0
        self.hasp_uid = 0
        self.vendor_id = 0
        self.username = ""
        self.machine_name = ""
        self.login_type = ""
        self.spec=""
        self.scope=""
        self.api_version_major = 0
        self.api_version_minor = 0
        self.timestamp = 0
        self.val_8c = 0
        self.val_8d = 0
        self.val_8e = 0
        self.val_8f = 0
        self.volume_serial = ""
        self.val_91 = 0
        self.hasp_handle = 0
        self.val_93 = 0

    def populate(self,vendor_id,hasp_handle,spec,scope,api_version_major,api_version_minor,hasp_uid=0x3E9,val_8c=0x0C,val_8d=0,val_8e=1,val_8f=0x12B,val_91=0,val_93=0):
        self.pid = HaspUtils.GetPID()
        self.tid = HaspUtils.GetMTID()
        self.hasp_uid = hasp_uid
        self.vendor_id = vendor_id
        self.username = HaspUtils.GetUserName()
        self.machine_name = HaspUtils.GetMachineName()
        self.login_type = HaspUtils.GetScreenID()
        self.spec = spec
        self.scope = scope
        self.val_89 = api_version_major
        self.val_8a = api_version_minor
        self.timestamp = 0
        self.val_8c = val_8c
        self.val_8d = val_8d
        self.val_8e = val_8e
        self.val_8f = val_8f
        self.volume_serial = HaspUtils.GetVolumeSerial()
        self.val_91 = val_91
        self.hasp_handle = hasp_handle
        self.val_93 = val_93

    def serialize(self):
        is_linux_request=False
        if(self.tid == 0x1234):
            is_linux_request = True
        rb = {
            self.oid:{
                0x80: {'value': self.pid, 'type': 'intval', 'blen': 2},
                0x81: {'value': self.tid, 'type': 'intval', 'blen': 2},
                0x82: {'value': self.hasp_uid, 'type': 'intval', 'blen': 2}, # This is 0 in linux
                0x83: {'value': self.vendor_id, 'type': 'intval', 'blen': 3},
                0x84: {'value': self.username, 'type': 'strval'},
                0x85: {'value': self.machine_name, 'type': 'strval'},
                0x86: {'value': self.login_type, 'type': 'strval'},
                0x87: {'value': self.spec, 'type': 'strval'},
                0x88: {'value': self.scope, 'type': 'strval'},
                0x89: {'value': self.api_version_major, 'type': 'intval'},
                0x8A: {'value': self.api_version_minor, 'type': 'intval'},
                0x8B: {'value': HaspUtils.GetTimestamp(), 'type': 'intval', 'blen': 5},
                0x8C: {'value': self.val_8c, 'type': 'intval'},
                0x8D: {'value': self.val_8d, 'type': 'intval'},
                0x8E: {'value': self.val_8e, 'type': 'intval'},
                0x8F: {'value': self.val_8f, 'type': 'intval'},
                0x90: {'value': self.volume_serial, 'type': 'intval', 'blen': 4},
                0x91: {'value': self.val_91, 'type': 'intval'},
                0x92: {'value': self.hasp_handle, 'type': 'intval', 'blen': 5},
                0x93: {'value': self.val_93, 'type': 'intval'},
            }
        }
        if(is_linux_request == True):
            rb[self.oid][0x90] = {'value': self.volume_serial, 'type': 'strval'}
        return HaspASN1.encode(rb)

    def parse(self,data):
        is_linux_request = False
        rb = HaspASN1.decode(data)[self.oid]
        self.pid = HaspASN1.get_intval(rb[0x80])
        self.tid = HaspASN1.get_intval(rb[0x81])
        if(self.tid == 0x1234):
            is_linux_request = True
        self.hasp_uid = HaspASN1.get_intval(rb[0x82])
        self.vendor_id = HaspASN1.get_intval(rb[0x83])
        self.username = HaspASN1.get_strval(rb[0x84])
        self.machine_name = HaspASN1.get_strval(rb[0x85])
        self.login_type = HaspASN1.get_strval(rb[0x86])
        self.spec = HaspASN1.get_strval(rb[0x87])
        self.scope = HaspASN1.get_strval(rb[0x88])
        self.api_version_major = HaspASN1.get_intval(rb[0x89])
        self.api_version_minor = HaspASN1.get_intval(rb[0x8A])
        self.timestamp = HaspASN1.get_intval(rb[0x8B])
        self.val_8c = HaspASN1.get_intval(rb[0x8C])
        self.val_8d = HaspASN1.get_intval(rb[0x8D])
        self.val_8e = HaspASN1.get_intval(rb[0x8E])
        self.val_8f = HaspASN1.get_intval(rb[0x8F])
        if(is_linux_request == True):
            self.volume_serial = HaspASN1.get_strval(rb[0x90])
        else:
            self.volume_serial = HaspASN1.get_intval(rb[0x90])
        self.val_91 = HaspASN1.get_intval(rb[0x91])
        self.hasp_handle = HaspASN1.get_intval(rb[0x92])
        self.val_93 = HaspASN1.get_intval(rb[0x93])



class HO_Login_Scope_Response(object):
    def __init__(self):
        self.oid = HaspConst.OID_LOGINSCOPE_REP
        self.status = 0
        self.session_id = 0
        self.hasp_serial = 0
        self.val_83 = 0
        self.val_84 = 0
        self.val_85 = 0
        self.val_87 = 0
        self.sc_id = 0
        self.val_89 = 0
        self.val_8a = ""
        self.val_8b = 0

    def populate(self,status,session_id,hasp_serial,sc_id,val_83=0,val_84=1,val_85=0,val_87=2,val_89=0,val_8a="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",val_8b=0):
        self.status = status
        self.session_id = session_id
        self.hasp_serial = hasp_serial
        self.val_83 = val_83
        self.val_84 = val_84
        self.val_85 = val_85
        self.val_87 = val_87
        self.sc_id = sc_id
        self.val_89 = val_89
        self.val_8a = val_8a
        self.val_8b = val_8b

    def serialize(self):
        rb = {
            self.oid: {
                0x80: {'value': self.status, 'type': 'intval'},
                0x81: {'value': self.session_id,'type':'intval'},
                0x82: {'value': self.hasp_serial, 'type': 'intval'},
                0x83: {'value': self.val_83, 'type': 'intval'},
                0x84: {'value': self.val_84, 'type': 'intval'},
                0x85: {'value': self.val_85, 'type': 'intval'},
                0x87: {'value': self.val_87, 'type': 'intval'},
                0x88: {'value': self.sc_id, 'type': 'intval'},
                0x89: {'value': self.val_89, 'type': 'intval'},
                0x8A: {'value': self.val_8a},
                0x8B: {'value': self.val_8b, 'type': 'intval'},
            }
        }
        return HaspASN1.encode(rb)

    def parse(self,data):
        rb = HaspASN1.decode(data)[self.oid]
        self.status = HaspASN1.get_intval(rb[0x80])
        self.session_id = HaspASN1.get_intval(rb[0x81])
        self.hasp_serial = HaspASN1.get_intval(rb[0x82])
        self.val_83 = HaspASN1.get_intval(rb[0x83])
        self.val_84 = HaspASN1.get_intval(rb[0x84])
        self.val_85 = HaspASN1.get_intval(rb[0x85])
        self.val_87 = HaspASN1.get_intval(rb[0x87])
        self.sc_id = HaspASN1.get_intval(rb[0x88])
        self.val_89 = HaspASN1.get_intval(rb[0x89])
        self.val_8a = rb[0x8A]
        self.val_8b = HaspASN1.get_intval(rb[0x8B])

# Logout Operation Objects
class HO_Logout_Request(HaspObject):
    def __init__(self):
        self.oid = HaspConst.OID_LOGOUT_REQ
        self.session_id = 0
        self.val_81 = 0

    def populate(self,session_id,val_81=0):
        self.session_id = session_id
        self.val_81 = val_81

    def serialize(self):
        sd ={
            self.oid:{
                0x80: {'value': self.session_id,'type':'intval'},
                0x81: {'value': self.val_81, 'type': 'intval'}
            }
        }
        return HaspASN1.encode(sd)

    def parse(self,data):
        rb = HaspASN1.decode(data)[self.oid]
        self.session_id = HaspASN1.get_intval(rb[0x80])
        self.val_81 = HaspASN1.get_intval(rb[0x81])

class HO_Logout_Response(HaspObject):
    def __init__(self):
        self.oid = HaspConst.OID_LOGOUT_REP
        self.status = 0

    def populate(self,status):
        self.status = status

    def serialize(self):
        rb = {
            self.oid: {
                0x80: {'value': self.status, 'type': 'intval'}
            }
        }
        return HaspASN1.encode(rb)

    def parse(self, data):
        rb = HaspASN1.decode(data)[self.oid]
        self.status = HaspASN1.get_intval(rb[0x80])

# Info Operation Objects
class HO_Get_Info_Request(HaspObject):
    def __init__(self):
        self.oid = HaspConst.OID_INFO_REQ
        self.feature_id = 0
        self.vendor_id = 0
        self.scope = ""
        self.format = ""
        self.api_version_major = 0
        self.api_version_minor = 0
        self.api_build_number = 0
        self.val_84 = ""

    def populate(self,vendor_id,api_version_major,api_version_minor,api_build_number,scope,format,feature_id=0):
        self.feature_id = feature_id
        self.vendor_id = vendor_id
        self.scope = scope
        self.format = format
        self.api_version_major = api_version_major
        self.api_version_minor = api_version_minor
        self.api_build_number = api_build_number
        self.val_84 = struct.pack(">I",api_version_major)+\
                      struct.pack(">I",api_version_minor)+\
                      struct.pack(">I",api_build_number)

    def serialize(self):
        rb = {
            self.oid:{
                0x80:{'value':self.feature_id,'type':'intval'},
                0x81:{'value':self.vendor_id,'type':'intval','blen':3},
                0x82:{'value':self.scope,'type':'strval'},
                0x83:{'value':self.format,'type':'strval'},
                0x84:{'value':self.val_84}
            }
        }
        return HaspASN1.encode(rb)

    def parse(self,data):
        rb = HaspASN1.decode(data)[self.oid]
        self.feature_id = HaspASN1.get_intval(rb[0x80])
        self.vendor_id = HaspASN1.get_intval(rb[0x81])
        self.scope = HaspASN1.get_strval(rb[0x82])
        self.format = HaspASN1.get_strval(rb[0x83])
        self.val_84 = rb[0x84]
        self.api_version_major = struct.unpack(">I",self.val_84[0:4])[0]
        self.api_version_minor = struct.unpack(">I", self.val_84[4:8])[0]
        self.api_build_number = struct.unpack(">I", self.val_84[8:12])[0]


class HO_Get_Info_Response(HaspObject):
    def __init__(self):
        self.oid = HaspConst.OID_INFO_REP
        self.status = 0
        self.info = ""

    def populate(self,status,info):
        self.status = status
        self.info = info

    def serialize(self):
        rb = {
            self.oid:{
                0x80: {'value': self.status, 'type': 'intval'},
                0x81: {'value': self.info, 'type': 'strval'}
            }
        }
        return HaspASN1.encode(rb)

    def parse(self,data):
        rb = HaspASN1.decode(data)[self.oid]
        self.status = HaspASN1.get_intval(rb[0x80])
        self.info = HaspASN1.get_strval(rb[0x81])

# Read Operation Objects
class HO_Read_Request(HaspObject):
    def __init__(self):
        self.oid = HaspConst.OID_READ_REQ
        self.session_id = 0
        self.file_id = 0
        self.offset = 0
        self.amount = 0
        self.seedvals = ""

    def populate(self,session_id,file_id,offset,amount,seedvals):
        self.session_id = session_id
        self.file_id = file_id
        self.offset = offset
        self.amount = amount
        self.seedvals = seedvals

    def serialize(self):
        rb = {
            self.oid : {
                0x80:{'value':self.session_id,'type':'intval'},
                0x81:{'value':self.file_id,'type':'intval','blen':3},
                0x82:{'value':self.offset,'type':'intval'},
                0x83:{'value':self.amount,'type':'intval'},
                0x84:{'value':self.seedvals},
            }
        }
        return HaspASN1.encode(rb)


    def parse(self,data):
        rb = HaspASN1.decode(data)[self.oid]
        self.session_id = HaspASN1.get_intval(rb[0x80])
        self.file_id = HaspASN1.get_intval(rb[0x81])
        self.offset = HaspASN1.get_intval(rb[0x82])
        self.amount = HaspASN1.get_intval(rb[0x83])
        self.seedvals = rb[0x84]


class HO_Read_Response(HaspObject):
    def __init__(self):
        self.oid = HaspConst.OID_READ_REP
        self.status = 0
        self.data = ""
        self.val_82 = 0

    def populate(self,status,data,val_82=0):
        self.status = status
        self.data = data
        self.val_82 = val_82

    def serialize(self):
        rb = {
            self.oid: {
                0x80:{'value':self.status,'type':'intval'},
                0x81:{'value':self.data},
                0x82:{'value':self.val_82,'type':'intval'}
            }
        }
        return HaspASN1.encode(rb)

    def parse(self,data):
        rb = HaspASN1.decode(data)[self.oid]
        self.status = HaspASN1.get_intval(rb[0x80])
        self.data = rb[0x81]
        self.val_82 = HaspASN1.get_intval(rb[0x82])

# Write Operation Objects
class HO_Write_Request(HaspObject):
    def __init__(self):
        self.oid = HaspConst.OID_WRITE_REQ
        self.session_id = 0
        self.file_id = 0
        self.offset = 0
        self.data = ""
        self.seedvals = 0
        self.val_85 = 0

    def populate(self,session_id,file_id,offset,data,seedvals,val_85=0):
        self.session_id = session_id
        self.file_id = file_id
        self.offset = offset
        self.data = data
        self.seedvals = seedvals
        self.val_85 = val_85

    def serialize(self):
        rb = {
            self.oid: {
                0x80:{'value':self.session_id,'type':'intval'},
                0x81:{'value':self.file_id,'type':'intval','blen':3},
                0x82:{'value':self.offset,'type':'intval'},
                0x83:{'value':self.data},
                0x84:{'value':self.seedvals},
                0x85:{'value':self.val_85,'type':'intval'}
            }
        }
        return HaspASN1.encode(rb)

    def parse(self,data):
        rb = HaspASN1.decode(data)[self.oid]
        self.session_id = HaspASN1.get_intval(rb[0x80])
        self.file_id = HaspASN1.get_intval(rb[0x81])
        self.offset = HaspASN1.get_intval(rb[0x82])
        self.data = rb[0x83]
        self.seedvals = rb[0x84]
        self.val_85 = HaspASN1.get_intval(rb[0x85])

class HO_Write_Response(HaspObject):
    def __init__(self):
        self.oid = HaspConst.OID_WRITE_REP
        self.status = 0
        self.num_written = 0
        self.seedvals = ""

    def populate(self,status,num_written,seedvals):
        self.status = status
        self.num_written = num_written
        self.seedvals = seedvals

    def serialize(self):
        rb = {
            self.oid:{
                0x80:{'value':self.status,'type':'intval'},
                0x81:{'value':self.num_written,'type':'intval'},
                0x82:{'value':self.seedvals},
            }
        }
        return HaspASN1.encode(rb)

    def parse(self,data):
        rb = HaspASN1.decode(data)[self.oid]
        self.status = HaspASN1.get_intval(rb[0x80])
        self.num_written = HaspASN1.get_intval(rb[0x81])
        self.seedvals = rb[0x82]

# Get Memory Size Operation Objects

class HO_Get_Size_Request(HaspObject):
    def __init__(self):
        self.oid = HaspConst.OID_GETSIZE_REQ
        self.session_id = 0
        self.file_id = 0

    def populate(self,session_id,file_id):
        self.session_id = session_id
        self.file_id = file_id

    def serialize(self):
        rb = {
            self.oid: {
                0x80: {'value': self.session_id,'type':'intval'},
                0x81: {'value': self.file_id,'type':'intval','blen':3}
            }
        }
        return HaspASN1.encode(rb)

    def parse(self,data):
        rb = HaspASN1.decode(data)[self.oid]
        self.session_id = HaspASN1.get_intval(rb[0x80])
        self.file_id = HaspASN1.get_intval(rb[0x81])

class HO_Get_Size_Response(HaspObject):
    def __init__(self):
        self.oid = HaspConst.OID_GETSIZE_REP
        self.status = 0
        self.file_size = 0

    def populate(self,status,file_size):
        self.status = status
        self.file_size = file_size

    def serialize(self):
        rb = {
            self.oid:{
                0x80:{'value':self.status,'type':'intval'},
                0x81:{'value':self.file_size,'type':'intval'}
            }
        }
        return HaspASN1.encode(rb)

    def parse(self,data):
        rb = HaspASN1.decode(data)[self.oid]
        self.status = HaspASN1.get_intval(rb[0x80])
        self.file_size = HaspASN1.get_intval(rb[0x81])

# Get RTC Operation Objects

class HO_Get_RTC_Request(HaspObject):
    def __init__(self):
        self.oid = HaspConst.OID_GETRTC_REQ
        self.session_id = 0

    def populate(self,session_id):
        self.session_id = session_id

    def serialize(self):
        rb = {
            self.oid:{
                0x80:{'value':self.session_id,'type':'intval'}
            }
        }
        return HaspASN1.encode(rb)

    def parse(self,data):
        rb = HaspASN1.decode(data)[self.oid]
        self.session_id = HaspASN1.get_intval(rb[0x80])

class HO_Get_RTC_Response(HaspObject):
    def __init__(self):
        self.oid = HaspConst.OID_GETRTC_REP
        self.status = 0
        self.rtc_timestamp = 0

    def populate(self,status,rtc_timestamp=0):
        self.status = status
        self.rtc_timestamp = rtc_timestamp

    def serialize(self):
        rb = {
            self.oid:{
                0x80:{'value':self.status,'type':'intval'},
                0x81: {'value': self.rtc_timestamp, 'type': 'intval','blen':5},
            }
        }
        return HaspASN1.encode(rb)

    def parse(self,data):
        rb = HaspASN1.decode(data)[self.oid]
        self.status = HaspASN1.get_intval(rb[0x80])
        self.rtc_timestamp = HaspASN1.get_intval(rb[0x81])

# Setup Secure Channel (sc) Operation Objects

class HO_Setup_Schannel_Request(HaspObject):
    def __init__(self):
        self.oid = HaspConst.OID_SCHANNEL_REQ
        self.session_id = 0
        self.val_81 = 0

    def populate(self,session_id,val_81=0):
        self.session_id = session_id
        self.val_81 = val_81

    def serialize(self):
        rb = {
            self.oid: {
                0x80: {'value': self.session_id,'type':'intval'},
                0x81: {'value': self.val_81,'type':'intval'}
            }
        }
        return HaspASN1.encode(rb)

    def parse(self,data):
        rb = HaspASN1.decode(data)[self.oid]
        self.session_id = HaspASN1.get_intval(rb[0x80])
        self.val_81 = HaspASN1.get_intval(rb[0x81])


class HO_Setup_Schannel_Response(HaspObject):
    def __init__(self):
        self.oid = HaspConst.OID_SCHANNEL_REP
        self.status = 0
        self.sc_id = 0

    def populate(self,status,sc_id):
        self.status = status
        self.sc_id = sc_id

    def serialize(self):
        bcid = struct.pack(">I",self.sc_id)
        rb = {
            self.oid: {
                0x80: {'value': self.status, 'type': 'intval'},
                0x81: {'value': bcid}
            }
        }
        return HaspASN1.encode(rb)

    def parse(self,data):
        rb = HaspASN1.decode(data)[self.oid]
        self.status = HaspASN1.get_intval(rb[0x80])
        self.sc_id = struct.unpack(">I",rb[0x81])[0]

# Crypto Operation Objects

class HO_Crypt_Request(HaspObject):
    def __init__(self):
        self.oid = HaspConst.OID_CRYPT_REQ
        self.session_id = 0
        self.is_decrypt = 0
        self.crypt_type = 0
        self.enc_len = 0
        self.data = ""
        self.seedvals = ""
        self.val_86 = 0

    def populate(self,instance_id,is_decrypt,enc_len,data,seedvals,crypt_type=0,val_86=0):
        self.session_id = instance_id
        self.is_decrypt = is_decrypt
        self.crypt_type = crypt_type
        self.enc_len = enc_len
        self.data = data
        self.seedvals = seedvals
        self.val_86 = val_86

    def serialize(self):
        rb = {
            self.oid: {
                0x80:{'value':self.session_id,'type':'intval'},
                0x81:{'value':self.is_decrypt,'type':'intval'},
                0x82:{'value':self.crypt_type,'type':'intval'},
                0x83:{'value':self.enc_len,'type':'intval'},
                0x84:{'value':self.data},
                0x85:{'value':self.seedvals},
                0x86:{'value':self.val_86,'type':'intval'}
            }
        }
        return HaspASN1.encode(rb)

    def parse(self,data):
        rb = HaspASN1.decode(data)[self.oid]
        self.session_id=HaspASN1.get_intval(rb[0x80])
        self.is_decrypt=HaspASN1.get_intval(rb[0x81])
        self.crypt_type=HaspASN1.get_intval(rb[0x82])
        self.enc_len=HaspASN1.get_intval(rb[0x83])
        self.data=rb[0x84]
        self.seedvals=rb[0x85]
        self.val_86 = HaspASN1.get_intval(rb[0x86])


class HO_Crypt_Response(HaspObject):
    def __init__(self):
        self.oid = HaspConst.OID_CRYPT_REP
        self.status = 0
        self.data = ""

    def populate(self,status,data):
        self.status = status
        self.data = data

    def serialize(self):
        rb = {
            self.oid:{
                0x80:{'value':self.status,'type':'intval'},
                0x81:{'value':self.data},
            }
        }
        return HaspASN1.encode(rb)

    def parse(self,data):
        rb = HaspASN1.decode(data)[self.oid]
        self.status = HaspASN1.get_intval(rb[0x80])
        self.data = rb[0x81]