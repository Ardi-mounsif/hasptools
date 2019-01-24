import struct
import HaspCore.HaspASN1 as HaspASN1
import HaspCore.HaspConst as HaspConst
import HaspCore.HaspUtils as HaspUtils

# Initialization Operations

class xlm_apiuid_request(object):
    def __init__(self, packet_type):
        self.packet_id = HaspConst.PK_ID_APIUID_REQ
        self.packet_type = packet_type
        self.val_80 = 0
        self.val_81 = 0
        self.val_82 = 0
        self.timestamp = 0

    def init(self, val_80=0, val_81=5, val_82=11):
        self.val_80 = val_80
        self.val_81 = val_81
        self.val_82 = val_82
        self.timestamp = 0

    def serialize(self):
        rb = {
            self.packet_id: {
                0x80: {'value': self.val_80, 'type': 'intval'},
                0x81: {'value': self.val_81, 'type': 'intval'},
                0x82: {'value': self.val_82, 'type': 'intval'},
                0x84: {'value': HaspUtils.GetTimestamp(), 'type': 'intval', 'blen': 5}
            }
        }
        return HaspASN1.asn1_pack(rb)

    def parse(self, data):
        rb = HaspASN1.de_asn1(data)[self.packet_id]
        self.val_80 = HaspASN1.asn1_get_intval(rb[0x80])
        self.val_81 = HaspASN1.asn1_get_intval(rb[0x81])
        self.val_82 = HaspASN1.asn1_get_intval(rb[0x82])
        self.timestamp = HaspASN1.asn1_get_intval(rb[0x84])


class xlm_apiuid_reply(object):
    def __init__(self):
        self.packet_id = HaspConst.PK_ID_APIUID_REP
        self.status = 0
        self.apiuid = 0

    def init(self, status, apiuid=0):
        self.status = status
        self.apiuid = apiuid

    def serialize(self):
        rb = {
            self.packet_id: {
                0x80: {'value': self.status, 'type': 'intval'},
                0x81: {'value': self.apiuid, 'type': 'intval'}
            }
        }
        return HaspASN1.asn1_pack(rb)

    def parse(self, data):
        rb = HaspASN1.de_asn1(data)[self.packet_id]
        self.status = HaspASN1.asn1_get_intval(rb[0x80])
        self.apiuid = HaspASN1.asn1_get_intval(rb[0x81])

# Login Operations
class xlm_api_login_request(object):
    def __init__(self, packet_type):
        self.packet_id = HaspConst.PK_ID_LOGIN_REQ
        self.packet_type = packet_type
        self.pid = 0
        self.tid = 0
        self.hasp_uid = 0
        self.vendor_id = 0
        self.feature_id = 0
        self.username = ""
        self.machine_name = ""
        self.login_type = ""
        self.val_88 = 0
        self.val_89 = 0
        self.timestamp = 0
        self.val_8b = 0
        self.val_8c = 0
        self.val_8d = 0
        self.val_8e = 0
        self.volume_serial = ""
        self.val_90 = 0
        self.hasp_handle = 0

    def init(self, vendor_id, feature_id, hasp_handle, hasp_uid=0x3E9, val_88=5, val_89=11, val_8b=12, val_8c=0,
             val_8d=1, val_8e=0x12B, val_90=0):
        self.pid = HaspUtils.GetPID()
        self.tid = HaspUtils.GetMTID()
        self.hasp_uid = hasp_uid
        self.vendor_id = vendor_id
        self.feature_id = feature_id
        self.username = HaspUtils.GetUserName()
        self.machine_name = HaspUtils.GetMachineName()
        self.login_type = HaspUtils.GetScreenID()
        self.val_88 = val_88
        self.val_89 = val_89
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
            self.packet_id: {
                0x80: {'value': self.pid, 'type': 'intval', 'blen': 2},
                0x81: {'value': self.tid, 'type': 'intval', 'blen': 2},
                0x82: {'value': self.hasp_uid, 'type': 'intval', 'blen': 2},
                0x83: {'value': self.vendor_id, 'type': 'intval', 'blen': 3},
                0x84: {'value': self.feature_id, 'type': 'intval'},
                0x85: {'value': self.username, 'type': 'strval'},
                0x86: {'value': self.machine_name, 'type': 'strval'},
                0x87: {'value': self.login_type, 'type': 'strval'},
                0x88: {'value': self.val_88, 'type': 'intval'},
                0x89: {'value': self.val_89, 'type': 'intval'},
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
        return HaspASN1.asn1_pack(rb)

    def parse(self, data):
        rb = HaspASN1.de_asn1(data)[self.packet_id]
        self.pid = HaspASN1.asn1_get_intval(rb[0x80])
        self.tid = HaspASN1.asn1_get_intval(rb[0x81])
        self.hasp_uid = HaspASN1.asn1_get_intval(rb[0x82])
        self.vendor_id = HaspASN1.asn1_get_intval(rb[0x83])
        self.feature_id = HaspASN1.asn1_get_intval(rb[0x84])
        self.username = HaspASN1.asn1_get_strval(rb[0x85])
        self.machine_name = HaspASN1.asn1_get_strval(rb[0x86])
        self.login_type = HaspASN1.asn1_get_strval(rb[0x87])
        self.val_88 = HaspASN1.asn1_get_intval(rb[0x88])
        self.val_89 = HaspASN1.asn1_get_intval(rb[0x89])
        self.timestamp = HaspASN1.asn1_get_intval(rb[0x8A])
        self.val_8b = HaspASN1.asn1_get_intval(rb[0x8B])
        self.val_8c = HaspASN1.asn1_get_intval(rb[0x8C])
        self.val_8d = HaspASN1.asn1_get_intval(rb[0x8D])
        self.val_8e = HaspASN1.asn1_get_intval(rb[0x8E])
        self.volume_serial = HaspASN1.asn1_get_intval(rb[0x8F])
        self.val_90 = HaspASN1.asn1_get_intval(rb[0x90])
        self.hasp_handle = HaspASN1.asn1_get_intval(rb[0x91])


class xlm_api_login_reply(object):
    def __init__(self):
        self.packet_id = HaspConst.PK_ID_LOGIN_REP
        self.status = 0
        self.instance_id = ""
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
        self.schannel_address = 0
        self.val_8d = 0
        self.val_8e = ""
        self.val_8f = 0

    def init(self, instance_id, hasp_serial, status=0, val_83=0, val_84=0, val_85=0, val_86=0, val_87=0, val_88=0,
             val_89=0, val_8a=0, val_8b=2, schannel_address=0x45, val_8d=0,
             val_8e=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", val_8f=0):
        self.status = status
        self.instance_id = instance_id
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
        self.schannel_address = schannel_address
        self.val_8d = val_8d
        self.val_8e = val_8e
        self.val_8f = val_8f

    def serialize(self):
        rb = {
            self.packet_id: {
                0x80: {'value': self.status, 'type': 'intval'},
                0x81: {'value': self.instance_id},
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
                0x8C: {'value': self.schannel_address, 'type': 'intval'},
                0x8D: {'value': self.val_8d, 'type': 'intval'},
                0x8E: {'value': self.val_8e},
                0x8F: {'value': self.val_8f, 'type': 'intval'}
            }
        }
        return HaspASN1.asn1_pack(rb)

    def parse(self, data):
        rb = HaspASN1.de_asn1(data)[self.packet_id]
        self.status = HaspASN1.asn1_get_intval(rb[0x80])
        self.instance_id = rb[0x81]
        self.hasp_serial = HaspASN1.asn1_get_intval(rb[0x82])
        self.val_83 = HaspASN1.asn1_get_intval(rb[0x83])
        self.val_84 = HaspASN1.asn1_get_intval(rb[0x84])
        self.val_85 = HaspASN1.asn1_get_intval(rb[0x85])
        self.val_86 = HaspASN1.asn1_get_intval(rb[0x86])
        self.val_87 = HaspASN1.asn1_get_intval(rb[0x87])
        self.val_88 = HaspASN1.asn1_get_intval(rb[0x88])
        self.val_89 = HaspASN1.asn1_get_intval(rb[0x89])
        self.val_8a = HaspASN1.asn1_get_intval(rb[0x8A])
        self.val_8b = HaspASN1.asn1_get_intval(rb[0x8B])
        self.schannel_address = HaspASN1.asn1_get_intval(rb[0x8C])
        self.val_8d = HaspASN1.asn1_get_intval(rb[0x8D])
        self.val_8e = rb[0x8E]
        self.val_8f = HaspASN1.asn1_get_intval(rb[0x8F])


# Login Scope Operations
class xlm_api_login_scope_request(object):
    def __init__(self,packet_type = HaspConst.PK_TYPE_LOGINSCOPE):
        self.packet_type = packet_type
        self.packet_id = HaspConst.PK_ID_LOGINSCOPE_REQ
        self.pid = 0
        self.tid = 0
        self.hasp_uid = 0
        self.vendor_id = 0
        self.username = ""
        self.machine_name = ""
        self.login_type = ""
        self.spec=""
        self.scope=""
        self.val_89 = 0
        self.val_8a = 0
        self.timestamp = 0
        self.val_8c = 0
        self.val_8d = 0
        self.val_8e = 0
        self.val_8f = 0
        self.volume_serial = ""
        self.val_91 = 0
        self.hasp_handle = 0
        self.val_93 = 0

    def init(self,vendor_id,hasp_handle,spec,scope,hasp_uid=0x3E9,val_89=5,val_8a=0x0B,val_8c=0x0C,val_8d=0,val_8e=1,val_8f=0x12B,val_91=0,val_93=0):
        self.pid = HaspUtils.GetPID()
        self.tid = HaspUtils.GetMTID()
        self.hasp_uid = hasp_uid
        self.vendor_id = vendor_id
        self.username = HaspUtils.GetUserName()
        self.machine_name = HaspUtils.GetMachineName()
        self.login_type = HaspUtils.GetScreenID()
        self.spec = spec
        self.scope = scope
        self.val_89 = val_89
        self.val_8a = val_8a
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
        rb = {
            self.packet_id:{
                0x80: {'value': self.pid, 'type': 'intval', 'blen': 2},
                0x81: {'value': self.tid, 'type': 'intval', 'blen': 2},
                0x82: {'value': self.hasp_uid, 'type': 'intval', 'blen': 2},
                0x83: {'value': self.vendor_id, 'type': 'intval', 'blen': 3},
                0x84: {'value': self.username, 'type': 'strval'},
                0x85: {'value': self.machine_name, 'type': 'strval'},
                0x86: {'value': self.login_type, 'type': 'strval'},
                0x87: {'value': self.spec, 'type': 'strval'},
                0x88: {'value': self.scope, 'type': 'strval'},
                0x89: {'value': self.val_89, 'type': 'intval'},
                0x8A: {'value': self.val_8a, 'type': 'intval'},
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
        return HaspASN1.asn1_pack(rb)

    def parse(self,data):
        rb = HaspASN1.de_asn1(data)[self.packet_id]
        self.pid = HaspASN1.asn1_get_intval(rb[0x80])
        self.tid = HaspASN1.asn1_get_intval(rb[0x81])
        self.hasp_uid = HaspASN1.asn1_get_intval(rb[0x82])
        self.vendor_id = HaspASN1.asn1_get_intval(rb[0x83])
        self.username = HaspASN1.asn1_get_strval(rb[0x84])
        self.machine_name = HaspASN1.asn1_get_strval(rb[0x85])
        self.login_type = HaspASN1.asn1_get_strval(rb[0x86])
        self.spec = HaspASN1.asn1_get_strval(rb[0x87])
        self.scope = HaspASN1.asn1_get_strval(rb[0x88])
        self.val_89 = HaspASN1.asn1_get_intval(rb[0x89])
        self.val_8A = HaspASN1.asn1_get_intval(rb[0x8A])
        self.timestamp = HaspASN1.asn1_get_intval(rb[0x8B])
        self.val_8c = HaspASN1.asn1_get_intval(rb[0x8C])
        self.val_8d = HaspASN1.asn1_get_intval(rb[0x8D])
        self.val_8e = HaspASN1.asn1_get_intval(rb[0x8E])
        self.val_8f = HaspASN1.asn1_get_intval(rb[0x8F])
        self.volume_serial = HaspASN1.asn1_get_intval(rb[0x90])
        self.val_91 = HaspASN1.asn1_get_intval(rb[0x91])
        self.hasp_handle = HaspASN1.asn1_get_intval(rb[0x92])
        self.val_93 = HaspASN1.asn1_get_intval(rb[0x93])



class xlm_api_login_scope_reply(object):
    def __init__(self):
        self.packet_id = HaspConst.PK_ID_LOGINSCOPE_REP
        self.status = 0
        self.instance_id = 0
        self.hasp_serial = 0
        self.val_83 = 0
        self.val_84 = 0
        self.val_85 = 0
        self.val_87 = 0
        self.schannel_id = 0
        self.val_89 = 0
        self.val_8a = ""
        self.val_8b = 0

    def init(self,status,instance_id,hasp_serial,val_83=0,val_84=1,val_85=0,val_87=2,schannel_id=0x46,val_89=0,val_8a="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",val_8b=0):
        self.status = status
        self.instance_id = instance_id
        self.hasp_serial = hasp_serial
        self.val_83 = val_83
        self.val_84 = val_84
        self.val_85 = val_85
        self.val_87 = val_87
        self.schannel_id = schannel_id
        self.val_89 = val_89
        self.val_8a = val_8a
        self.val_8b = val_8b

    def serialize(self):
        rb = {
            self.packet_id: {
                0x80: {'value': self.status, 'type': 'intval'},
                0x81: {'value': self.instance_id},
                0x82: {'value': self.hasp_serial, 'type': 'intval'},
                0x83: {'value': self.val_83, 'type': 'intval'},
                0x84: {'value': self.val_84, 'type': 'intval'},
                0x85: {'value': self.val_85, 'type': 'intval'},
                0x87: {'value': self.val_87, 'type': 'intval'},
                0x88: {'value': self.schannel_id, 'type': 'intval'},
                0x89: {'value': self.val_89, 'type': 'intval'},
                0x8A: {'value': self.val_8a},
                0x8B: {'value': self.val_8b, 'type': 'intval'},
            }
        }
        return HaspASN1.asn1_pack(rb)

    def parse(self,data):
        rb = HaspASN1.de_asn1(data)[self.packet_id]
        self.status = HaspASN1.asn1_get_intval(rb[0x80])
        self.instance_id = rb[0x81]
        self.hasp_serial = HaspASN1.asn1_get_intval(rb[0x82])
        self.val_83 = HaspASN1.asn1_get_intval(rb[0x83])
        self.val_84 = HaspASN1.asn1_get_intval(rb[0x84])
        self.val_85 = HaspASN1.asn1_get_intval(rb[0x85])
        self.val_87 = HaspASN1.asn1_get_intval(rb[0x87])
        self.schannel_id = HaspASN1.asn1_get_intval(rb[0x88])
        self.val_89 = HaspASN1.asn1_get_intval(rb[0x89])
        self.val_8a = rb[0x8A]
        self.val_8b = HaspASN1.asn1_get_intval(rb[0x8B])


# Logout Operations
class xlm_api_logout_request(object):
    def __init__(self, packet_type):
        self.packet_id = HaspConst.PK_ID_LOGOUT_REQ
        self.packet_type = packet_type
        self.instance_id = 0
        self.val_81 = 0

    def init(self, instance_id, val_81=0):
        self.instance_id = instance_id
        self.val_81 = val_81

    def serialize(self):
        rb = {
            self.packet_id: {
                0x80: {'value': self.instance_id},
                0x81: {'value': self.val_81, 'type': 'intval'}
            }
        }
        return HaspASN1.asn1_pack(rb)

    def parse(self, data):
        rb = HaspASN1.de_asn1(data)[self.packet_id]
        self.instance_id = HaspASN1.asn1_get_intval(rb[0x80])
        self.val_81 = HaspASN1.asn1_get_intval(rb[0x81])


class xlm_api_logout_reply(object):
    def __init__(self):
        self.packet_id = HaspConst.PK_ID_LOGOUT_REP
        self.status = 0

    def parse(self, data):
        rb = HaspASN1.de_asn1(data)[self.packet_id]
        self.status = HaspASN1.asn1_get_intval(rb[0x80])

    def init(self, status):
        self.status = status

    def serialize(self):
        rb = {
            self.packet_id: {
                0x80: {'value': self.status, 'type': 'intval'}
            }
        }
        return HaspASN1.asn1_pack(rb)



# Secure Operations

class xlm_api_setup_schan_request(object):
    def __init__(self,packet_type=HaspConst.PK_TYPE_SCHANNEL):
        self.packet_id = HaspConst.PK_ID_SCHANNEL_REQ
        self.packet_type = packet_type
        self.instance_id = 0
        self.val_81 = 0

    def init(self,instance_id,val_81=0):
        self.instance_id = instance_id
        self.val_81 = val_81

    def parse(self,data):
        rb = HaspASN1.de_asn1(data)[self.packet_id]
        self.instance_id = HaspASN1.asn1_get_intval(rb[0x80])
        self.val_81 = HaspASN1.asn1_get_intval(rb[0x81])

    def serialize(self):
        rb = {
            self.packet_id: {
                0x80: {'value': self.instance_id},
                0x81: {'value': self.val_81,'type':'intval','blen':1}
            }
        }
        return HaspASN1.asn1_pack(rb)

class xlm_api_setup_schan_reply(object):
    def __init__(self):
        self.packet_id = HaspConst.PK_ID_SCHANNEL_REP
        self.status = 0
        self.schannel_address = 0

    def init(self,status=0,schannel_address=0x45):
        self.status = status
        self.schannel_address = schannel_address

    def parse(self,data):
        rb = HaspASN1.de_asn1(data)[self.packet_id]
        self.status = HaspASN1.asn1_get_intval(rb[0x80])
        self.schannel_address = struct.unpack(">I",rb[0x81])[0]

    def serialize(self):
        bcid = struct.pack(">I",self.schannel_address)
        rb = {
            self.packet_id: {
                0x80: {'value': self.status, 'type': 'intval'},
                0x81: {'value': bcid}
            }
        }
        return HaspASN1.asn1_pack(rb)

# Get Size Operations
class xlm_api_get_size_request(object):
    def __init__(self,packet_type=HaspConst.PK_TYPE_GETSIZE):
        self.packet_type = packet_type
        self.packet_id = HaspConst.PK_ID_GETSIZE_REQ
        self.instance_id = 0
        self.file_id = 0

    def init(self,instance_id,file_id):
        self.instance_id = instance_id
        self.file_id = file_id

    def serialize(self):
        rb = {
            self.packet_id: {
                0x80: {'value': self.instance_id},
                0x81: {'value': self.file_id,'type':'intval','blen':3}
            }
        }
        return HaspASN1.asn1_pack(rb)

    def parse(self,data):
        rb = HaspASN1.de_asn1(data)[self.packet_id]
        self.instance_id = rb[0x80]
        self.file_id = HaspASN1.asn1_get_intval(rb[0x81])

class xlm_api_get_size_reply(object):
    def __init__(self):
        self.packet_id = HaspConst.PK_ID_GETSIZE_REP
        self.status = 0
        self.file_size = 0

    def init(self,status,file_size):
        self.status = status
        self.file_size = file_size

    def serialize(self):
        rb = {
            self.packet_id:{
                0x80:{'value':self.status,'type':'intval'},
                0x81:{'value':self.file_size,'type':'intval'}
            }
        }
        return HaspASN1.asn1_pack(rb)

    def parse(self,data):
        rb = HaspASN1.de_asn1(data)[self.packet_id]
        self.status = HaspASN1.asn1_get_intval(rb[0x80])
        self.file_size = HaspASN1.asn1_get_intval(rb[0x81])

# RTC Operations
class xlm_api_get_rtc_request(object):
    def __init__(self,packet_type=HaspConst.PK_TYPE_GETRTC):
        self.packet_type = packet_type
        self.packet_id = HaspConst.PK_ID_GETRTC_REQ
        self.instance_id = 0

    def init(self,instance_id):
        self.instance_id = instance_id

    def serialize(self):
        rb = {
            self.packet_id:{
                0x80:{'value':self.instance_id}
            }
        }
        return HaspASN1.asn1_pack(rb)

    def parse(self,data):
        rb = HaspASN1.de_asn1(data)[self.packet_id]
        self.instance_id = rb[0x80]

class xlm_api_get_rtc_reply(object):
    def __init__(self):
        self.packet_id = HaspConst.PK_ID_GETRTC_REP
        self.status = 0
        self.timestamp = 0

    def init(self,status,timestamp=0):
        self.status = status
        self.timestamp = timestamp

    def serialize(self):
        rb = {
            self.packet_id:{
                0x80:{'value':self.status,'type':'intval'},
                0x81: {'value': self.timestamp, 'type': 'intval','blen':5},
            }
        }
        return HaspASN1.asn1_pack(rb)

    def parse(self,data):
        rb = HaspASN1.de_asn1(data)[self.packet_id]
        self.status = HaspASN1.asn1_get_intval(rb[0x80])
        self.timestamp = HaspASN1.asn1_get_intval(rb[0x81])

# Get Info Operations
class xlm_api_get_info_xml_request(object):
    def __init__(self,packet_type=HaspConst.PK_TYPE_GETINFO):
        self.packet_type = packet_type
        self.packet_id = HaspConst.PK_ID_INFO_REQ
        self.val_80 = 0
        self.hasp_id = 0
        self.scope = ""
        self.format = ""
        self.val_84 = ""

    def init(self,hasp_id,scope,format,val_80=0,val_84=b"\x00\x00\x00\x05\x00\x00\x00\x0B\x00\x00\x5E\x17"):
        self.hasp_id = hasp_id
        self.scope = scope
        self.format = format
        self.val_80 = val_80
        self.val_84 = val_84

    def serialize(self):
        rb = {
            self.packet_id:{
                0x80:{'value':self.val_80,'type':'intval'},
                0x81:{'value':self.hasp_id,'type':'intval','blen':3},
                0x82:{'value':self.scope,'type':'strval'},
                0x83:{'value':self.format,'type':'strval'},
                0x84:{'value':self.val_84}
            }
        }
        return HaspASN1.asn1_pack(rb)

    def parse(self,data):
        rb = HaspASN1.de_asn1(data)[self.packet_id]
        self.val_80 = HaspASN1.asn1_get_intval(rb[0x80])
        self.hasp_id = HaspASN1.asn1_get_intval(rb[0x81])
        self.scope = HaspASN1.asn1_get_strval(rb[0x82])
        self.format = HaspASN1.asn1_get_strval(rb[0x83])
        self.val_84 = HaspASN1.asn1_get_intval(rb[0x84])


class xlm_api_get_info_xml_reply(object):
    def __init__(self):
        self.packet_id = HaspConst.PK_ID_INFO_REP
        self.status = 0
        self.info = ""

    def init(self,status,info):
        self.status = status
        self.info = info

    def serialize(self):
        rb = {
            self.packet_id:{
                0x80: {'value': self.status, 'type': 'intval'},
                0x81: {'value': self.info, 'type': 'strval'}
            }
        }
        return HaspASN1.asn1_pack(rb)

    def parse(self,data):
        rb = HaspASN1.de_asn1(data)[self.packet_id]
        self.status = HaspASN1.asn1_get_intval(rb[0x80])
        self.info = HaspASN1.asn1_get_strval(rb[0x81])


# Read Operations
class xlm_api_read_request(object):
    def __init__(self,packet_type = HaspConst.PK_TYPE_READ):
        self.packet_id = HaspConst.PK_ID_READ_REQ
        self.packet_type = packet_type
        self.instance_id = 0
        self.file_id = 0
        self.offset = 0
        self.amount = 0
        self.seedvals = ""

    def init(self,instance_id,file_id,offset,amount,seedvals):
        self.instance_id = instance_id
        self.file_id = file_id
        self.offset = offset
        self.amount = amount
        self.seedvals = seedvals

    def serialize(self):
        rb = {
            self.packet_id : {
                0x80:{'value':self.instance_id},
                0x81:{'value':self.file_id,'type':'intval','blen':3},
                0x82:{'value':self.offset,'type':'intval'},
                0x83:{'value':self.amount,'type':'intval'},
                0x84:{'value':self.seedvals},
            }
        }
        return HaspASN1.asn1_pack(rb)


    def parse(self,data):
        rb = HaspASN1.de_asn1(data)[self.packet_id]
        self.instance_id = rb[0x80]
        self.file_id = HaspASN1.asn1_get_intval(rb[0x81])
        self.offset = HaspASN1.asn1_get_intval(rb[0x82])
        self.amount = HaspASN1.asn1_get_intval(rb[0x83])
        self.seedvals = rb[0x84]


class xlm_api_read_reply(object):
    def __init__(self):
        self.packet_id = HaspConst.PK_ID_READ_REP
        self.status = 0
        self.data = ""
        self.val_82 = 0

    def init(self,status,data,val_82=0):
        self.status = status
        self.data = data
        self.val_82 = val_82

    def serialize(self):
        rb = {
            self.packet_id: {
                0x80:{'value':self.status,'type':'intval'},
                0x81:{'value':self.data},
                0x82:{'value':self.val_82,'type':'intval'}
            }
        }
        return HaspASN1.asn1_pack(rb)

    def parse(self,data):
        rb = HaspASN1.de_asn1(data)[self.packet_id]
        self.status = HaspASN1.asn1_get_intval(rb[0x80])
        self.data = rb[0x81]
        self.val_82 = HaspASN1.asn1_get_intval(rb[0x82])


# Write Operations
class xlm_api_write_request(object):
    def __init__(self,packet_type=HaspConst.PK_TYPE_WRITE):
        self.packet_type = packet_type
        self.packet_id = HaspConst.PK_ID_WRITE_REQ
        self.instance_id = 0
        self.file_id = 0
        self.offset = 0
        self.data = ""
        self.seedvals = 0
        self.val_85 = 0

    def init(self,instance_id,file_id,offset,data,seedvals,val_85=0):
        self.instance_id = instance_id
        self.file_id = file_id
        self.offset = offset
        self.data = data
        self.seedvals = seedvals
        self.val_85 = val_85

    def serialize(self):
        rb = {
            self.packet_id: {
                0x80:{'value':self.instance_id},
                0x81:{'value':self.file_id,'type':'intval','blen':3},
                0x82:{'value':self.offset,'type':'intval'},
                0x83:{'value':self.data},
                0x84:{'value':self.seedvals},
                0x85:{'value':self.val_85,'type':'intval'}
            }
        }
        return HaspASN1.asn1_pack(rb)

    def parse(self,data):
        rb = HaspASN1.de_asn1(data)[self.packet_id]
        self.instance_id = rb[0x80]
        self.file_id = HaspASN1.asn1_get_intval(rb[0x81])
        self.offset = HaspASN1.asn1_get_intval(rb[0x82])
        self.data = rb[0x83]
        self.seedvals = rb[0x84]
        self.val_85 = HaspASN1.asn1_get_intval(rb[0x85])

class xlm_api_write_reply(object):
    def __init__(self):
        self.packet_id = HaspConst.PK_ID_WRITE_REP
        self.status = 0
        self.num_written = 0
        self.seedvals = ""

    def init(self,status,num_written,seedvals):
        self.status = status
        self.num_written = num_written
        self.seedvals = seedvals

    def serialize(self):
        rb = {
            self.packet_id:{
                0x80:{'value':self.status,'type':'intval'},
                0x81:{'value':self.num_written,'type':'intval'},
                0x82:{'value':self.seedvals},
            }
        }
        return HaspASN1.asn1_pack(rb)

    def parse(self,data):
        rb = HaspASN1.de_asn1(data)[self.packet_id]
        self.status = HaspASN1.asn1_get_intval(rb[0x80])
        self.num_written = HaspASN1.asn1_get_intval(rb[0x81])
        self.seedvals = rb[0x82]


# Crypt Operations
class xlm_api_crypt_request(object):
    def __init__(self,packet_type):
        self.packet_id = HaspConst.PK_ID_CRYPT_REQ
        self.packet_type = packet_type
        self.instance_id = 0
        self.is_decrypt = 0
        self.crypt_type = 0
        self.enc_len = 0
        self.data = ""
        self.seedvals = ""
        self.val_86 = 0

    def init(self,instance_id,is_decrypt,enc_len,data,seedvals,crypt_type=0,val_86=0):
        self.instance_id = instance_id
        self.is_decrypt = is_decrypt
        self.crypt_type = crypt_type
        self.enc_len = enc_len
        self.data = data
        self.seedvals = seedvals
        self.val_86 = val_86

    def serialize(self):
        rb = {
            self.packet_id: {
                0x80:{'value':self.instance_id},
                0x81:{'value':self.is_decrypt,'type':'intval'},
                0x82:{'value':self.crypt_type,'type':'intval'},
                0x83:{'value':self.enc_len,'type':'intval'},
                0x84:{'value':self.data},
                0x85:{'value':self.seedvals},
                0x86:{'value':self.val_86,'type':'intval'}
            }
        }
        return HaspASN1.asn1_pack(rb)

    def parse(self,data):
        rb = HaspASN1.de_asn1(data)[self.packet_id]
        self.instance_id=rb[0x80]
        self.is_decrypt=HaspASN1.asn1_get_intval(rb[0x81])
        self.crypt_type=HaspASN1.asn1_get_intval(rb[0x82])
        self.enc_len=HaspASN1.asn1_get_intval(rb[0x83])
        self.data=rb[0x84]
        self.seedvals=rb[0x85]
        self.val_86 = HaspASN1.asn1_get_intval(rb[0x86])


class xlm_api_crypt_reply(object):
    def __init__(self):
        self.packet_id = HaspConst.PK_ID_CRYPT_REP
        self.status = 0
        self.data = ""

    def init(self,status,data):
        self.status = status
        self.data = data

    def serialize(self):
        rb = {
            self.packet_id:{
                0x80:{'value':self.status,'type':'intval'},
                0x81:{'value':self.data},
            }
        }
        return HaspASN1.asn1_pack(rb)

    def parse(self,data):
        rb = HaspASN1.de_asn1(data)[self.packet_id]
        self.status = HaspASN1.asn1_get_intval(rb[0x80])
        self.data = rb[0x81]