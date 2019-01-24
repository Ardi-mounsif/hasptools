
import base64,struct
import HaspUtils

class HaspVendor(object):
    def __init__(self,hVC,vendor_key):
        self.bdata = hVC
        self.is_valid = False
        self.vendor_id = 0
        if(self.bdata[0:4] != b"2xCV"):
            self.bdata = base64.b64decode(self.bdata)
            self.bdata = HaspUtils.aes_cbc_decrypt(self.bdata,vendor_key)

        if(self.bdata[0:4] != b"2xCV"):
            print("Vendor Blob is Invalid")
            return
        self.is_valid = True
        self.vendor_id = struct.unpack("<I",self.bdata[16:20])[0]



