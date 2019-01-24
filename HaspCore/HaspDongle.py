import binascii,json,os
import HaspConst

class HaspDongle(object):
    def __init__(self,root):
        self.root = root
        self.name = ""
        self.vendor_id = 0
        self.serial = 0
        self.type = ""
        self.version = ""
        self.rtc = 0
        self.features = {}
        self.memory_info = {}
        self.parse()

    def __str__(self):
        info = ""
        info += "Root Path: %s\n" % self.root
        info += "Name: %s\n" % self.name
        info += "Vendor ID: %d\n" % self.vendor_id
        info += "Hasp Serial: %d\n" % self.serial
        info += "Hasp Type: %s\n" % self.type
        info += "Hasp Version: %s\n" % self.version
        info += "Hasp RTC?: %d\n" % self.rtc
        info += "Memory: \n"
        for flid in self.memory_info.keys():
            cmi = self.memory_info[flid]
            info+= "--Memory - FID: %d Name: %s Size: %d\n" % (flid,cmi["name"],cmi["size"])
        info += "Features: \n"
        for fid in self.features.keys():
            cf = self.features[fid]
            info+="-- Feature ID: %d Key Table Entry Count: %d\n" % (fid,len(cf["keytable"]))
        return info

    def parse(self):
        meta_path = os.path.join(self.root,"meta.json")
        sdata = {}
        with open(meta_path,"rb") as f:
            sdata = json.load(f)
        self.name = sdata['name']
        self.vendor_id = sdata['vendor_id']
        self.serial = sdata['serial']
        self.type = sdata['type']
        self.version = sdata['version']
        self.rtc = sdata['rtc']

        # Query Memory Info
        self.memory_info = self.query_memory()
        # Load Features and Key Table
        self.features = self.load_features()

    def query_memory(self):
        mem_db = {}
        mem_path = os.path.join(self.root,"memory")
        for root,dirs,files in os.walk(mem_path):
            for fl in files:
                if(not fl.endswith(".bin")):
                    continue
                file_id = int(os.path.splitext(fl)[0])
                fpath = os.path.join(root, fl)
                file_size = os.path.getsize(fpath)
                name = ""
                if(file_id == 65524):
                    name = "read/write"
                if(file_id == 65525):
                    name = "read-only"
                mem_db[file_id] = {
                    "size":file_size,
                    "path":fpath,
                    "name":name
                }
        return mem_db


    def load_features(self):
        fdb = {}
        features_path = os.path.join(self.root,"features")
        for root,dirs,files in os.walk(features_path):
            for fl in files:
                fpath = os.path.join(root,fl)
                if(not fpath.endswith("json")):
                    continue
                with open(fpath,"rb") as f:
                    cdb = json.load(f)
                    fid = cdb['feature_id']
                    fdb[fid] = {"keytable":{}}
                    for ki in cdb["keytable"].keys():
                        kreq = binascii.unhexlify(ki)
                        krep = binascii.unhexlify(cdb["keytable"][ki])
                        fdb[fid]["keytable"][kreq] = krep
        return fdb


    def get_key_info(self):
        info = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?><hasp_info><keyspec><keycaps><hasphl /><newintf /><hasp4 /><aes /></keycaps><hasp><haspid>%d</haspid><nethasptype>0</nethasptype>" % self.serial
        for fid in self.memory_info.keys():
            cmi = self.memory_info[fid]
            info+="<memoryinfo><name>%s</name><fileid>%d</fileid><size>%d</size></memoryinfo>" % (cmi["name"],fid,cmi["size"])
        info+="</hasp><port><type>USB</type><address>786432</address></port></keyspec></hasp_info>"
        return info

    def get_hasp_info(self):
        info = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?><hasp_info><hasp id=\"%d\" /></hasp_info>" % self.serial
        return info

    def read_memory(self,file_id,offset,amount):
        if(not file_id in self.memory_info.keys()):
            return HaspConst.HASP_INV_FILEID,b""
        cmi = self.memory_info[file_id]

        if(offset > cmi["size"] or offset+amount > cmi["size"]):
            return HaspConst.HASP_MEM_RANGE,b""
        f = open(cmi["path"],"rb")
        f.seek(offset)
        data = f.read(amount)
        f.close()
        return HaspConst.HASP_STATUS_OK,data

    def write_memory(self,file_id,offset,data):
        if(not file_id in self.memory_info.keys()):
            return HaspConst.HASP_INV_FILEID
        cmi = self.memory_info[file_id]
        if(offset > cmi["size"] or offset+len(data) > cmi["size"]):
            return HaspConst.HASP_MEM_RANGE
        # Read-Only Check
        if(cmi["name"] == "read-only"):
            return HaspConst.HASP_INV_FILEID

        g = open(cmi["path"],"ab")
        g.seek(offset)
        g.write(data)
        return HaspConst.HASP_STATUS_OK

    def crypt_lookup(self,feature_id,request_data):
        if(not feature_id in self.features.keys()):
            return HaspConst.HASP_DEVICE_ERR,b""
        ckeytable = self.features[feature_id]["keytable"]
        if(not request_data in ckeytable.keys()):
            print("Error: Request not found in KeyTable!: %s" % binascii.hexlify(request_data))
            return HaspConst.HASP_DEVICE_ERR, b""

        return HaspConst.HASP_STATUS_OK,ckeytable[request_data]

