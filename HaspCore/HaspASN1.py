import struct,binascii

# Decoding Methods
def decode_length(data,offset):
    tv_len = 1
    val_len = struct.unpack("B",data[offset])[0]
    if(val_len == 0x81):
        tv_len = 2
        val_len = struct.unpack("B",data[offset+1])[0]
    elif(val_len == 0x82):
        tv_len = 3
        val_len = struct.unpack(">H",data[offset+1:offset+3])[0]
    offset += tv_len
    return val_len,offset

# Determine size of tag and value.
def decode_tag(data,offset):
    itag = struct.unpack("B", data[offset])[0]
    tlen = 1
    if(itag == 0x7F):
        itag = struct.unpack(">H",data[offset:offset+2])[0]
        tlen = 2
    offset +=tlen
    return itag,offset

# Return data + length
def decode(data):
    db  = {}
    offset = 0
    while(offset < len(data)):
        tag,offset = decode_tag(data,offset)
        dlen,offset = decode_length(data,offset)
        if(tag > 0x7F and tag < 0x9F):
            db[tag] = data[offset:offset+dlen]
        else:
            db[tag] = decode(data[offset:offset+dlen])
        offset+=dlen
    return db

# Utility Functions (Parsing)
def get_strval(data):
    return data[:-1].decode('ascii')

def get_intval(data):
    dlen = len(data)
    if(dlen == 1):
        return struct.unpack("B",data)[0]
    elif(dlen == 2):
        return struct.unpack(">H",data)[0]
    elif(dlen == 3):
        return struct.unpack(">I",b"\x00"+data)[0]
    elif(dlen == 4):
        return struct.unpack(">I",data)[0]
    elif(dlen == 5):
        return struct.unpack(">I",data[1:])[0]
    else:
        print("WARN: Intval, unknown length %d" % dlen)
        return 0

#Encoding
def encode_strval(val):
    return val.encode("ascii")+b"\x00"


def encode_intval(val):
    # First - Deal with the Value
    bval = b""

    if (val <= 0xFF):
        bval = struct.pack("B",val)
    elif(val <= 0xFFFF):
        bval = struct.pack(">H",val)
    elif(val <= 0xFFFFFF):
        bval = struct.pack(">I",val)[1:]
    elif(val <= 0xFFFFFFFF):
        bval = struct.pack(">I",val)
    elif(val <= 0xFFFFFFFFFFFFFFFF):
        bval = struct.pack(">Q",val)
    else:
        print("Error - Unsupported Int Type")
    # Next - Deal with padding.
    if(struct.unpack("B",bval[0])[0] > 0x7F):
        bval = b"\x00"+bval

    return bval

def encode_gen_length(idata):
    idata_len = len(idata)
    if(idata_len <= 0x7F):
        return struct.pack("B",idata_len)
    elif(idata_len <= 0xFF):
        return b"\x81"+struct.pack("B",idata_len)
    elif(idata_len <= 0xFFFF):
        return b"\x82"+struct.pack(">H",idata_len)
    elif(idata_len <= 0xFFFFFFFF):
        return b"\x84"+struct.pack(">I",idata_len)

def encode_item(tag,val,vtype=None):
    if(tag > 0xFF):
        btag = struct.pack(">H",tag)
    else:
        btag = struct.pack("B",tag)
    if(vtype == 'intval'):
        bv = encode_intval(val)
    elif(vtype == 'timeval'):
        bv = b"\x00"+encode_intval(val)
    elif(vtype == 'strval'):
        bv = encode_strval(val)
    else:
        bv = val

    return btag + encode_gen_length(bv) + bv

def encode(aobj):
    pdata = b""
    for ok in aobj.keys():
        items_data = b""
        items = aobj[ok]
        for ik in items.keys():
            items_data+=encode_item(ik,items[ik]['value'],items[ik].get("type",None))
        pdata += encode_item(ok,items_data)
    return pdata

if(__name__=="__main__"):
    #test_data = binascii.unhexlify("68820188800100818201813c3f786d6c2076657273696f6e3d22312e302220656e636f64696e673d225554462d3822203f3e0a3c686173705f696e666f3e0a20203c666561747572653e0a202020203c6665617475726569643e313c2f6665617475726569643e0a202020203c6d61786c6f67696e733e756e6c696d697465643c2f6d61786c6f67696e733e0a202020203c636f6e63757272656e63793e0a2020202020203c6578706f72743e6c6f63616c3c2f6578706f72743e0a2020202020203c636f756e743e73746174696f6e3c2f636f756e743e0a202020203c2f636f6e63757272656e63793e0a202020203c766d656e61626c65643e747275653c2f766d656e61626c65643e0a202020203c63757272656e746c6f67696e733e313c2f63757272656e746c6f67696e733e0a202020203c6c6963656e73653e0a2020202020203c6c6963656e73653e70657270657475616c3c2f6c6963656e73653e0a202020203c2f6c6963656e73653e0a20203c2f666561747572653e0a3c2f686173705f696e666f3e0a00")
    import time
    rb = {}
    rb[0x65] = {
    0x80:{'value':0x110,'type':'intval'},
    0x81:{'value':int(time.time()),'type':'timeval'},
    0x82:{'value':'FUCK YOU','type':'strval'},
    0x83:{'value':b"\x00\x00"}
    }
    bdata = encode(rb)
    print(binascii.hexlify(bdata))
    rb = decode(test_data)
    print(rb)



