import os,struct,ctypes,platform,time,getpass,hashlib
from Crypto.Cipher import AES


import HaspDongle

def rand_bytes(num):
    return os.urandom(num)

def make_fake_handle_value():
    return struct.unpack("<I",rand_bytes(4))[0]

def xor_data(indata,key):
    indata = bytearray(indata)
    key = bytearray(key)
    outdata = bytearray(len(indata))
    for i in range(0,len(indata)):
        outdata[i] = (indata[i] ^ key[i % len(key)]) & 0xFF
    return outdata

def ripemd160(indata):
    h = hashlib.new('ripemd160')
    h.update(indata)
    return bytearray(h.digest())

def pad_data(indata,plen=16):
    extra = len(indata) % plen
    if(extra > 0):
        indata += b"\x00" * (plen-extra)
    return indata

def aes_cbc_decrypt(indata,key,iv=None):
    orig_len = len(indata)
    indata = pad_data(indata)
    if(iv == None):
        iv = "\x00" * 16
    if(len(iv) < 16):
        pad_len = 16 - len(iv)
        iv+="\x00" * pad_len

    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.decrypt(str(indata))[:orig_len]

def aes_cbc_encrypt(indata,key,iv=None):
    orig_len = len(indata)
    indata = pad_data(indata)
    if(iv == None):
        iv = "\x00" * 16
    if(len(iv) < 16):
        pad_len = 16 - len(iv)
        iv+="\x00" * pad_len

    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(str(indata))[:orig_len]


def aes_ecb_encrypt(indata,key):
    orig_len = len(indata)
    pad_amt = 16 - orig_len
    if(pad_amt > 0):
        indata+=b"\x00" * pad_amt
    aes = AES.new(key,AES.MODE_ECB)
    return aes.encrypt(indata)

def aes_ecb_decrypt(indata,key):
    aes = AES.new(key,AES.MODE_ECB)
    return aes.decrypt(indata)

def GetVolumeSerial(root="C:\\"):
    if(platform.system() == "Linux"):
        f = open("/proc/sys/kernel/random/boot_id", "r")
        id = f.read()
        f.close()
        return id
    else:
        kernel32 = ctypes.windll.kernel32
        volumeNameBuffer = ctypes.create_unicode_buffer(1024)
        fileSystemNameBuffer = ctypes.create_unicode_buffer(1024)
        serial_number = ctypes.create_string_buffer(1024)
        max_component_length = None
        file_system_flags = None

        rc = kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(root),
            volumeNameBuffer,
            ctypes.sizeof(volumeNameBuffer),
            serial_number,
            max_component_length,
            file_system_flags,
            fileSystemNameBuffer,
            ctypes.sizeof(fileSystemNameBuffer)
        )

    return struct.unpack(">I",serial_number.value)[0]

def GetScreenID():
    return "console"

def GetMachineName():
    return os.getenv('COMPUTERNAME')

def GetUserName():
    return getpass.getuser()

def GetPID():
    return ctypes.windll.Kernel32.GetCurrentProcessId()

def GetMTID():
    if(platform.system() == "Linux"):
        return 0x1234
    else:
        return ctypes.windll.Kernel32.GetCurrentThreadId()

def GetTimestamp():
    return int(time.time())


"""

"""

def LoadDongles(dongles_root):
    dongle_db = {}
    for root,dirs,files in os.walk(dongles_root):
        for d in dirs:
            dr = os.path.join(root,d)
            hd = HaspDongle.HaspDongle(dr)
            dongle_db[hd.vendor_id] = hd
            print("Loaded Dongle: %s" % hd.name)
            print(hd)
            print(" ")
        break
    return dongle_db