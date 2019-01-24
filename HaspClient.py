import HaspCore.HaspSocket as HaspSocket
import HaspCore.HaspConst as HaspConst
from HaspCore.HaspAPI import  *
import HaspCore.HaspAPI
import binascii

def test_login_logout(hc):
    print("Login/Logout Test...")
    status,hH = hc.login(1)
    if(status != 0):
        print("Login Fail: %04X\n" % status)
        return False

    status = hc.logout(hH)
    if(status != 0):
        print("Logout Fail: %04X\n" % status)
        return False

    print("Login/Logout Test OK!")
    return True

def test_encrypt_decrypt(hc,test_data):
    status,hH = hc.login(1)
    if(status != 0):
        print("Login Fail: %04X" % status)
        return False

    print("Test %d Byte EncDec..." % len(test_data))
    status,enc_data = hc.encrypt(hH,test_data)
    if(status != 0):
        print("Encrypt Failed: %04X" % status)
        return False
    print("Encrypted Data: %s" % binascii.hexlify(enc_data))
    status,dec_data = hc.decrypt(hH,enc_data)
    if(status != 0):
        print("Decrypt Failed: %04X" % status)
        return False
    print("Decrypted Data: %s" % binascii.hexlify(dec_data))
    if(test_data != dec_data):
        print("ENC/DEC Mismatch!")
        print("Original Data: %s" % binascii.hexlify(test_data))
        print("Dec Data: %s" % binascii.hexlify(dec_data))
        return False
    else:
        print("Enc/Dec OP OK!")

    print("Encrypt Decrypt Test OK!")
    hc.logout(hH)
    return True

def test_read_write(hc):
    print("Test Write/Read...")
    test_data = "ALL HAIL KING GREGORY!!!"
    status,hH = hc.login(1)
    if(status != 0):
        print("Login Fail: %04X" % status)
        return False

    status = hc.write(hH,HaspConst.HASP_FILEID_RW,0,test_data)
    if(status != 0):
        print("Write Fail: %04X" % status)
        hc.logout(hH)
        return False
    status,rdata = hc.read(hH,HaspConst.HASP_FILEID_RW,0,len(test_data))
    if(status != 0):
        print("Read Fail: %04X" % status)
        hc.logout(hH)
        return False
    if(rdata != test_data):
        print("Write/Read Mismatch!")
        hc.logout(hH)
        return False

    hc.logout(hH)
    print("Write/Read OK!")
    return True


def test_rtc(hc):
    print("Test Get RTC...")
    status,hH = hc.login(1)
    if(status != 0):
        print("Login Fail: %04X" % status)
        return False
    status,rtcts = hc.get_rtc(hH)
    if(status !=0):
        print("Get RTC Fail: %04X" % status)
        hc.logout(hH)
        return False

    hc.logout(hH)
    print("RTC Test Complete")

def test_get_size(hc,file_id):
    print("Test Get Size...")
    status,hH = hc.login(1)
    if(status != 0):
        print("Login Fail: %04X" % status)
        return False
    status,f_size = hc.get_size(hH,file_id)
    if(status !=0):
        print("Get Size Fail: %04X" % status)
        hc.logout(hH)
        return False
    else:
        print("Size of File ID %04X is %d bytes." % (file_id,f_size))
    hc.logout(hH)
    print("Get Size Test Complete")

def test_get_info(hc,scope,format):
    status,info = hc.get_info(scope,format)
    if(status != 0):
        print("Get Info Error: %04X" % status)
        return False
    print("Get Info OK!")
    print(info)
    return True

def test_get_session_info(hc,scope,format):
    status,hH = hc.login(1)
    if(status != 0):
        print("Login Fail: %04X" % status)
        return False

    status,info = hc.get_session_info(hH,scope % hH,format)
    if(status !=0):
        print("Get Session Info Failed: %04X" % status)
        hc.logout(hH)
        return False
    print("Get Session Info OK!")
    print(info)
    return True

def test_login_scope(hc):
    scope = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><haspscope><hasp type=\"HASP-HL\"><license_manager ip=\"127.0.0.1\" /></hasp></haspscope>"
    status,hH = hc.login_scope(1,scope)
    if(status != 0):
        print("Login Scope Failed: %04X" % status)
        return False
    print("Login Scope OK!")
    hc.logout(hH)
    return True

if(__name__=="__main__"):
    sock = HaspSocket.HaspSocketClient()
    hc = HaspCore.HaspAPI.HaspAPIClient("APIs/92684.json",sock)
    #test_login_logout(hc)
    #test_read_write(hc)
    #test_rtc(hc)
    #test_get_size(hc,HaspConst.HASP_FILEID_RW)
    #test_get_info(hc,HaspConst.SCOPE_LM,HaspConst.FORMAT_GETID)
    #test_get_info(hc, HaspConst.SCOPE_LM, HaspConst.FORMAT_GETKEYINFO)
    #test_get_session_info(hc,HaspConst.SCOPE_HANDLE,HaspConst.FORMAT_GETSESSION)
    #test_login_scope(hc)
    test_data_16 = b"\x00" * 64
    test_encrypt_decrypt(hc,test_data_16)