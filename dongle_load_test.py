import HaspCore.HaspDongle as HaspDongle

if(__name__=="__main__"):
    ddb = HaspDongle.LoadDongles("Dongles")
    for dk in ddb.keys():
        print(ddb[dk])