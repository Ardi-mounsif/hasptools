import HaspCore.HaspAPI as HaspAPI


if(__name__=="__main__"):
    api_db = HaspAPI.Load_Server_APIS("APIs")
    for a in api_db.keys():
        print(api_db[a])