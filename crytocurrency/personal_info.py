import os


class GetInfo:
    access_key, secret_key, server_url = ''

    def __init__(self):
        access_key = os.environ['UPBIT_OPEN_API_ACCESS_KEY']
        secret_key = os.environ['UPBIT_OPEN_API_SECRET_KEY']
        server_url = os.environ['UPBIT_OPEN_API_SERVER_URL']

    def getAccessKey(self):
        return self.access_key

    def getSecretKey(self):
        return self.secret_key

    def getServerURL(self):
        return self.server_url

    pass
