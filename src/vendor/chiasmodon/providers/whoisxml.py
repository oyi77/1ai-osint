import requests

class WhoisXMLProvider:
    API_URL = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
    def __init__(self, api_key=None):
        self.api_key = api_key
    def search(self, domain):
        params = {"apiKey": self.api_key, "domainName": domain, "outputFormat": "JSON"}
        resp = requests.get(self.API_URL, params=params)
        if resp.status_code == 200:
            return resp.json()
        else:
            return {"error": resp.text}
