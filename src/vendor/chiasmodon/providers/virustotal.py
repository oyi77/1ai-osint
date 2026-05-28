import requests

class VirusTotalProvider:
    API_URL = "https://www.virustotal.com/api/v3/urls/"
    def __init__(self, api_key=None):
        self.api_key = api_key
    def search(self, url):
        headers = {"x-apikey": self.api_key or ""}
        resp = requests.get(f"{self.API_URL}{url}", headers=headers)
        if resp.status_code == 200:
            return resp.json()
        else:
            return {"error": resp.text}
