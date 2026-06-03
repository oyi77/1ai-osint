import requests


class AbuseIPDBProvider:
    API_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key=None):
        self.api_key = api_key

    def search(self, ip):
        headers = {"Key": self.api_key or "", "Accept": "application/json"}
        params = {"ipAddress": ip}
        resp = requests.get(self.API_URL, headers=headers, params=params)
        if resp.status_code == 200:
            return resp.json()
        else:
            return {"error": resp.text}
