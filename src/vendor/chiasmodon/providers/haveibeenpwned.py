import requests

class HaveIBeenPwnedProvider:
    API_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/"
    def __init__(self, api_key=None):
        self.api_key = api_key
    def search(self, email):
        headers = {"hibp-api-key": self.api_key or "", "user-agent": "1ai-osint"}
        resp = requests.get(f"{self.API_URL}{email}", headers=headers)
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 404:
            return []
        else:
            return {"error": resp.text}
