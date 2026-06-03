import requests


class ShodanProvider:
    API_URL = "https://api.shodan.io/shodan/host/"

    def __init__(self, api_key=None):
        self.api_key = api_key

    def search(self, ip):
        params = {"key": self.api_key}
        resp = requests.get(f"{self.API_URL}{ip}", params=params)
        if resp.status_code == 200:
            return resp.json()
        else:
            return {"error": resp.text}
