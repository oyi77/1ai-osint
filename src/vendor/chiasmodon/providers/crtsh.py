import requests


class CrtShProvider:
    API_URL = "https://crt.sh/?q={}&output=json"

    def search(self, domain):
        resp = requests.get(self.API_URL.format(domain))
        if resp.status_code == 200:
            return resp.json()
        else:
            return {"error": resp.text}
