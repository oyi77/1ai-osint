import requests


class WaybackProvider:
    API_URL = "http://archive.org/wayback/available?url={}"

    def search(self, url):
        resp = requests.get(self.API_URL.format(url))
        if resp.status_code == 200:
            return resp.json()
        else:
            return {"error": resp.text}
