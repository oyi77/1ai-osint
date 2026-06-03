import requests


class SocialProvider:
    SOCIAL_URLS = {
        "twitter": "https://twitter.com/{}",
        "linkedin": "https://www.linkedin.com/in/{}",
        "github": "https://github.com/{}",
        "facebook": "https://facebook.com/{}",
    }

    def search(self, username):
        results = {}
        for platform, url in self.SOCIAL_URLS.items():
            resp = requests.get(url.format(username))
            results[platform] = resp.status_code == 200
        return results
