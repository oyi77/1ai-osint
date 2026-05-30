import re
import time
import requests

VERSION = "3.0.2"
_API_URL = "http://chiasmodon.online/v2/api/beta"
_API_HEADERS = {"user-agent": "cli/python"}
_VIEW_TYPE = {
    "full": [
        "cred.username",
        "cred.phone",
        "cred.password",
        "cred.email",
        "cred.email.domain",
        "cred.country",
        "domain",
        "domain.all",
        "ip",
        "ip.asn",
        "ip.isp",
        "ip.org",
        "ip.port",
        "ip.country",
        "app.id",
        "app.name",
        "app.domain",
        "url.path",
        "url.port",
    ],
    "cred": [
        "cred.phone",
        "cred.username",
        "cred.password",
        "cred.email",
        "cred.email.domain",
        "cred.country",
        "domain",
        "domain.all",
        "ip",
        "ip.asn",
        "ip.isp",
        "ip.org",
        "ip.port",
        "ip.country",
        "app.id",
        "app.name",
        "app.domain",
        "url.path",
        "url.port",
    ],
    "url": [
        "cred.username",
        "cred.password",
        "cred.phone",
        "cred.email",
        "cred.email.domain",
        "cred.country",
        "domain",
        "domain.all",
        "ip",
        "ip.asn",
        "ip.isp",
        "ip.org",
        "ip.port",
        "ip.country",
        "url.path",
        "url.port",
    ],
    "email": [
        "cred.username",
        "cred.phone",
        "cred.password",
        "cred.country",
        "cred.email.domain",
        "domain",
        "domain.all",
        "ip",
        "ip.asn",
        "ip.isp",
        "ip.org",
        "ip.port",
        "ip.country",
        "app.id",
        "app.name",
        "app.domain",
        "url.path",
        "url.port",
    ],
    "phone": [
        "cred.username",
        "cred.email",
        "cred.email.domain",
        "domain",
        "domain.all",
        "ip",
        "ip.asn",
        "ip.isp",
        "ip.org",
        "ip.port",
        "ip.country",
        "app.id",
        "app.name",
        "app.domain",
        "url.path",
        "url.port",
        "cred.country",
    ],
    "password": [
        "cred.username",
        "cred.phone",
        "cred.email",
        "cred.email.domain",
        "domain",
        "domain.all",
        "ip",
        "ip.asn",
        "ip.isp",
        "ip.org",
        "ip.port",
        "ip.country",
        "app.id",
        "app.name",
        "app.domain",
        "url.path",
        "url.port",
        "cred.country",
    ],
    "username": [
        "cred.phone",
        "cred.password",
        "domain",
        "domain.all",
        "ip",
        "ip.asn",
        "ip.isp",
        "ip.org",
        "ip.port",
        "ip.country",
        "app.id",
        "app.name",
        "app.domain",
        "url.path",
        "url.port",
        "cred.country",
    ],
    "app": [
        "cred.phone",
        "cred.username",
        "cred.password",
        "cred.email",
        "cred.email.domain",
        "cred.country",
        "app.domain",
    ],
    "domain": [
        "cred.username",
        "cred.phone",
        "cred.password",
        "cred.email",
        "cred.email.domain",
        "cred.country",
        "domain",
        "domain.all",
        "ip",
        "ip.asn",
        "ip.isp",
        "ip.org",
        "ip.port",
        "ip.country",
        "app.id",
        "app.name",
        "app.domain",
        "url.path",
        "url.port",
    ],
    "ip": [
        "cred.username",
        "cred.phone",
        "cred.password",
        "cred.email",
        "cred.email.domain",
        "domain",
        "domain.all",
        "ip.asn",
        "ip.isp",
        "ip.org",
        "ip.port",
        "ip.country",
        "app.id",
        "app.name",
        "app.domain",
        "url.path",
        "url.port",
        "cred.country",
    ],
    "related": [
        "domain",
    ],
    "subdomain": ["domain"],
}

_METHODS = [
    "cred.username",
    "cred.password",
    "cred.email",
    "cred.phone",
    "cred.email.domain",
    "cred.country",
    "domain",
    "domain.all",
    "ip",
    "ip.asn",
    "ip.isp",
    "ip.org",
    "ip.port",
    "ip.country",
    "app.id",
    "app.name",
    "app.domain",
    "url.path",
    "url.port",
]

VIEW_TYPE_LIST = list(_VIEW_TYPE.keys())


class Chiasmodon:
    def __init__(
        self, token=None, color=True, debug=True, conf_file=None, check_token=True
    ) -> None:
        self.token = token
        self.conf_file = conf_file
        self.debug = debug
        self.err: bool = False
        self.msg: str = ""
        self.__result: list = []
        self.scan_mode = False

    def filter(self, query: str, method: str):
        if "domain" in method:
            if not re.match(
                r"^(?!.*\d+\.\d+\.\d+\.\d+$)[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", query
            ):
                return False
        elif method == "ip":
            if not re.match(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", query):
                return False
        elif method == "cred.email":
            if not re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", query):
                return False
        return query

    def __request(self, data: dict, timeout=60):
        try:
            resp = requests.post(
                _API_URL, data=data, headers=_API_HEADERS, timeout=timeout
            )
            resp.close()
            resp = resp.json()
            try:
                if resp.get("err"):
                    self.err = True
                    self.msg = resp["msg"]
            except Exception:
                pass
            return resp
        except Exception as e:
            self.print(f"Request error: {e}")
            return {}

    def __proc_query(
        self,
        method: str,
        query: str,
        view_type: str,
        timeout: int,
        sort: bool,
        limit: int,
        callback_view_result=None,
        **kwargs,
    ) -> list:
        result = []
        data = {
            "token": self.token,
            "type-view": view_type,
            "method": method,
            "version": VERSION,
            "query": query,
            "get-info": "yes",
        }
        process_info = self.__request(data=data, timeout=timeout)
        if not process_info or process_info.get("count") == 0:
            return result
        if self.err:
            self.err = False
            return result
        del data["get-info"]
        data["sid"] = process_info["sid"]
        for p in range(1, process_info.get("pages", 1) + 1):
            data["page"] = p
            beta_result = self.__request(data=data, timeout=timeout)
            if self.err:
                self.err = False
                return result
            for r in beta_result.get("data", []):
                result.append(r)
                if len(result) == limit:
                    return result
            if beta_result.get("done"):
                return result
            time.sleep(1)
        return result

    def search(
        self,
        query,
        method="domain",
        view_type="full",
        limit=10000,
        timeout=60,
        sort=True,
        **kwargs,
    ) -> list:
        if method not in _METHODS:
            raise Exception(f"not found this method: {method}")
        if method not in _VIEW_TYPE.get(view_type, []):
            raise Exception(f"{view_type} doesn't support ({method})")
        self.err = False
        self.msg = ""
        query = self.filter(query, method)
        if query is False:
            return []
        result = self.__proc_query(
            query=query,
            method=method,
            view_type=view_type,
            sort=sort,
            timeout=timeout,
            limit=limit,
        )
        self.__result = []
        return result

    def print(self, text, **kwargs):
        if text and self.debug:
            print(text)
