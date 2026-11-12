import urllib.request


def build_request(url):
    return urllib.request.Request(url)


def call_identify(user_supplied_url):
    req = build_request(user_supplied_url)
    with urllib.request.urlopen(req) as resp:
        return resp.read()
