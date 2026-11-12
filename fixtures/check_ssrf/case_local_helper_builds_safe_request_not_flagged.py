import urllib.request

BASE = "http://127.0.0.1:8000"


def build_request(base, path):
    return urllib.request.Request(base + path)


def call_identify():
    req = build_request(BASE, "/identify")
    with urllib.request.urlopen(req) as resp:
        return resp.read()
