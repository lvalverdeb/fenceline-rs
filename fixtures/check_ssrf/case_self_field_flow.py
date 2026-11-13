import requests
from tornado.web import RequestHandler


class Fetcher:
    def __init__(self, url):
        self.url = url
        self.base = "https://api.example.com"

    def run(self):
        requests.get(self.url)
        requests.get(self.base)


class Proxy(RequestHandler):
    def prepare(self):
        self.target = self.get_argument("u")

    def helper(self):
        requests.get(self.target)
        requests.get(self.unknown)
