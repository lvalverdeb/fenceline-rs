import httpx
import requests
from flask import request

client = httpx.AsyncClient()


def fixed_target():
    return requests.request(request.method, "https://api.example.com/health")


def relay():
    return requests.request("GET", request.args["u"])


def through_session(session, url):
    return session.request("GET", url)


def proxy():
    return client.build_request("GET", request.args["u"], headers={})


def helper(http):
    return http.request(method="GET", url=request.args["u"])


def orm(session, pk):
    return session.get(Model, pk)
