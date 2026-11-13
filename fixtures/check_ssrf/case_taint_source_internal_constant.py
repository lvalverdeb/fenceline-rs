import os
import requests

BASE = "http://127.0.0.1:8000"


@app.get("/proxy")
def proxy(target: str):
    return requests.get(target)


def fetch(path):
    return requests.get(BASE + path)


def from_env():
    return requests.get(os.environ["UPSTREAM"])


def fixed():
    return requests.get(BASE + "/health")
