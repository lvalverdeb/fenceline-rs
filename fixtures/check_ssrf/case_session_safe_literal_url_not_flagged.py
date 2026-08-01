import requests


def health_check():
    session = requests.Session()
    return session.get("http://127.0.0.1:8000/health")
