import os
import platform

import requests

VERSION = "0.2"
machine = platform.machine()
if machine == "x86_64":
    machine = "amd64"
BINARY_REMOTE_NAME = f"frpc_{platform.system().lower()}_{machine.lower()}"
EXTENSION = ".exe" if os.name == "nt" else ""
BINARY_URL = f"https://cdn.example.com/frpc-{VERSION}/{BINARY_REMOTE_NAME}{EXTENSION}"


class Tunnel:
    @staticmethod
    def download_binary():
        return requests.get(BINARY_URL, timeout=30)


def fetch(request):
    return requests.get(f"{BINARY_URL}/{request.args['v']}", timeout=30)
