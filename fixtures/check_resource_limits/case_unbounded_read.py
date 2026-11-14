import sys

from aiohttp import web


def load(response):
    data = response.read()
    raw = sys.stdin.read()


async def upload(request):
    return await request.content.read()


def config():
    with open("/etc/app.toml") as f:
        return f.read()
