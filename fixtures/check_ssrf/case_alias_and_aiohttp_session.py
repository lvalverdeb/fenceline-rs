import requests as rq
import aiohttp


async def fetch(user_url, session: aiohttp.ClientSession):
    rq.get(user_url)
    async with aiohttp.ClientSession() as s:
        return await s.get(user_url)
