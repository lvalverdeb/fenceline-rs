async def fetch(user_url):
    async with httpx.AsyncClient() as client:
        return await client.get(user_url)
