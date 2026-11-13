import random

api_key = "".join(random.choices(chars, k=16))
key = str(random.getrandbits(2048)).encode()
secure = secrets.choice(chars)
