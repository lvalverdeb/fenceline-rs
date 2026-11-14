import random
import string


def schedule(servers, items):
    delay = random.randint(0, 120)
    server = random.choice(servers)
    random.shuffle(items)
    jitter = random.random() / 1000000
    otp = str(random.randint(100, 999))
    code = "".join(random.choices(string.ascii_letters, k=16))
    chars = string.ascii_lowercase + string.digits
    api = "".join(random.choices(chars, k=16))
    key = str(random.getrandbits(2048)).encode()
    return delay, server, jitter, otp, code, api, key


def challenge(length):
    field = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.sample(field, length))
