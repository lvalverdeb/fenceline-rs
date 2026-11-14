from hashlib import md5

digest = md5(data)
password_hash = md5(password.encode())
