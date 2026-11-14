import hashlib


def check(self, password, email, code_half):
    if self.pwd_hash == hashlib.md5(password.encode()).hexdigest():
        return True
    token = hashlib.md5(f"{email}:{now()}".encode()).hexdigest()
    bucket = hashlib.sha1(code_half.encode()).hexdigest()
    hashed = hashlib.sha1(salted_encoded).hexdigest()
    return token, bucket, hashed
