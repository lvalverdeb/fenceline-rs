etag = hashlib.md5(data, usedforsecurity=False)
digest = hashlib.md5(data)
h = hashlib.new("SHA1", data)
ok = hashlib.new("sha256", data)
