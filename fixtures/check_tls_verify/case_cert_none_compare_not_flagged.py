if opts["cert_reqs"] == ssl.CERT_NONE:
    pass
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ssl._create_unverified_context()
