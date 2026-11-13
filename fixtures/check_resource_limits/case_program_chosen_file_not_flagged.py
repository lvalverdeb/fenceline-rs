def load(request):
    with open("/etc/app/config.toml") as f:
        config = f.read()
    key_file = open("keys/private.pem", "rb")
    key = key_file.read()
    with open(request.args["path"]) as g:
        chosen = g.read()
