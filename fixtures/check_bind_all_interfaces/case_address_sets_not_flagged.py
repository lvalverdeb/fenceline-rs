WILDCARDS = frozenset({"0.0.0.0", "::"})
ALLOWED_HOSTS = ["localhost", "0.0.0.0"]
if host == "0.0.0.0":
    pass
HOST = "0.0.0.0"
app.run(host="0.0.0.0", port=8000)
sock.bind(("0.0.0.0", 8080))
DEFAULT_BIND = ["0.0.0.0", "::"] if has_ipv6 else ["0.0.0.0"]
