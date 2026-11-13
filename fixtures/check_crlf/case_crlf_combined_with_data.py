header = "X-Name: " + name + "\r\n"
line = "%s: %s\r\n" % (key, value)
chunk = f"{len(body):x}\r\n"
status = "HTTP/1.1 {} OK\r\n".format(code)
delim = b"\r\n"
parts = data.split(b"\r\n")
if tail == b"\r\n":
    pass
fixed = "A: 1\r\n" + "B: 2\r\n"
