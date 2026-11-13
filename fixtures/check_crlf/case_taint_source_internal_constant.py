from flask import request

SERVER = "fenceline/1.0"


@app.route("/echo")
def echo():
    name = request.headers.get("X-Name")
    return "X-Echo: " + name + "\r\n"


def frame(chunk):
    return f"{len(chunk):x}\r\n" + chunk


def banner():
    return "Server: " + SERVER + "\r\n"


def write_header(stream, value):
    key = value.strip()
    stream.write(f"X-Key: {key}\r\n")


class Upload(RequestHandler):
    def post(self):
        self.write("X-Value: %s\r\n" % self.get_argument("v"))
