from flask import send_file, send_from_directory, request
from starlette.responses import FileResponse


@app.route("/dl")
def download():
    return send_file(request.args["path"])


@app.route("/safe")
def safe():
    return send_from_directory(UPLOADS, request.args["name"])


def internal(path):
    return FileResponse(path)


def fixed():
    return send_file("static/manual.pdf")
