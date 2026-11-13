from flask import request

ROOT = "/srv/files"


@app.route("/download")
def download():
    name = request.args["name"].lstrip("/")
    return send(name)


def resolve(user_path):
    return user_path.lstrip("/")


def fixed():
    return ROOT.lstrip("/")
