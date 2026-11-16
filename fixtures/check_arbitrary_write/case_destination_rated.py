import shutil

from flask import request


def save(upload):
    with open("/srv/incoming/latest.bin", "wb") as buffer:
        shutil.copyfileobj(upload.file, buffer)


def place():
    shutil.copy("/srv/incoming/latest.bin", request.args["to"])
