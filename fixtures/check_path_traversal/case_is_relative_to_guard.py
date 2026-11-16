from pathlib import Path

from flask import request, send_file

ROOT = Path("/srv/files")


def download():
    target = (ROOT / request.args["name"]).resolve()
    if not target.is_relative_to(ROOT.resolve()):
        raise ValueError("outside the root")
    return send_file(target)


def unchecked():
    target = (ROOT / request.args["name"]).resolve()
    return send_file(target)
