import os

from flask import render_template, request, send_file
from werkzeug.utils import safe_join

ROOT = "/srv/files"


def download(filename):
    return send_file(safe_join(ROOT, filename), as_attachment=True)


def theme_static(theme, path):
    for cand in (safe_join(ROOT, t, "static", path) for t in (theme, "core")):
        if cand is not None and os.path.isfile(cand):
            return send_file(cand, max_age=3600)
    return None


def plugin_template(plugin_class):
    return render_template(plugin_class.templates["view"].lstrip("/"))


def user_template():
    return render_template(request.args["t"].lstrip("/"))
