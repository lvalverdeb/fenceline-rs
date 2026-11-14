from flask import request
from markupsafe import Markup, escape
from urllib.parse import urlencode


def highlight(text, before, matched, after, params, value):
    a = Markup(escape(text))
    b = Markup(f"{escape(before)}<mark>{escape(matched)}</mark>{escape(after)}")
    escaped = escape(value)
    c = mark_safe(escaped)
    d = mark_safe("?" + urlencode(params))
    e = Markup(text)
    return a, b, c, d, e


@app.route("/x")
def view():
    return mark_safe(request.args["x"])
