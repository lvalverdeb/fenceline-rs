from django.utils.safestring import mark_safe
from markupsafe import Markup
from flask import request


def django_view(request):
    return mark_safe("<b>" + request.GET["name"] + "</b>")


@app.route("/hello")
def flask_view():
    return Markup(request.args["name"])


def helper(text):
    return mark_safe(text)


def fixed():
    return mark_safe("<hr>")
