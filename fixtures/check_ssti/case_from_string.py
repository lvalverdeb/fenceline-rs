import jinja2
from flask import request

env = jinja2.Environment()


@app.route("/render")
def render():
    return env.from_string(request.args["tpl"]).render()


def fixed():
    return env.from_string("Hello {{ name }}").render(name="x")
