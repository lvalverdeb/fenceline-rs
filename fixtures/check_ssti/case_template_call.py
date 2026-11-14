from flask import request
from jinja2 import Template


@app.route("/t")
def view():
    return Template(request.args["tpl"]).render()


tpl = Template(user_input)
