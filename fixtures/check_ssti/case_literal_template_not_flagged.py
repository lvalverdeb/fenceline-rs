from flask import request
tpl = Template("Hello {{ name }}")
other = jinja2.Template("<b>{{ x }}</b>", autoescape=True)
risky = jinja2.Template(request.args["t"])
