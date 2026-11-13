from flask import redirect, request

HOME = "/home"


@app.route("/login")
def login():
    return redirect(request.args.get("next", HOME))


def bounce(target):
    return redirect(target)


def go_home():
    return redirect(HOME)
