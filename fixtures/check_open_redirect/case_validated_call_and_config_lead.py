from flask import redirect, request


def login(app):
    if request.args.get("next") and is_safe_url(request.args.get("next")):
        return redirect(request.args.get("next"))
    return redirect(request.args.get("next"))


def force_root(app):
    application_root = app.config.get("APPLICATION_ROOT")
    return redirect(application_root + request.script_root + request.full_path)


def jump(app):
    base = app.config.get("BASE")
    return redirect(base + request.args["next"])


def scheme(app):
    return redirect("https://" + request.args["host"])
