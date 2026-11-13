import re
from flask import request, abort

ALLOWED = ("users", "orders")


@app.route("/a")
def membership_guard_then_abort():
    table = request.args["t"]
    if table not in ALLOWED:
        abort(400)
    cursor.execute(f"SELECT * FROM {table}")


@app.route("/b")
def membership_guard_body_only():
    table = request.args["t"]
    if table in ALLOWED:
        cursor.execute(f"SELECT * FROM {table}")
    cursor.execute(f"SELECT * FROM {table}")


@app.route("/c")
def assert_and_regex():
    col = request.args["c"]
    assert col in ALLOWED
    cursor.execute("SELECT " + col)
    other = request.args["o"]
    if not re.fullmatch(r"[a-z_]+", other):
        return "bad"
    cursor.execute("SELECT " + other)


@app.route("/d")
def tainted_container_is_no_guard():
    col = request.args["c"]
    if col not in request.args.getlist("allowed"):
        return "bad"
    cursor.execute("SELECT " + col)


@app.route("/e")
def reassignment_cancels_guard():
    col = request.args["c"]
    if col not in ALLOWED:
        return "bad"
    col = request.args["other"]
    cursor.execute("SELECT " + col)


@app.route("/f")
def guard_without_exit_does_not_hold():
    col = request.args["c"]
    if col not in ALLOWED:
        log("bad")
    cursor.execute("SELECT " + col)
