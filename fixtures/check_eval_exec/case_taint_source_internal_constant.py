import sys
from flask import request

exec("print('hello')")
compile("x = 1", "<string>", "exec")


def load(source):
    return compile(source, "<string>", "exec")


def plugin():
    return __import__(sys.argv[1])


@app.get("/calc")
def calc():
    return str(eval(request.args["expr"]))
