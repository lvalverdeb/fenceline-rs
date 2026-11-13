import pandas as pd
from flask import request


@app.route("/filter")
def filter_rows(df):
    return df.query(request.args["q"])


def narrow(df, expr):
    return df.eval(expr)


def fixed(df):
    return df.query("a > 1")


async def lookup(resolver, host):
    return await resolver.query(host, "A")
