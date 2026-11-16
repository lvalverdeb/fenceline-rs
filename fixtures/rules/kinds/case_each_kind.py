import os
import tempfile

import requests as rq
import torch
from flask import request
from mako.template import Template as T


def view(url, path, ctx):
    T(request.args["tpl"])
    T("hello")
    T(text=request.args["tpl"])
    T(ctx)
    render(ctx, request.args["t"])
    render(request.args["t"])
    render(ctx, text=request.args["t"])
    name = tempfile.mktemp()
    rq.get(url, verify=False)
    rq.get(url, timeout=3)
    rq.post(url, verify=0)
    torch.load(path)
    torch.load(path, weights_only=True)
    torch.load(path, weights_only=False)
    os.symlink(path, name)
    # os.symlink(path, name) in a comment is masked
    """os.symlink(path, name) in a docstring is masked"""
    return name
