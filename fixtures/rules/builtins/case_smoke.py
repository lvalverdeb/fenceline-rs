import marshal
import os
import pickle

import ldap
import numpy as np
import pandas as pd
import paramiko
import requests
import torch
from django.utils.safestring import mark_safe
from flask import request


def load_all(path, url):
    pd.read_pickle(path)
    pd.read_xml(path)
    pd.read_xml(path, parser="etree")
    torch.load(path)
    torch.load(path, weights_only=True)
    np.load(path, allow_pickle=True)
    np.load(path)
    requests.get(url)
    requests.get(url, timeout=5)
    pickle.loads(path)
    marshal.loads(path)
    mark_safe(request.args["html"])
    mark_safe("<b>ok</b>")
    os.symlink(path, path + ".lnk")
    conn = ldap.initialize(url)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    return conn
