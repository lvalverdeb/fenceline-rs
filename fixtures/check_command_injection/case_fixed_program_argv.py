import subprocess
import sys
from flask import request


def compile_translations(folder, program, args):
    subprocess.call(["pybabel", "compile", "-d", folder])
    subprocess.run([sys.executable, "-m", "flaskbb", *args], check=True)
    subprocess.run([program, "--version"])
    subprocess.call(["ls", folder], shell=True)


@app.route("/ping")
def ping():
    subprocess.run(["ping", "-c", "1", request.args["host"]])
