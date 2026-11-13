import os
import shlex
import subprocess
import sys

subprocess.run(["git", "status"], check=True)
subprocess.Popen([sys.executable, "-m", "pip", "list"])
os.system("ls -la")


def run_hook(name):
    subprocess.run(["sh", "-c", name], shell=True)


def run_quoted(name):
    subprocess.run("echo " + shlex.quote(name), shell=True)


def from_environment():
    os.system(os.environ["HOOK_CMD"])


@router.post("/run")
async def run_endpoint(cmd: str):
    return subprocess.check_output(cmd, shell=True)
