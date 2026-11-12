"""Module docstring that quotes os.system("rm -rf /") as an example."""
import subprocess


def run(cmd):
    """Runs a command.

    Example::

        subprocess.run(cmd, shell=True)
    """
    # subprocess.Popen(cmd) was the old way
    'os.popen(cmd) -- a bare string used as a block comment'
    return subprocess.run(cmd)  # shell=True would be worse
