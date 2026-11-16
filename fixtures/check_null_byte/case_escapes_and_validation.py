import re


def colour(text):
    return f"\033[33m{text}\033[0m"


def reject(path):
    if "\x00" in path:
        raise ValueError(path)
    return re.sub(r"[\x00-\x1f\x7f]+", " ", path)


def poke(name):
    open(name + "\x00.txt")
    return name.split("\000")
