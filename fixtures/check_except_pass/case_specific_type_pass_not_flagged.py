try:
    os.remove(path)
except FileNotFoundError:
    pass
try:
    risky()
except (ValueError, KeyError):
    pass
try:
    risky()
except (ValueError, BaseException):
    pass
