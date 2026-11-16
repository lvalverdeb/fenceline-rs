import traceback

from flask import Response


def handler():
    try:
        work()
    except Exception:
        traceback.print_exc()
        return Response(traceback.format_exc(), status=500)


def quiet():
    try:
        work()
    except Exception:
        text = traceback.format_exc()
        logger.error(text)
