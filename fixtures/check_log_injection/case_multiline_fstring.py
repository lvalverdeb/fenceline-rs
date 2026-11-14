import logging
import warnings

from django.http import HttpResponse

logger = logging.getLogger(__name__)


def audit(request, action):
    logger.warning(
        f"{request.user} did {action}"
    )
    logger.info("%s did %s", request.user, action)
    logger.info(f"static")
    warnings.warn(f"{action} is deprecated", DeprecationWarning, stacklevel=2)
    return HttpResponse()


def __del__(self, _warnings=warnings):
    _warnings.warn(f"Unclosed session {self!r}", ResourceWarning)


def startup(host, port):
    logger.info(f"App is listening at http://{host}:{port}")
    try:
        connect(host)
    except OSError as e:
        logger.error(f"cannot bind {host}: {e}")
