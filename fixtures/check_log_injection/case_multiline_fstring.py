import warnings


def audit(logger, user, action):
    logger.warning(
        f"{user} did {action}"
    )
    logger.info("%s did %s", user, action)
    logger.info(f"static")
    warnings.warn(f"{action} is deprecated", DeprecationWarning, stacklevel=2)


def __del__(self, _warnings=warnings):
    _warnings.warn(f"Unclosed session {self!r}", ResourceWarning)
