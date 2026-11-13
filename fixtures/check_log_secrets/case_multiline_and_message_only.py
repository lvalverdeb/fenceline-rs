import logging
import warnings

logger = logging.getLogger(__name__)


def refresh(token, user, path):
    logger.info(
        "refreshing for %s",
        user,
        token,
    )
    logger.debug(
        "Retrieved credentials will expire at: %s", expiry
    )
    logger.info("user %s logged in", user)
    logging.getLogger("audit").warning("password rotated for %s", user)
    logger.debug("Credentials need to be refreshed.")
    warnings.warn("The 'auth' parameter is deprecated; pass %s" % path)
