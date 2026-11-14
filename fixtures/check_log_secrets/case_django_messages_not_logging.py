import logging

from django.contrib import messages
from django.contrib import messages as flash

logger = logging.getLogger(__name__)


def reset_password(request, token):
    messages.warning(request, 'Invalid password reset token')
    messages.error(request, "Token %s has expired" % token)
    flash.info(request, "Check your email for a reset token")
    logger.warning("password reset token %s rejected", token)
