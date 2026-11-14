import logging

log = logging.getLogger(__name__)


def run(model_token_limit, tokeniser_name, token, path):
    log.warning(f"Prompt truncated to fit within {model_token_limit} tokens.")
    log.info("Using tokeniser %s", tokeniser_name)
    log.info("token=%s", token)
    log.info("Found a token in %s", path)
