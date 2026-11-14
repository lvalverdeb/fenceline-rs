import logging

from flask import Flask, request

app = Flask(__name__)
logger = logging.getLogger(__name__)


@app.route("/login")
def login():
    user = request.args.get("user", "")
    logger.info(f"login attempt for {user}")
    logger.info("login attempt for %s", user)
    logger.info(f"login handler ready on {app.name}")
    return ""

