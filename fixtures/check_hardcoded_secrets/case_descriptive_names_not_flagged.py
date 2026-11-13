password_field = "password"
token_type = "Bearer"
auth_header = "X-Auth-Token"
PASSWORD = ""
SECRET_COOKIE_KEY = "PYGOAT"
ACCESS_KEY = "AWS_ACCESS_KEY_ID"
_TOKEN_TTL = "21600"
message = "Invalid username or password. Please try again."
template = "token={token}"
fields = {"password": forms.CharField(), "secret": None}
aliases = {"secretsmanager": "secrets-manager"}
if "close" in conn_tokens:
    pass
if token != "None":
    pass
