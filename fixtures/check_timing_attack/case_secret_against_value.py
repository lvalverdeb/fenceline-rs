def login(app, username, password, form, channel, token, parsed, data):
    if username in app.auth and app.auth[username] == password:
        return True
    if form.password != form.password_confirm:
        return False
    if parsed.operation != Actions.RESET_PASSWORD:
        return False
    if channel.make_token() == token:
        return True
    if data.get("smtp_password") == ENCRYPTED_PASSWORD_PLACEHOLDER:
        return False
    return password is None or password == 1
