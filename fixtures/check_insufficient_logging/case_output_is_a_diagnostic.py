from flask import abort


def disable_checks(db):
    try:
        db.query("SET FOREIGN_KEY_CHECKS=0;")
    except Exception:
        print("Failed to disable foreign key checks. Continuing.")


def auth(token):
    try:
        user = lookup(token)
    except Exception:
        abort(401, description="Invalid authorization header")
    return user


class Command:
    def handle(self):
        try:
            rebuild()
        except Exception:
            self.stdout.write("rebuild failed")


def quiet():
    try:
        configure()
    except Exception:
        cleanup()
