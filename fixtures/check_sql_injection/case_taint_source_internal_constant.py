from flask import request

TABLE = "users"


@app.route("/user")
def user():
    cursor.execute("SELECT * FROM users WHERE id = " + request.args["id"])


def by_id(cursor, user_id):
    cursor.execute(f"SELECT * FROM {TABLE} WHERE id = {user_id}")


def count(cursor):
    cursor.execute(f"SELECT count(*) FROM {TABLE}")
