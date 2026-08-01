import requests


def fetch(user_url):
    session = requests.Session()
    return session.get(user_url)


def unrelated_orm_call(session, obj):
    # "session" here is a function parameter (e.g. a SQLAlchemy Session),
    # not a requests.Session() -- must not be treated as an HTTP client
    # just because it shares the variable name used in a different scope.
    return session.delete(obj)
