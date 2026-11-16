from mlflow.gateway import query


def run(route, data, store):
    a = query(route, data)
    b = Client().query(route, data)
    c = store["files"].query(Drop(tables=[route]))
    d = query(route=route, data=data)
    return a, b, c, d
