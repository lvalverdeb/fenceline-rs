async def create(conn, name):
    q = ("INSERT INTO students (name) "
         "VALUES ('%(name)s')" % {'name': name})
    async with conn.cursor() as cur:
        await cur.execute(q)


def constant_only(conn):
    q = "SELECT 1"
    conn.execute(q)


def handler(request, conn):
    sql = "SELECT * FROM t WHERE id = " + request.args["id"]
    conn.execute(sql)
