def run(conn, table):
    stmt = f"SELECT * FROM {table}"
    conn.exec_driver_sql(stmt)
