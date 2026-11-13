import os


def analyze(conn, table):
    conn.exec_driver_sql(f"ANALYZE {table}")


def from_env(conn):
    conn.exec_driver_sql(f"SET search_path TO {os.environ['SCHEMA']}")
