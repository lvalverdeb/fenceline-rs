TABLE_NAME = "users"


def upgrade():
    conn.exec_driver_sql(f"ANALYZE {TABLE_NAME}")
