from alembic import op
import sqlalchemy as sa

ROLE_NAME = "face_recognition_app"


def upgrade():
    db_name = op.get_bind().execute(sa.text("SELECT current_database()")).scalar()
    op.execute(f"GRANT CONNECT ON DATABASE {db_name} TO {ROLE_NAME}")
