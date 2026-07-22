ROLE_NAME = "face_recognition_app"


def upgrade(user_id):
    op.execute(f"GRANT CONNECT ON DATABASE {user_id} TO {ROLE_NAME}")
