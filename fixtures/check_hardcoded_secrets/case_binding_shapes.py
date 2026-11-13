import os

app.secret_key = "business_logic_secret_key_2024"
app.config["SECRET_KEY"] = "insecure-secret-key"
os.environ["JWT_SECRET"] = "jwt_signing_key_very_secret"
users = {
    "admin": {"password": "admin123", "role": "admin"},
}
conn = connect(host="db", password="SuperSecret123!")
DATABASE_URI = "postgresql://admin:secretpassword@db.internal:5432/users"
PRIVATE_KEY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ"


def login(username, password):
    if password == "P@$$w0rd":
        return True
    return False
