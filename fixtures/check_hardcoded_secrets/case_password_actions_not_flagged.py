RATELIMITS = {
    "change_password": "1/m/user",
    "reset_password": "1/m/ip,1/m/key",
}
URLS = {"account_reset_password": "/account/password-reset"}
admin_password_file = "/run/secrets/admin"
admin_password = "/etc/secrets/admin"
db_password = "hunter2hunter2"
