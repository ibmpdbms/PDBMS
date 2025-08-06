# INSERT INTO users (username, hash, role, uuid, email, phone_number)
# VALUES ('admin', 'scrypt:32768:8:1$ViikOqGxeHKH5t6H$ac20f21af1cabd0b08ba2f79926be03601e6360c8fc6e132c34bcd9fb7752ba5dd7ea01c9a13200f39eea0f33b76bd4255f72aeda3713a4f46b9fc4d319db903', 'admin', 'ADMIN123', 'admin@example.com', '9999999999');

from werkzeug.security import generate_password_hash
print(generate_password_hash("admin"))
