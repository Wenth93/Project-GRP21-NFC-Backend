import jwt
from datetime import datetime, timedelta

SECRET_KEY = "VotreCléSecrèteJWT"

def generate_jwt():
    payload = {
        "sub": "1234567890",
        "name": "John Doe",
        "email": "john.doe@example.com",
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=1),
        "role": "employee"
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token

if __name__ == "__main__":
    print(generate_jwt())
