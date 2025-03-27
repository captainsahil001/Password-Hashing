from flask import Flask, request, jsonify
import bcrypt
from argon2 import PasswordHasher

app = Flask(__name__)
ph = PasswordHasher()

# Hash a password using bcrypt
def hash_password_bcrypt(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

# Verify a bcrypt password
def verify_password_bcrypt(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())

# Hash a password using Argon2
def hash_password_argon2(password):
    return ph.hash(password)

# Verify an Argon2 password
def verify_password_argon2(password, hashed):
    try:
        ph.verify(hashed, password)
        return True
    except:
        return False

@app.route('/hash', methods=['POST'])
def hash_password():
    data = request.json
    password = data.get("password")
    algo = data.get("algo", "bcrypt")  # Default to bcrypt

    if not password:
        return jsonify({"error": "Password is required"}), 400

    hashed_password = hash_password_bcrypt(password) if algo == "bcrypt" else hash_password_argon2(password)
    return jsonify({"hashed_password": hashed_password})

@app.route('/verify', methods=['POST'])
def verify_password():
    data = request.json
    password = data.get("password")
    hashed_password = data.get("hashed_password")
    algo = data.get("algo", "bcrypt")

    if not password or not hashed_password:
        return jsonify({"error": "Password and hashed password are required"}), 400

    is_valid = verify_password_bcrypt(password, hashed_password) if algo == "bcrypt" else verify_password_argon2(password, hashed_password)
    return jsonify({"valid": is_valid})

if __name__ == '__main__':
    app.run(debug=True)
