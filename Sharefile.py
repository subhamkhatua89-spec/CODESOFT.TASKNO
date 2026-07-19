
from flask import request, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_required, current_user
from cryptography.fernet import Fernet
import os, time

from a import app

app.config['SECRET_KEY'] = 'supersecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)

# Encryption key
key = Fernet.generate_key()
cipher = Fernet(key)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(200))
    role = db.Column(db.String(20))  # "admin" or "user"

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200))
    owner_id = db.Column(db.Integer)
    encrypted_path = db.Column(db.String(200))

class TempLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer)
    token = db.Column(db.String(200))
    expires_at = db.Column(db.Integer)
@app.route('/upload', methods=['POST'])
@login_required
def upload():
    file = request.files['file']
    data = file.read()
    encrypted = cipher.encrypt(data)

    path = f"uploads/{file.filename}.enc"
    with open(path, 'wb') as f:
        f.write(encrypted)

    new_file = File(filename=file.filename, owner_id=current_user.id, encrypted_path=path)
    db.session.add(new_file)
    db.session.commit()
    return jsonify({"message": "File uploaded securely"})
@app.route('/download/<int:file_id>', methods=['GET'])
@login_required
def download(file_id):
    file = File.query.get(file_id)
    if file.owner_id != current_user.id and current_user.role != "admin":
        return jsonify({"error": "Access denied"}), 403

    with open(file.encrypted_path, 'rb') as f:
        encrypted = f.read()
    decrypted = cipher.decrypt(encrypted)

    temp_path = f"temp/{file.filename}"
    with open(temp_path, 'wb') as f:
        f.write(decrypted)

    return send_file(temp_path, as_attachment=True)
@app.route('/generate_link/<int:file_id>', methods=['POST'])
@login_required
def generate_link(file_id):
    expiry = int(time.time()) + 60  # 1 minute expiry
    token = os.urandom(16).hex()
    link = TempLink(file_id=file_id, token=token, expires_at=expiry)
    db.session.add(link)
    db.session.commit()
    return jsonify({"url": f"/temp_download/{token}"})

@app.route('/temp_download/<token>', methods=['GET'])
def temp_download(token):
    link = TempLink.query.filter_by(token=token).first()
    if not link or link.expires_at < int(time.time()):
        return jsonify({"error": "Link expired"}), 403
    return download(link.file_id)
