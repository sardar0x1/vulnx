from app import db, login
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

@login.user_loader
def load_user(id):
    return User.query.get(int(id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    assets = db.relationship('Asset', backref='owner', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class Asset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(128), index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    scans = db.relationship('Scan', backref='asset', lazy='dynamic')

    def __repr__(self):
        return f'<Asset {self.domain}>'

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'))
    status = db.Column(db.String(64), default='PENDING') # PENDING, RUNNING, COMPLETED, FAILED
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy='dynamic')

    def __repr__(self):
        return f'<Scan {self.id} for Asset {self.asset_id}>'

class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'))
    name = db.Column(db.String(255))
    severity = db.Column(db.String(64))
    url = db.Column(db.Text)
    ai_summary = db.Column(db.Text, nullable=True)
    ai_mitigation = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f'<Vulnerability {self.name}>'