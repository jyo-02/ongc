from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Boolean

db = SQLAlchemy()

class User(db.Model):
    id = Column(Integer, primary_key=True)
    full_name = Column(String(100))
    email = Column(String(100), unique=True)
    password = Column(String(200))
    profile_image = Column(String(200))
    is_verified = Column(Boolean, default=False)
    role = Column(String(50), default='user')
    department = Column(String(50))
    is_valid_user = Column(Boolean, default=False)

    def __repr__(self):
        return f'<User {self.full_name}>'

class File(db.Model):
    id = Column(Integer, primary_key=True)
    filename = Column(String(200))
    filepath = Column(String(500))
    uploaded_by = Column(Integer, db.ForeignKey('user.id'))
    department = Column(String(50))
    upload_date = Column(db.DateTime, default=db.func.current_timestamp())
    description = db.Column(db.String(120))
    category = db.Column(db.String(50), nullable=False)

class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(255), nullable=False)
    link = db.Column(db.String(255), nullable=True)

class LoginRecord(db.Model):
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, db.ForeignKey('user.id'))  
    action = db.Column(db.String(10))
    timestamp = Column(db.DateTime, default=db.func.current_timestamp())

    def __repr__(self):
        return f'<LoginRecord {self.id}>'
