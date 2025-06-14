import os
import random
from flask_mail import Mail, Message

mail = Mail()

def init_mail(app):
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USE_SSL'] = False
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')  
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')  
    mail.init_app(app)

def generate_otp():
    return str(random.randint(100000, 999999))

def send_verification_email(recipient, otp):
    subject = "Email Verification OTP"
    body = f"Your OTP code for email verification is: {otp}"
    msg = Message(subject, recipients=[recipient], body=body)
    try:
        mail.send(msg)
    except Exception as e:
        print(f"Failed to send email: {e}")  # Handle the error appropriately
