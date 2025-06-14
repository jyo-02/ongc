from flask import Flask, render_template, request, redirect, session, flash, url_for
from flask_bcrypt import Bcrypt
import os
from dotenv import load_dotenv  
from models import db, User  
from mail_utils import init_mail, send_verification_email
import random  
from datetime import datetime  

load_dotenv()

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')  

db.init_app(app)  
bcrypt = Bcrypt(app)

init_mail(app)

image_folder = os.path.join('static', 'images')
os.makedirs(image_folder, exist_ok=True)


# Routes
@app.route("/")
def index():
    return render_template("pages/index.html", current_year=datetime.now().year)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        fullname = request.form['fullname']
        email = request.form['email']
        password = request.form['password']
        profile_image = request.files['profile_image']

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered. Please use a different email.')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        image_path = os.path.join('images', profile_image.filename)
        profile_image.save(os.path.join(image_folder, profile_image.filename))

        new_user = User(full_name=fullname, email=email, password=hashed_password, profile_image=image_path)
        db.session.add(new_user)
        db.session.commit()

        otp = random.randint(100000, 999999)  
        session['otp'] = otp  
        session['user_id'] = new_user.id  
        send_verification_email(email, otp)  

        flash('Registration successful! Please check your email for the OTP to verify your account.')
        return redirect(url_for('verify_otp'))  
    return render_template('pages/register.html') 

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            if not user.is_verified:
                flash('Please verify your email before logging in.')
                return redirect('/login')
            session['user_id'] = user.id
            return redirect('/welcome')
        flash('Login failed. Check your email and password.')
    return render_template('pages/login.html') 

@app.route('/welcome')
def welcome():
    if 'user_id' not in session:
        return redirect('/login')
    user = User.query.get(session['user_id'])
    return render_template('pages/welcome.html', user=user)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect('/login')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form['otp']
        user_id = session.get('user_id') 
        user = User.query.get(user_id)  

        if str(session.get('otp')) == entered_otp:  
            user.is_verified = True  
            db.session.commit()  
            flash('OTP verified successfully! You can now log in.')
            return redirect(url_for('login'))  
        else:
            flash('Invalid OTP. Please try again.')
    return render_template('pages/verify_otp.html')  

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            otp = random.randint(100000, 999999)
            session['otp'] = otp  
            session['user_id'] = user.id  

            send_verification_email(email, otp)  

            flash('An OTP has been sent to your email for verification.')
            return redirect(url_for('verify_forgot_password_otp'))  
        else:
            flash('Email not found.')
    return render_template('pages/forgot_password.html')  

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        new_password = request.form['new_password']
        user_id = session.get('user_id')
        user = User.query.get(user_id)

        if user:
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user.password = hashed_password
            db.session.commit()
            flash('Your password has been reset successfully. You can now log in.')
            return redirect('/login')
    return render_template('pages/reset_password.html')  

@app.route('/verify_forgot_password_otp', methods=['GET', 'POST'])
def verify_forgot_password_otp():
    if request.method == 'POST':
        entered_otp = request.form['otp']
        user_id = session.get('user_id')  
        user = User.query.get(user_id)  

        if str(session.get('otp')) == entered_otp:  
            flash('OTP verified successfully! You can now reset your password.')
            return redirect(url_for('reset_password')) 
        else:
            flash('Invalid OTP. Please try again.')
    return render_template('pages/verify_otp.html')  

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  
    app.run(debug=True)
