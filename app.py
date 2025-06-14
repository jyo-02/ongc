from flask import Flask, render_template, request, redirect, session, flash, url_for, send_file
from flask_bcrypt import Bcrypt
import os
from dotenv import load_dotenv  
from models import db, User, File  
from mail_utils import init_mail, send_verification_email
import random  
from datetime import datetime  
from functools import wraps
from werkzeug.utils import secure_filename

load_dotenv()

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users2.db'
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')  
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db.init_app(app)  
bcrypt = Bcrypt(app)

init_mail(app)

image_folder = os.path.join('static', 'images')
os.makedirs(image_folder, exist_ok=True)

def role_required(*roles):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect('/login')
            user = User.query.get(session['user_id'])
            if user.role not in roles:  # Check if the user's role is in the allowed roles
                return redirect('/login')
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

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
        department = request.form['department']
        profile_image = request.files['profile_image']

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered. Please use a different email.')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        image_path = os.path.join('images', profile_image.filename)
        profile_image.save(os.path.join(image_folder, profile_image.filename))

        new_user = User(full_name=fullname, email=email, password=hashed_password, 
                        profile_image=image_path, is_verified=False, role='user', 
                        department=department)
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
    
    if not user.is_internal_user:
        return redirect(url_for('access_denied'))  # Redirect to access_denied route

    files = File.query.all()  # Fetch all uploaded files
    return render_template('pages/welcome.html', user=user, files=files)

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

@app.route('/admin/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session or not User.query.get(session['user_id']).role == 'master_admin':
        return redirect('/login')

    if request.method == 'POST':
        user_id = request.form['user_id']
        user = User.query.get(user_id)
        if user:
            user.is_verified = True
            db.session.commit()
            flash('User verified successfully.')
        else:
            flash('User not found.')

    users = User.query.all()  # Fetch all users
    return render_template('pages/admin.html', users=users)  # Render admin.html with users

@app.route('/upload', methods=['GET', 'POST'])
@role_required('group_admin', 'master_admin')
def upload_file():
    user = User.query.get(session['user_id'])  

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected')
            return redirect(request.url)
        
        file = request.files['file']
        description = request.form['description']
        print(f"Received description: {description}")  # Debug statement
        
        if file.filename == '':
            flash('No file selected')
            return redirect(request.url)
            
        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            department = request.form['department']
            if user.role == 'group_admin':
                department = user.department  

            new_file = File(
                filename=filename,
                filepath=filepath,
                uploaded_by=session['user_id'],
                department=department,
                description=description
            )
            db.session.add(new_file)
            db.session.commit()
            
            flash('File uploaded successfully')
            return redirect(url_for('upload_file'))
            
    return render_template('pages/upload.html', user=user)

@app.route('/delete/<int:file_id>', methods=['POST'])
@role_required('group_admin', 'master_admin')
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    user = User.query.get(session['user_id'])
    
    if file.uploaded_by == user.id or user.role == 'master_admin':
        try:
            os.remove(file.filepath)  
            db.session.delete(file)
            db.session.commit()
            flash('File deleted successfully')
        except Exception as e:
            flash('Error deleting file')
            return redirect(url_for('files'), 500)
    else:
        flash('Permission denied')
        return redirect(url_for('files'), 403)
        
    return redirect(url_for('welcome'))

@app.route('/admin/change_user_role', methods=['POST'])
def change_user_role():
    if 'user_id' not in session or not User.query.get(session['user_id']).role == 'master_admin':
        return redirect('/login')

    user_id = request.form['user_id']
    new_role = request.form['role']
    
    user = User.query.get(user_id)
    if user:
        user.role = new_role
        db.session.commit()
        flash('User role updated successfully.')
    else:
        flash('User not found.')

    return redirect(url_for('dashboard'))  

@app.route('/files')
def files():
    return render_template('pages/files.html')  

@app.route('/download/<int:file_id>')
def download_file(file_id):
    file = File.query.get_or_404(file_id)
    return send_file(file.filepath, as_attachment=True)  

@app.route('/admin/toggle_internal_user/<int:user_id>', methods=['POST'])
@role_required('master_admin')
def toggle_internal_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_internal_user = not user.is_internal_user  
    db.session.commit()
    flash(f'User {user.full_name} is now {"internal" if user.is_internal_user else "external"}.')
    return redirect(url_for('dashboard'))  

@app.route('/access_denied')
def access_denied():
    if 'user_id' not in session:
        return redirect('/login')

    user = User.query.get(session['user_id'])
    return render_template('pages/access_denied.html', user=user)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  
    app.run(debug=True)
