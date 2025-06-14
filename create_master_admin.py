from app import app, db  # Adjust the import based on your app structure
from models import User  # Import your User model
from flask_bcrypt import Bcrypt

app.app_context().push()
bcrypt = Bcrypt(app)

# Create a master admin user
def create_master_admin():
    master_admin_email = 'admin@gmail.com'  
    master_admin_password = '12345'  
    master_admin_fullname = 'Jyotiska'  
    master_admin_department = 'Admin' 
    picture = 'static/image/1313491.jpg' 

    existing_user = User.query.filter_by(email=master_admin_email).first()
    if existing_user:
        print("Master admin user already exists.")
    else:
        hashed_password = bcrypt.generate_password_hash(master_admin_password).decode('utf-8')

        new_master_admin = User(
            full_name=master_admin_fullname,
            email=master_admin_email,
            password=hashed_password,
            is_verified=True,  
            role='master_admin',  
            department=master_admin_department,
            is_internal_user=True,
            profile_picture = picture
        )

        db.session.add(new_master_admin)
        db.session.commit()
        print("Master admin user created successfully.")

if __name__ == '__main__':
    create_master_admin()
