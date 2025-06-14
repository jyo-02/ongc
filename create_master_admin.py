from app import app, db  # Adjust the import based on your app structure
from models import User  # Import your User model
from flask_bcrypt import Bcrypt

# Initialize the app and bcrypt
app.app_context().push()
bcrypt = Bcrypt(app)

# Create a master admin user
def create_master_admin():
    # Define the master admin details
    master_admin_email = 'admin@gmail.com'  # Change to desired email
    master_admin_password = '12345'  # Change to desired password
    master_admin_fullname = 'Master Admin'  # Change to desired name
    master_admin_department = 'Admin'  # Change to desired department

    # Check if the user already exists
    existing_user = User.query.filter_by(email=master_admin_email).first()
    if existing_user:
        print("Master admin user already exists.")
    else:
        # Hash the password
        hashed_password = bcrypt.generate_password_hash(master_admin_password).decode('utf-8')

        # Create a new master admin user
        new_master_admin = User(
            full_name=master_admin_fullname,
            email=master_admin_email,
            password=hashed_password,
            is_verified=True,  # Set to True if you want the user to be verified
            role='master_admin',  # Set the role to master_admin
            department=master_admin_department,
            is_internal_user=True
        )

        # Add the new user to the database
        db.session.add(new_master_admin)
        db.session.commit()
        print("Master admin user created successfully.")

if __name__ == '__main__':
    create_master_admin()
