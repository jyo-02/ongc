ONGC Internal Portal & File Management System

Prerequisites

- Ensure Python is installed on the offline system.
- Ensure you have the packages folder containing all required dependencies.
- Ensure you have users.db file

Steps to Run the Application

1. (Optional) Set Up a Virtual Environment :

   - Navigate to the project directory:

     cd /path/to/your/project

   - Create a virtual environment:

     python -m venv test

   - Activate the virtual environment:

     - On macOS/Linux:

       source test/bin/activate

     - On Windows:

     .\test\Scripts\activate

2. Install Dependencies:

   - Navigate to the directory containing the requirements.txt:

   - Install the dependencies using the following command:

     python -m pip install --no-index --find-links=packages -r requirements.txt

3. Configuration:

   - Set up any necessary configuration files or environment variables.

4. Run the Application\*\*:

   python app.py

Notes :

- If you require creating the master admin account, run create_master_admin.py

- Make sure to transfer any static files or database files needed for the application to the offline system.

Existing Users

Below are the users already present in the database:
(Password for all users is 12345)

| Email                  | Role              |
| ---------------------  | --------------    |
| admin@gmail.com        | Master Admin      |
| manisel237@ethsms.com  | Group Admin IT    |
| wonekac918@ethsms.com  | User Geology      |
| leliy19815@boxmach.com | Invalid User HR   |
