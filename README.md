# FixMyCampus - Campus Issue Reporting System

FixMyCampus is a comprehensive web application that allows students to report and track campus infrastructure issues. The system provides an intuitive interface for students to submit problems related to electricity, water, internet, furniture, cleanliness, and other campus facilities.

## Features

- **User Authentication**: Secure login/signup system with password recovery
- **Issue Reporting**: Submit detailed reports about campus infrastructure problems
- **Issue Tracking**: Track the status of reported issues (Pending, In Progress, Resolved)
- **User Profiles**: View and update personal information
- **Dashboard**: Visual analytics of campus-wide issues
- **Admin Panel**: Comprehensive management system for administrators
- **Responsive Design**: Works seamlessly on mobile, tablet, and desktop devices

## Technical Stack

- **Backend**: Python Flask
- **Database**: MySQL
- **Frontend**: HTML, Tailwind CSS, JavaScript
- **Charts**: Chart.js
- **Icons**: Font Awesome

## Directory Structure

```
/fix_my_campus
|   admin.py
|   app.py
|   README.md
|   requirements.txt
|   File Structure.txt
|   
+---src
|       index.css
|       
+---static
|   +---css
|   |       styles.css
|   |       
|   \---js
|           charts.js
|           main.js
|           
\---templates
    |   about.html
    |   about_campus.html
    |   change_password.html
    |   forgot_password.html
    |   help_support.html
    |   home.html
    |   issue_dashboard.html
    |   login.html
    |   my_issues.html
    |   profile.html
    |   report_issue.html
    |   signup.html
    |   
    +---admin
    |       audit_logs.html
    |       dashboard.html
    |       login.html
    |       manage_issues.html
    |       user_management.html
    |       
    +---components
    |       footer.html
    |       navbar.html
    |       
    \---layouts
            base.html
            
```

## Installation

1. Clone the repository:
```
git clone https://github.com/mehta-g1/fix-my-campus-1.git
cd fix-my-campus
```

2. Install dependencies:
```
pip install -r requirements.txt
```

3. Run the application:
```
python app.py
```

4. Run the admin panel (separate server):
```
python admin.py
```

## Database Setup

The application is configured to use a MySQL database. The database connection details are set in the app.py file:

```python
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'your_sql_passwrod'
app.config['MYSQL_DB'] = 'your_databasr_name'
```

## User Credentials

For testing purposes:

- **Regular User**:
  - Create a new account through the signup page

- **Admin**:
  - Username: admin@1234
  - Password: 123

## License

This project is licensed under the MIT License - see the LICENSE file for details.
