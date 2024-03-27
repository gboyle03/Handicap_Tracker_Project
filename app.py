from datetime import datetime
import logging
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Regexp, Length, EqualTo
from passlib.hash import sha256_crypt


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
login_manager = LoginManager()
login_manager.init_app(app)
# Create a logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Create a file handler and set the logging level to INFO
handler = logging.FileHandler('login_attempts.log')
handler.setLevel(logging.INFO)

# Create a formatter
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# Set the formatter to the handler
handler.setFormatter(formatter)

# Add the handler to the logger
logger.addHandler(handler)


registrations = []



class User(UserMixin):
    def __init__(self, id):
        self.id = id


class LoginForm(FlaskForm):
    user_id = StringField('User ID', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')


class PasswordUpdateForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[InputRequired()])
    new_password = PasswordField('New Password', validators=[
        InputRequired(),
        Length(min=12, message="Password must be at least 12 characters."),
        Regexp(
            r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]*$',
            message="Password must include 1 uppercase, 1 lowercase, 1 number, and 1 special character.")
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[InputRequired(), EqualTo('new_password', message="Passwords must match.")])
    submit = SubmitField('Update Password')


def is_common_password(password):
    with open('CommonPassword.txt', 'r') as common_passwords:
        common_password_list = [line.strip() for line in common_passwords]

    return password in common_password_list


class RegistrationForm(FlaskForm):
    user_id = StringField('User ID', validators=[InputRequired()])
    email = StringField('Email', validators=[InputRequired()])
    password = PasswordField('Password', validators=[
        InputRequired(),
        Length(min=12, message="Password must be at least 12 characters."),
        Regexp(
            r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]*$',
            message="Password must include 1 uppercase, 1 lowercase, 1 number, and 1 special character."
        )
    ])
    password_confirm = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password', message="Passwords must match.")])
    submit = SubmitField('Register')


@login_manager.user_loader
def load_user(user_id):
    return User(user_id)


@app.route('/')
def index():
    """Home landing page with links and description of page"""
    return render_template('index.html')


@app.route('/about')
def about():
    """route to about me page for the Site Owner"""
    return render_template('about.html')


@app.route('/contact')
def contact():
    """route to contact page with current time and Site Owner's email"""
    current_time = datetime.now().strftime('%A, %B %d, %Y %I:%M %p')
    return render_template('contact.html', current_time=current_time)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()  # Create an instance of the RegistrationForm

    if request.method == 'POST' and form.validate_on_submit():
        username = form.user_id.data
        email = form.email.data
        password = form.password.data

        if is_common_password(password):
            flash('Please select a different password; the chosen password is too common.', 'error')
            print("new password attempted: " + password)
        else:

            hashed_password = sha256_crypt.hash(password)
            # Create a registration dictionary
            registration = {
                'username': username,
                'email': email,
                'password': hashed_password,
            }

            # Store the registration in the local data structure
            registrations.append(registration)

            flash('Registration successful! You can now log in.', 'success')
            print(registrations)
            return redirect(url_for('login'))

    return render_template('register.html', form=form)  # Pass the form instance to the template


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()  # Create an instance of the LoginForm

    if request.method == 'POST':
        user_id = form.user_id.data
        password = form.password.data

        # Find the registration entry for the provided user_id
        user_registration = next((user for user in registrations if user['username'] == user_id), None)

        if user_registration:
            stored_hashed_password = user_registration['password']

            # Verify the entered password against the stored hashed password
            if sha256_crypt.verify(password, stored_hashed_password):
                user = User(user_id)
                login_user(user)
                print("Trying to Log In")
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid credentials', 'error')
                logger.info(f'Failed login attempt for user: {user_id} from IP: {request.remote_addr}')
        else:
            flash('Invalid credentials', 'error')
            logger.info(f'Failed login attempt for user: {user_id} from IP: {request.remote_addr}')

    return render_template('login.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/reset', methods=['GET', 'POST'])
@login_required
def reset():
    form = PasswordUpdateForm()
    if request.method == 'POST':
        current_password = form.current_password.data
        new_password = form.new_password.data
        # Check if the current password is valid
        user_registration = next((user for user in registrations if user['username'] == current_user.id), None)

        if user_registration and sha256_crypt.verify(current_password, user_registration['password']):
            if is_common_password(new_password):
                flash('Please select a different password; the chosen password is too common.', 'error')
                print("new password attempted: " + new_password)
            else:
                # Update the user's password
                print(new_password)
                user_registration['password'] = sha256_crypt.hash(new_password)
                flash('Password successfully updated!', 'success')
                return redirect(url_for('dashboard'))
        else:
            flash('Invalid current password', 'error')


    return render_template('reset.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
