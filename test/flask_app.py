import os
from flask import Flask, session, render_template
from flask_session_plus import Session
from flask_login import LoginManager, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField
from test.auth import login_user, logout_user

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = os.path.join(os.path.dirname(BASE_DIR), 'firebase.json')

from test.models import User, db

app = Flask(__name__, template_folder='templates')
app.config['SESSION_CONFIG'] = [
    # First session will store the csrf_token only on it's own cookie.
    {
        'cookie_name': 'csrf',
        'session_type': 'secure_cookie',
        'session_fields': ['csrf_token']
    },
    # Second session will store the user logged in inside the firestore sessions collection.
    {
        'cookie_name': 'session',
        'session_type': 'firestore',
        'session_fields': ['user_id', 'user_data', '_fresh', '_id'],
        'client': db,
        'collection': 'sessions',
    },
    # Third session will store any other values set on the Flask session on it's own secure cookie
    {
        'cookie_name': 'data',
        'session_type': 'secure_cookie',
        'session_fields': 'auto'
    }
]
app.config['SECRET_KEY'] = 'my_secret_key'
app.config['SESION_USER_FIELDS'] = ['name', 'email', 'timezone', 'language', 'active']

mses = Session(app)
login_manager = LoginManager(app)


# Example Form to test the csrf token
class LoginForm(FlaskForm):
    username = StringField('name')


@login_manager.user_loader
def load_user(id):
    # Flask-Login USER loader
    # can't use current_user here as this method is setting the current_user
    if 'user_id' in session:
        print('Got user from SESSION')
        return User.get_user_from_session(session)
    else:
        print('Got user from DATABASE')
        return User.get_user_by_id(id)


@app.route('/')
def index():
    # testing setting session random values
    session['dog'] = 'cat'

    if current_user.is_authenticated:
        return f"Hi!: {current_user.to_dict()}"
    else:
        return 'Anon User'


@app.route('/login')
def login():
    """ Testing a normal login """
    user = User.get_user_by_id('1kuU9610nMtUlqLqdjxR')

    login_user(user)
    return 'User logged in!'


@app.route('/loginpermanent')
def loginp():
    """ Testing a permanent login """
    user = User.get_user_by_id('1kuU9610nMtUlqLqdjxR')

    login_user(user, remember=True)
    session.set_permanent('session')  # setting the session as permanent

    return 'User logged in!'


@app.route('/logout')
def logout():
    logout_user()
    session.set_permanent('session', remove=True)  # unsetting the session as permanent

    return 'User logged out!'


@app.route('/protected')
@login_required
def protected():
    return f'you have access!: {current_user.to_dict()}'


@app.route('/form', methods=['GET', 'POST'])
@login_required
def form():
    """ Testing that the csrf_token from flask-wtf is well set"""
    frm = LoginForm()
    if frm.validate_on_submit():
        return render_template('test_csrf.html', form=frm, success=True)
    return render_template('test_csrf.html', form=frm)


if __name__ == '__main__':
    app.run()
