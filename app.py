from flask import Flask, render_template, request, redirect, session
from flask_sslify import SSLify
from flask_session import Session
from models import users, common_passwords
from config import SECRET_KEY
import hashlib
import re

app = Flask(__name__)

sslify = SSLify(app)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True

Session(app)

app.secret_key = SECRET_KEY

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if not is_valid_username(username):
            return render_template('login.html', error='Please username must contain alpha numeric characters')
        if not is_valid_password(password): 
            return render_template('login.html', error='Password must be at least 12 characters long, and a mix of letters, numbers, and special characters')
        if username in users and hashlib.sha256(password.encode()).hexdigest() == users[username]['password']:
            users[username]['failed_logins'] = 0
            session['username'] = username
            session['httponly'] = True
            return redirect('/')
        else:
            if username in users:
                users[username]['failed_logins'] += 1
                if users[username]['failed_logins'] >= 5:
                    return render_template('login.html', error='Too many failed login attempts. Account locked')
            return render_template('login.html', error='Incorrect Username or Password !')
    else:
        return render_template('login.html')

def is_valid_username(username):
    if not username.isalnum():
        return False
    return True

def is_valid_password(password):
    if not re.search(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@#$%!*&?])[A-Za-z\d@$#%!*&?]{12,}$', password):
        return False
    if password in common_passwords:
        return False
    return True

@app.route('/')
def home():
    if'username' in session:
        return render_template('home.html', username=session['username'])
    else:
        return redirect('/login')

if __name__ == "__main__":
    app.run(debug=True, port=9000) 
    
