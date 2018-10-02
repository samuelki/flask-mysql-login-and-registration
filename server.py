from flask import Flask, render_template, redirect, session, request, flash
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt
import re

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "kj249xjkfh17nsf0ah3"
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    mysql = connectToMySQL('login_and_registration')

    session['first_name'] = request.form['first_name']
    session['last_name'] = request.form['last_name']
    session['email'] = request.form['email']
    session['password'] = request.form['password']
    session['confirm_pw'] = request.form['confirm_pw']

    first_name_valid = False
    last_name_valid = False
    email_valid = False
    password_valid = False
    password_match = False

    # validate first name
    if session['first_name'].isalpha() and len(session['first_name']) > 1:
        first_name_valid = True
    else: 
        if not session['first_name'].isalpha():
            flash("First name can only be letters.", 'error')
        if len(session['first_name']) < 2:
            flash("First name must be at least two characters long.", 'error')

    # validate last name
    if session['last_name'].isalpha() and len(session['last_name']) > 1:
        last_name_valid = True
    else:
        if not session['last_name'].isalpha:
            flash("Last name can only be letters.", 'error')
        if len(session['last_name']) < 2:
            flash("Last name must be at least two characters long.", 'error')

    # validate email
    query = "SELECT * FROM users WHERE email = %(email)s"
    data = {
        'email': session['email']
    }
    result = mysql.query_db(query, data)
    if len(result) > 0:
        flash("Account already exists!", 'error')
        return redirect('/')
    
    if EMAIL_REGEX.match(session['email']):
        email_valid = True
    else:
        flash("Invalid Email Address!", 'error')
        return redirect('/')

    # validate password
    if len(session['password']) > 7:
        password_valid = True
    else: 
        flash("Password must be at least 8 characters long.", 'error')
        return redirect('/')

    # check if passwords match
    if session['password'] == session['confirm_pw']:
        password_match = True
    else:
        flash("Passwords do not match!", 'error')
        return redirect('/')

    # if all validations pass, insert new user and redirect
    if first_name_valid and last_name_valid and email_valid and password_valid and password_match:
        mysql = connectToMySQL('login_and_registration')
        pw_hash = bcrypt.generate_password_hash(session['password'])
        query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s, NOW(), NOW())"
        data = {
            'first_name': session['first_name'],
            'last_name': session['last_name'],
            'email': session['email'],
            'password': pw_hash
        }
        mysql.query_db(query, data)

        mysql = connectToMySQL('login_and_registration')
        query = "SELECT * FROM users WHERE first_name=%(first_name)s AND last_name=%(last_name)s AND email=%(email)s"
        data = {
            'first_name': session['first_name'],
            'last_name': session['last_name'],
            'email': session['email']
        }
        user = mysql.query_db(query, data)
        session['id'] = user[0]['id']
        session['first_name'] = user[0]['first_name']
        return redirect('/home')
    else:
        return redirect('/')

@app.route('/home')
def home():
    if session.get('id') == None:
        return redirect('/')
    
    return render_template('home.html')

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']

    mysql = connectToMySQL('login_and_registration')
    query = "SELECT * FROM users WHERE email=%(email)s"
    data = { 
        'email': request.form['email']
    }
    user = mysql.query_db(query, data)

    if len(user) > 0:
        if bcrypt.check_password_hash(user[0]['password'], request.form['password']):
            session['id'] = user[0]['id']
            session['first_name'] = user[0]['first_name']
            return redirect('/home')

    flash("Incorrect email address or password")
    return redirect('/')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have logged out.", 'success')
    return redirect('/')

if __name__=="__main__":
    app.run(debug=True)