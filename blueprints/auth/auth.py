from flask import Blueprint, render_template, redirect, url_for, request
import datetime, hashlib, hmac, base64

auth_bp = Blueprint("auth", __name__)

def generate_session(username):
    '''
    Generates user sessions
        sessions will be invalidated each day for security
    '''
    auth_secret = str(datetime.date.today()).encode('utf-8')
    hmac_value = hmac.new(auth_secret, username.encode('utf-8'), hashlib.md5).digest()
    session_token = base64.b64encode(hmac_value).decode('utf-8')
    print(session_token)
    return session_token

def validate_session(token, username):
    '''
    Validates if user token was generated from our site
    '''
    token_sig = base64.b64decode(token)
    auth_secret = str(datetime.date.today()).encode('utf-8')
    username_bytes = username.encode('utf-8')
    hmac_digest = hmac.new(auth_secret, username_bytes, hashlib.md5).digest()
    if hmac.compare_digest(token_sig, hmac_digest):
        return username
    else:
        return False
    

@auth_bp.route("/")
def auth_index():
    return render_template('login.html')

@auth_bp.route("/login", methods=['POST'])
def login():
    data = request.form
    username = data.get('username')
    password = data.get('password')
    session = generate_session(username)
    resp = redirect("/")
    resp.set_cookie('session', session)
    print(validate_session(session, username))
    return resp 