from flask import Blueprint, render_template, redirect, url_for, request
from hackypaws.Authenticator import Authenticator

auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/")
def auth_index():
    return render_template('login.html')

@auth_bp.route("/login", methods=['POST'])
def login():
    data = request.form
    if not data.get('username') or not data.get('password'):
        return redirect("/auth?login=False")
    if not Authenticator.login(data.get('username'), data.get('password')):
        return redirect("/auth?login=False")
    else:
        session = Authenticator.generate_session(data.get('username'))
        resp = redirect("/admin/")
        resp.set_cookie('session', session)
        return resp
    