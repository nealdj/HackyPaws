from flask import Flask, render_template
from blueprints.auth.auth import auth_bp
from blueprints.admin.admin import admin_bp
from hackypaws.Authenticator import Authenticator

app = Flask(__name__)

app.register_blueprint(auth_bp, url_prefix="/auth")
app.register_blueprint(admin_bp, url_prefix="/admin")

@app.route("/")
def index():
    return render_template('index.html')

