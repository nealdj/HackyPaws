from flask import Flask, render_template
from blueprints.auth.auth import auth_bp
from blueprints.admin.admin import admin_bp
from blueprints.paws.paws import paws_bp
from hackypaws.Authenticator import Authenticator
from hackypaws.Paws import Paws

app = Flask(__name__)

app.register_blueprint(auth_bp, url_prefix="/auth")
app.register_blueprint(admin_bp, url_prefix="/admin")
app.register_blueprint(paws_bp, url_prefix="/paws")

@app.route("/")
def index():
    paws = Paws.get_all_profile()
    return render_template('index.html', paws=paws)

