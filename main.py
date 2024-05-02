from flask import Flask, render_template
from blueprints.auth.auth import auth_bp

app = Flask(__name__)

app.register_blueprint(auth_bp, url_prefix="/auth")

@app.route("/")
def index():
    return render_template('index.html')

