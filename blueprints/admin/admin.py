from flask import Blueprint, render_template

admin_bp = Blueprint("admin")

@admin_bp.route("/")
def index():
    return "admin"