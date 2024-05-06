import os
from flask import Blueprint, render_template, request, redirect
from werkzeug.utils import secure_filename
from hackypaws.Authenticator import Authenticator
from hackypaws.Paws import Paws

admin_bp = Blueprint("admin", __name__)

@admin_bp.route("/")
def index():
    # require auth
    if not Authenticator.validate_session(request.cookies):
        return redirect("/auth/")
    paws = Paws.get_all_profile()
    return render_template("admin.html", paws=paws)

@admin_bp.route("/new_paw")
def new_paw():
    # require auth
    if not Authenticator.validate_session(request.cookies):
        return redirect("/auth/")
    return render_template("new_paw.html")

@admin_bp.route("/create", methods=["POST"])
def create_paw():
    # require auth
    username = Authenticator.validate_session(request.cookies)
    if not username:
        return redirect("/auth/")
    
    name = request.form.get('name')
    animal = request.form.get('animal')
    description = request.form.get('description')
    
    if 'profile_pic' in request.files:
        profile_pic = request.files['profile_pic']
    else:
        profile_pic = None
    if None in (name, animal, description, profile_pic):
        # check if user has included all options
        return "Error: All Options are required"

    if not Paws.allowed_picture(profile_pic.filename):
        return "Error: uploaded profile pic not allowed"
    
    profile_filename = secure_filename(profile_pic.filename)
    profile_filepath = os.path.join('static/img/', profile_filename)
    profile_pic.save(profile_filepath)

    Paws.add_profile(name, username, description, animal, profile_filepath)

    return redirect("/admin")

@admin_bp.route("/delete/<id>")
def delete_paw(id):
    # require auth
    if not Authenticator.validate_session(request.cookies):
        return redirect("/auth/")
    if Paws.delete_profile(id):
        return redirect("/")
    else:
        return "Unknown Error Occured"