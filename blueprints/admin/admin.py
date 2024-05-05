from flask import Blueprint, render_template, request, redirect
from hackypaws.Authenticator import Authenticator

admin_bp = Blueprint("admin", __name__)

@admin_bp.route("/")
def index():
    print(request.cookies)
    if not Authenticator.validate_session(request.cookies):
        return redirect("/auth/")
    return render_template("admin.html")

@admin_bp.route("/new_paw")
def new_paw():
    print(request.cookies)
    if not Authenticator.validate_session(request.cookies):
        return redirect("/auth/")
    return render_template("new_paw.html")

@admin_bp.route("/create", methods=["POST"])
def create_paw():

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

    print(name, animal, description, profile_pic)
    #if uploaded_file.filename != '':
    #    uploaded_file.save(uploaded_file.filename)

    return redirect("/admin")