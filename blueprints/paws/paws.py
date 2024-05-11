import random
from flask import Blueprint, render_template, request, render_template_string
from hackypaws.Paws import Paws

paws_bp = Blueprint("paws", __name__)

@paws_bp.route("/<int:id>")
def paws(id):

    paw = Paws.get_profile(str(id))
    tagline = Paws.generate_tagline(paw)
    animal = paw['animal'].lower()

    if animal == "dog":
        paw_icon = "<i class='fas fa-dog'></i>"
    elif animal == "cat":
        paw_icon = "<i class='fas fa-cat'></i>"
    else:
        paw_icon = "<i class='fas fa-paw'></i>"

    tagline_template = tagline + " {{paw_icon|safe}}"
    tagline = render_template_string(tagline_template, paw_icon=paw_icon)
    
    return render_template("paw.html", paw=paw, tagline=tagline)

@paws_bp.route("/adopt/<int:id>", methods=["POST"])
def adopt(id):

    name = request.form.get('name')
    email = request.form.get('email')
    
    Paws.adopt_request(id, name, email)
    return "Thank you for your adoption request, this will be reviewed soon!"