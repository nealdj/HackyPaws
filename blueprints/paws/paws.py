import os
from flask import Blueprint, render_template
from hackypaws.Paws import Paws

paws_bp = Blueprint("paws", __name__)

@paws_bp.route("/<int:id>")
def paws(id):

    paw = Paws.get_profile(str(id))
    print(paw)
    return render_template("paw.html")