"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User, Space, Form, FormResponse
from api.utils import generate_sitemap, APIException
from flask_cors import CORS
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from base64 import b64encode
import os


api = Blueprint('api', __name__)

# Allow CORS requests to this API
CORS(api)

def set_password(password, salt):
    return generate_password_hash(f"{password}{salt}")


def check_password(hash_password, password, salt):
    return check_password_hash(hash_password, f"{password}{salt}")


@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200


#register user
@api.route("/user", methods=["POST"])
def add_user():
    body = request.json

    lastname = body.get("lastname", None)
    email = body.get("email", None)
    password = body.get("password", None)



    if email is None or password is None or lastname is None:
        return jsonify("you need an the email and a password"), 400
    
    else:
        salt = b64encode(os.urandom(32)).decode("utf-8")
        password = set_password(password, salt)
        user = User(email=email, password=password, lastname=lastname, salt=salt)

        try:
            db.session.add(user)
            db.session.commit()
            return jsonify({"message":"User created"}), 201
            
        except Exception as error:
            print(error.args)
            db.session.rollback()
            return jsonify({"message":f"error: {error}"}), 500
        


@api.route("/user", methods=["GET"])
@jwt_required()
def get_all_users():
    user = User.query.get(get_jwt_identity())

    if user.email == "deimianvasquez@gmail.com":
        user_all = User.query.all()
        user_all = list(map(lambda item: item.serialize(), user_all))
        return jsonify(user_all), 200
    else:
        return jsonify("NO aotorizado, sorry"), 401



@api.route("/login", methods=["POST"])
def login():
    body = request.json

    email = body.get("email", None)
    password = body.get("password", None)

    if email is None or password is None:
        return jsonify("you need an the email and a password"), 400

    # valido que el email enviado exista
    else:
        user = User()
        user = user.query.filter_by(email=email).one_or_none()  

        if user is None:
            return jsonify({"message":"bad email"}), 400
        else:
            if check_password(user.password, password, user.salt):
                token = create_access_token(identity=user.id)
                return jsonify({"token":token}), 200
            else:
                return jsonify({"message":"bad password"}), 400
    
# rutas espacios
@api.route("/space", methods=["POST"])
@jwt_required()
def create_space():
    current_user = User.query.get(get_jwt_identity())
    if not current_user.is_admin:
        return jsonify({"message": "Solo los administradores pueden crear espacios"}), 403
    
    body = request.json
    name = body.get("name")
    description = body.get("description")
    
    new_space = Space(name=name, description=description)
    db.session.add(new_space)
    db.session.commit()
    
    return jsonify(new_space.serialize()), 201

@api.route("/spaces", methods=["GET"])
@jwt_required()
def get_spaces():
    spaces = Space.query.all()
    return jsonify([space.serialize() for space in spaces]), 200

# rutas forms

@api.route("/form", methods=["POST"])
@jwt_required()
def create_form():
    current_user = User.query.get(get_jwt_identity())
    if not current_user.is_admin:
        return jsonify({"message": "Solo los administradores pueden crear formularios"}), 403
    
    body = request.json
    title = body.get("title")
    description = body.get("description")
    structure = body.get("structure")
    
    new_form = Form(title=title, description=description, structure=structure)
    db.session.add(new_form)
    db.session.commit()
    
    return jsonify(new_form.serialize()), 201

@api.route("/forms", methods=["GET"])
@jwt_required()
def get_forms():
    forms = Form.query.all()
    return jsonify([form.serialize() for form in forms]), 200

# respuestas formularios
@api.route("/form-response", methods=["POST"])
@jwt_required()
def submit_form_response():
    current_user = User.query.get(get_jwt_identity())
    
    body = request.json
    form_id = body.get("form_id")
    space_id = body.get("space_id")
    response_data = body.get("response_data")
    
    new_response = FormResponse(
        form_id=form_id,
        user_id=current_user.id,
        space_id=space_id,
        response_data=response_data
    )
    db.session.add(new_response)
    db.session.commit()
    
    return jsonify(new_response.serialize()), 201

@api.route("/form-responses", methods=["GET"])
@jwt_required()
def get_form_responses():
    current_user = User.query.get(get_jwt_identity())
    if not current_user.is_admin:
        return jsonify({"message": "Solo los administradores pueden ver todas las respuestas"}), 403
    
    responses = FormResponse.query.all()
    return jsonify([response.serialize() for response in responses]), 200

@api.route("/form-responses/filter", methods=["GET"])
@jwt_required()
def filter_form_responses():
    current_user = User.query.get(get_jwt_identity())
    if not current_user.is_admin:
        return jsonify({"message": "Solo los administradores pueden filtrar respuestas"}), 403
    
    space_id = request.args.get("space_id")
    user_id = request.args.get("user_id")
    
    query = FormResponse.query
    if space_id:
        query = query.filter_by(space_id=space_id)
    if user_id:
        query = query.filter_by(user_id=user_id)
    
    responses = query.all()
    return jsonify([response.serialize() for response in responses]), 200

# informacion por usuario
@api.route("/me", methods=["GET"])
@jwt_required()
def get_current_user():
    current_user = User.query.get(get_jwt_identity())
    return jsonify(current_user.serialize()), 200

# actualizar perfil
@api.route("/user/profile", methods=["PUT"])
@jwt_required()
def update_profile():
    current_user = User.query.get(get_jwt_identity())
    
    body = request.json
    current_user.firstname = body.get("firstname", current_user.firstname)
    current_user.lastname = body.get("lastname", current_user.lastname)
    current_user.avatar = body.get("avatar", current_user.avatar)
    
    db.session.commit()
    
    return jsonify(current_user.serialize()), 200