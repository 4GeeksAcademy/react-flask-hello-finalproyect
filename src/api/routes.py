"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from werkzeug.security import generate_password_hash, check_password_hash
from base64 import b64encode
import os

api = Blueprint('api', __name__)

# Allow CORS requests to this API
CORS(api)

def set_password(password):
    return generate_password_hash(password)


def check_password(hash_password, password):
    return check_password_hash(hash_password, password)

@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200

@api.route('/signup', methods=['POST'])
def add_user():
    body = request.json

    email = body.get("email", None)
    password = body.get("password", None)

    if email is None or password is None:
        return jsonify("You need an email and password"), 400 
    else:
        password = set_password(password)
        user = User(email=email, password=password)

        try:
            db.session.add(user)
            db.session.commit()
            return jsonify({"message":"user created"}), 201
        except Exception as error:
            print(error.args)
            db.session.rollback()
            return jsonify({"message": f"error: {error}"}), 500

@api.route('/login', methods=['POST'])
def login_user():
    body = request.json

    email = body.get('email', None)
    password = body.get('password', None)

    if email is None or password is None:
        return jsonify("You need an email and password"), 400 
    else:
        user = User()
        user = user.query.filter_by(email=email).one_or_none()

        if user is None or password is None:
            return jsonify ({"message":"bad credentials"}), 400
        else:
            if check_password(user.password, password):
                access_token = create_access_token(identity=user.id)
                return jsonify(access_token=access_token), 200
    
    
@api.route("/signup", methods=["GET"])
@jwt_required()
def get_all_users():
    user = User.query.get(get_jwt_identity())

    if user.email == "alejosanch97@gmail.com":
        user_all = User.query.all()
        user_all = list(map(lambda item: item.serialize(), user_all))
        return jsonify(user_all), 200
    else:
        return jsonify("This information is not for you"), 401

    