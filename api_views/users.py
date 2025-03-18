import re
import jsonschema
import jwt
from werkzeug.security import generate_password_hash

from config import db, vuln_app
from constants import APPLICATION_JSON, INVALID_TOKEN
from api_views.json_schemas import register_user_schema, login_user_schema, update_email_schema
from flask import jsonify, Response, request, json
from models.user_model import User
from app import vuln

def error_message_helper(msg):
    return '{ "status": "fail", "message": "' + msg + '"}'

def get_all_users():
    return_value = jsonify({'users': User.get_all_users()})
    return return_value

def debug():
    return_value = jsonify({'users': User.get_all_users_debug()})
    return return_value

def get_by_username(username):
    if User.get_user(username):
        return Response(str(User.get_user(username)), 200, mimetype=APPLICATION_JSON)
    else:
        return Response(error_message_helper("User not found"), 404, mimetype=APPLICATION_JSON)

def register_user():
    request_data = request.get_json()
    # check if user already exists
    user = User.query.filter_by(username=request_data.get('username')).first()
    if not user:
        try:
            # validate the data are in the correct form
            jsonschema.validate(request_data, register_user_schema)
            if vuln and 'admin' in request_data:  # User is possible to define if she/he wants to be an admin !!
                admin = request_data['admin']
            else:
                admin = False
            user = User(username=request_data['username'], password=request_data['password'],
                        email=request_data['email'], admin=admin)
            db.session.add(user)
            db.session.commit()

            response_object = {
                'status': 'success',
                'message': 'Successfully registered. Login to receive an auth token.'
            }

            return Response(json.dumps(response_object), 200, mimetype=APPLICATION_JSON)
        except jsonschema.exceptions.ValidationError as exc:
            return Response(error_message_helper(exc.message), 400, mimetype=APPLICATION_JSON)
    else:
        return Response(error_message_helper("User already exists. Please Log in."), 200, mimetype=APPLICATION_JSON)

def login_user():
    request_data = request.get_json()

    try:
        # validate the data are in the correct form
        jsonschema.validate(request_data, login_user_schema)
        # fetching user data if the user exists
        user = User.query.filter_by(username=request_data.get('username')).first()
        if user and request_data.get('password') == user.password:
            auth_token = user.encode_auth_token(user.username)
            response_object = {
                'status': 'success',
                'message': 'Successfully logged in.',
                'auth_token': auth_token
            }
            return Response(json.dumps(response_object), 200, mimetype=APPLICATION_JSON)
        if vuln:  # Password Enumeration
            if user and request_data.get('password') != user.password:
                return Response(error_message_helper("Password is not correct for the given username. Week2 Completed"), 200, mimetype=APPLICATION_JSON)
            elif not user:  # User enumeration
                return Response(error_message_helper("Username does not exist"), 200, mimetype=APPLICATION_JSON)
        else:
            if (user and request_data.get('password') != user.password) or (not user):
                return Response(error_message_helper("Username or Password Incorrect!"), 200, mimetype=APPLICATION_JSON)
    except jsonschema.exceptions.ValidationError as exc:
        return Response(error_message_helper(exc.message), 400, mimetype=APPLICATION_JSON)
    except Exception as exc:
        return Response(error_message_helper("An error occurred! " + str(exc)), 200, mimetype=APPLICATION_JSON)

def token_validator(auth_header):
    if auth_header:
        try:
            auth_token = auth_header.split(" ")[1]
        except IndexError:
            auth_token = ""
    else:
        auth_token = ""
    if auth_token:
        # if auth_token is valid we get back the username of the user
        return User.decode_auth_token(auth_token)
    else:
        return INVALID_TOKEN

def update_email():
    request_data = request.get_json()
    try:
        jsonschema.validate(request_data, update_email_schema)
    except jsonschema.exceptions.ValidationError:
        return Response(error_message_helper("Please provide a proper JSON body."), 400, mimetype=APPLICATION_JSON)
    resp = token_validator(request.headers.get('x-user-token'))
    if "expired" in resp:
        return Response(error_message_helper(resp), 401, mimetype=APPLICATION_JSON)
    elif INVALID_TOKEN in resp:
        return Response(error_message_helper(resp), 401, mimetype=APPLICATION_JSON)
    else:
        user = User.query.filter_by(username=resp).first()
        if vuln:  # Regex DoS
            match = re.search(
                r"^([0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*@([0-9a-zA-Z][-\w]*[0-9a-zA-Z]\.)+[a-zA-Z]{2,9})$",
                str(request_data.get('email')))
            if match:
                user.email = request_data.get('email')
                db.session.commit()
                response_object = {
                    'status': 'success',
                    'data': {
                        'username': user.username,
                        'email': user.email
                    }
                }
                return Response(json.dumps(response_object), 204, mimetype=APPLICATION_JSON)
            else:
                return Response(error_message_helper("Please Provide a valid email address."), 400, mimetype=APPLICATION_JSON)
        else:
            regex = r'^[a-z0-9]+[._]?[a-z0-9]+@\w+\.\w{2,3}$'
            if (re.search(regex, request_data.get('email'))):
                user.email = request_data.get('email')
                db.session.commit()
                response_object = {
                    'status': 'success',
                    'data': {
                        'username': user.username,
                        'email': user.email
                    }
                }
                return Response(json.dumps(response_object), 204, mimetype=APPLICATION_JSON)
            else:
                return Response(error_message_helper("Please Provide a valid email address."), 400, mimetype=APPLICATION_JSON)

def update_password():
    request_data = request.get_json()
    resp = token_validator(request.headers.get('Authorization'))

    if not validate_token_response(resp):
        return Response(error_message_helper(resp), 401, mimetype=APPLICATION_JSON)

    if not request_data.get('password'):
        return Response(error_message_helper("Malformed Data"), 400, mimetype=APPLICATION_JSON)

    if not is_password_strong(request_data.get('password')):
        return Response(error_message_helper("Password does not meet security requirements."), 400, mimetype=APPLICATION_JSON)

    hashed_password = generate_password_hash(request_data.get('password'))
    return process_password_update(request_data, resp, hashed_password)


def validate_token_response(resp):
    if "expired" in resp or INVALID_TOKEN in resp:
        return False
    return True


def process_password_update(request_data, resp, hashed_password):
    if vuln:  # Unauthorized update of password of another user
        user = User.query.filter_by(username=request_data.get('username')).first()
        if not user:
            return Response(error_message_helper("User Not Found"), 400, mimetype=APPLICATION_JSON)
    else:
        user = User.query.filter_by(username=resp).first()

    user.password = hashed_password
    db.session.commit()

    response_object = {
        'status': 'success',
        'Password': 'Updated.'
    }
    return Response(json.dumps(response_object), 204, mimetype=APPLICATION_JSON)

def delete_user():
    request_data = request.get_json()
    resp = token_validator(request.headers.get('Authorization'))
    if "expired" in resp:
        return Response(error_message_helper(resp), 401, mimetype=APPLICATION_JSON)
    elif INVALID_TOKEN in resp:
        return Response(error_message_helper(resp), 401, mimetype=APPLICATION_JSON)
    else:
        user = User.query.filter_by(username=resp).first()
        if user.admin:
            if bool(User.delete_user(request_data.get('username'))):
                response_object = {
                    'status': 'success',
                    'message': 'User deleted.'
                }
                return Response(json.dumps(response_object), 200, mimetype=APPLICATION_JSON)
            else:
                return Response(error_message_helper("User not found!"), 404, mimetype=APPLICATION_JSON)
        else:
            return Response(error_message_helper("Only Admins may delete users!"), 401, mimetype=APPLICATION_JSON)

def is_password_strong(password):
    if len(password) < 8:
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.islower() for char in password):
        return False
    if not any(char in "!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~" for char in password):
        return False
    return True
