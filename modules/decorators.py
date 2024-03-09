from functools import wraps
from flask import request, jsonify
from modules.validation import isvalid
from . import jwtmodule


def admin_authorized(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        jwt_token = request.cookies.get('auth-cookie')
        if not jwtmodule.is_admin(jwt_token):
            return jsonify({"message": "Unauthorized"}), 403
        return f(*args, **kwargs)

    return decorated_function


def user_authorized(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        jwt_token = request.cookies.get('auth-cookie')
        validation_result = jwtmodule.validate_access_token(jwt_token)
        if not validation_result['status'] == "valid":
            return jsonify({"message": "Unauthorized"}), 401
        if not validation_result["type"] == "access":
            return jsonify({"message": "Unauthorized"}), 401
        return f(*args, **kwargs)

    return decorated_function


def otp_cookie_is_valid(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        otp_cookie = request.cookies.get('otp_cookie')
        validation_result = jwtmodule.validate_otp_token(otp_cookie)
        if not validation_result['status'] == "valid":
            return jsonify({"message": "Unauthorized"}), 401
        if not validation_result["type"] == "otp_token":
            return jsonify({"message": "Unauthorized"}), 401
        return f(*args, **kwargs)

    return decorated_function


# this decorator is non used
def request_is_json(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'GET':
            return f(*args, **kwargs)
        request_data = request.get_json(silent=True)
        if request_data is None:
            return jsonify({"message": "Invalid JSON data"}), 400
        return f(*args, **kwargs)
    return decorated_function


def validate_post_json(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'GET':
            return f(*args, **kwargs)

        json_data = request.get_json(silent=True)

        if json_data is None:
            return jsonify({"message": "Invalid JSON data"}), 400

        for key in json_data.keys():
            if key == 'email':
                if not isvalid('email', json_data[key]):
                    return jsonify({"message": "Invalid data format"}), 400
            if key in ['password', 'repeatPassword', 'new_password', 'new_password_repeat']:
                if not isvalid('password', json_data[key]):
                    return jsonify({"message": "Invalid data format"}), 400
            if key == 'pin':
                if not isvalid('pin', json_data[key]):
                    return jsonify({"message": "Invalid data format"}), 400
        return f(*args, **kwargs)
    return decorated_function
