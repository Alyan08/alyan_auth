from flask import request, make_response, Blueprint, jsonify, render_template, redirect, url_for
from modules.validation import isvalid
from modules import jwtmodule
from modules import config
from modules import decorators
from modules import db
from modules import logger
from modules import mail_agent


user_blueprint = Blueprint('user', __name__)

data_error = {"status": "error", "message": "invalid data"}
unknown_error = {"status": "error", "message": "Something was wrong"}
forbidden_response = {"status": "error", "message": "Forbidden!"}
unauthorized_error = {"status": "error", "message": "Unauthorized!"}


@user_blueprint.route('/registration', methods=['GET', 'POST'])
@decorators.validate_post_json
def registration():
    if request.method == 'GET':
        return render_template('registration.html')
    if request.method == 'POST':
        try:
            auth_data = request.get_json(silent=True)
            email = auth_data["email"]
            password = auth_data["password"]
            repeat_password = auth_data["repeatPassword"]
        except:
            logger.make_api_local_log(request, "invalid registration request", status_code=400)
            return make_response(jsonify(data_error), 400)

        if password != repeat_password:
            logger.make_api_local_log(request, "passwords pair mismatch", status_code=400)
            return make_response(jsonify({
                "status": "error",
                "message": "New password mismatch new password repeat"
                }), 400)

        result = db.register_new_user(email, password)
        if not result["status"]:
            logger.make_api_local_log(request, result["message"], {"email": email}, 403)
            return make_response(jsonify(unknown_error), 400)

        print(result["confirm_token"])

        response = {
            'status': 'success',
            'message': 'Confirmation email has been sent. Please check your email.'
        }

        if not mail_agent.send_reg_confirm_email(email, result["confirm_token"]):
            logger.make_api_local_log(request, msg="error through confirm token sending",
                                      data={"email": email}, status_code=400)
            return make_response(jsonify(unknown_error), 400)

        logger.make_api_local_log(request, msg=result["message"],
                                  data={"email": email}, status_code=200)
        return make_response(jsonify(response), 200)


@user_blueprint.route('/confirm', methods=['GET'])
def confirm():
    try:
        email = request.args.get('email')
        token = request.args.get('token')
    except:
        logger.make_api_local_log(request, "not enough parameters", status_code=400)
        return make_response(jsonify(data_error), 400)

    if not isvalid("email", email) or not isvalid("confirm_token", token):
        logger.make_api_local_log(request, msg="validation error",
                                  data={"email": email}, status_code=400)
        return make_response(jsonify(data_error), 400)

    confirm_result = db.approve_user_reg(email, token)

    if not confirm_result["status"]:
        logger.make_api_local_log(request, msg=confirm_result["message"],
                                  data={"email": email}, status_code=400)
        return make_response(jsonify(confirm_result), 400)

    logger.make_api_local_log(request, msg=confirm_result["message"],
                              data={"email": email}, status_code=200)
    return make_response(jsonify(confirm_result), 200)


@user_blueprint.route('/cancel', methods=['GET'])
def cancel():
    try:
        email = request.args.get('email')
        token = request.args.get('token')
    except:
        return make_response(jsonify(data_error), 400)

    if not isvalid('email', email) or not isvalid('confirm_token', token):
        return make_response(jsonify(data_error), 400)

    cancel_reg_result = db.delete_reg_req(email, token)

    if not cancel_reg_result["status"]:
        logger.make_api_local_log(request, msg=cancel_reg_result["message"], data={"email": email}, status_code=400)
        return make_response(jsonify({"status": "error", "message": "not canceled"}), 400)

    return make_response(jsonify(cancel_reg_result), 200)


@user_blueprint.route('/login', methods=['POST', 'GET'])
@decorators.validate_post_json
def login():
    if request.method == 'GET':
        return render_template('login.html')

    if request.method == 'POST':
        try:
            auth_data = request.get_json(silent=True)
            email = auth_data["email"]
            password = auth_data["password"]
        except:
            logger.make_api_local_log(request, "invalid request data", status_code=400)
            return make_response(jsonify(data_error), 400)

        check_user_result = db.check_auth_creds(email, password)
        if not check_user_result["status"]:
            logger.make_api_local_log(request, msg=check_user_result["message"], status_code=400)
            return make_response(jsonify({"message": "Unauthorized"}), 401)

        if config.AccountConfig.MULTI_FACTOR_REQUIRED:
            otp_cookie = jwtmodule.generate_otp_token(email)

            multi_factor_generation_result = db.generate_multi_factor_code(email)
            if not multi_factor_generation_result["status"]:
                return make_response(jsonify(unknown_error), 400)

            mail_agent.send_2fa_email(email, multi_factor_generation_result["code"])

            response = make_response(redirect(url_for('user.pin')))
            response.set_cookie("otp_cookie", otp_cookie, secure=True, httponly=True, samesite='Strict')
            response.status_code = 301
            logger.make_api_local_log(request, msg="login 2fa PIN requires", data={"email": email}, status_code=301)
            return response

        access_jwt_payload = check_user_result["user_info"]
        auth_cookie = jwtmodule.generate_access_jwt(access_jwt_payload)
        refresh_creating_res = db.create_refresh_token(email)
        if not refresh_creating_res["status"]:
            return make_response(jsonify(unknown_error), 400)
        refresh_cookie = refresh_creating_res["refresh"]
        response = make_response(jsonify({"message": "Success login"}))
        response.status_code = 200
        response.set_cookie("auth-cookie", auth_cookie, secure=True,
                            httponly=True, samesite='Strict', domain=config.HOSTNAME)
        response.set_cookie("refresh", refresh_cookie, secure=True,
                            httponly=True, samesite='Strict', domain=config.HOSTNAME, path='/user/updateaccess')
        logger.make_api_local_log(request, msg=check_user_result["message"], data={"email": email}, status_code=200)
        return response


@user_blueprint.route('/pin', methods=['GET'])
def pin():
    if not config.AccountConfig.MULTI_FACTOR_REQUIRED:
        return "Not found", 404
    return render_template('pin.html')


@user_blueprint.route('/pin/send', methods=['POST'])
@decorators.validate_post_json
def pin_send():
    if not config.AccountConfig.MULTI_FACTOR_REQUIRED:
        return "Not found", 404

    otp_cookie = request.cookies.get('otp_cookie')
    validation_result = jwtmodule.validate_otp_token(otp_cookie)

    if validation_result["status"] != "valid":
        return make_response(jsonify(unauthorized_error), 401)

    user_info = db.get_db_user_info(validation_result["sub"])

    if not user_info["status"] or user_info["user_status"] not in config.AccountConfig.ACTIVE_STATUSES:
        logger.make_api_local_log(request, msg=user_info["message"],
                                  data={"email": user_info["username"]}, status_code=400)
        return make_response(jsonify(unknown_error), 400)

    data = request.get_json(silent=True)
    pin_check_result = db.check_multi_factor_code(user_info["username"], data["pin"])
    if not pin_check_result["status"]:
        return make_response(jsonify(pin_check_result), 400)

    access_jwt_payload = {"sub": user_info["username"], "usergroup": user_info["usergroup"]}
    auth_cookie = jwtmodule.generate_access_jwt(access_jwt_payload)
    refresh_cookie = db.create_refresh_token(user_info["username"])["refresh"]
    response = make_response(jsonify({"message": "Success login!"}))
    response.status_code = 200
    response.set_cookie("auth-cookie", auth_cookie, secure=True,
                        httponly=True, samesite='Strict', domain=config.HOSTNAME)
    response.set_cookie("refresh", refresh_cookie, secure=True,
                        httponly=True, samesite='Strict', domain=config.HOSTNAME, path='/user/updateaccess')

    logger.make_api_local_log(request, "authorized", data={"email": user_info["username"]}, status_code=200)
    return response


@user_blueprint.route('/update-access', methods=['POST'])
def update_access():
    old_refresh_cookie = request.cookies.get("refresh")
    if not jwtmodule.validate_refresh_token(old_refresh_cookie)["status"] == "valid":
        return make_response(jsonify(unauthorized_error), 401)

    result = db.use_and_update_refresh_token(old_refresh_cookie)
    if not result["status"]:
        logger.make_api_local_log(request, msg=result["message"], status_code=400)
        return make_response(jsonify(unknown_error), 400)

    refresh_cookie = result["refresh"]

    user_info = db.get_db_user_info(result["username"])
    if not user_info["status"]:
        logger.make_api_local_log(request, msg=user_info["message"], status_code=400)
        return make_response(jsonify(unknown_error), 400)

    access_jwt_payload = {"sub": user_info["username"], "usergroup": user_info["usergroup"]}
    auth_cookie = jwtmodule.generate_access_jwt(access_jwt_payload)

    response = make_response(jsonify({"message": "Success cookie update!"}))
    response.set_cookie("auth-cookie", auth_cookie, secure=True,
                        httponly=True, samesite='Strict', domain=config.HOSTNAME)
    response.set_cookie("refresh", refresh_cookie, secure=True,
                        httponly=True, samesite='Strict', domain=config.HOSTNAME, path='/user/updateaccess')
    # response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


@user_blueprint.route('/check-jwt', methods=['GET'])
@decorators.user_authorized
def check_jwt():
    jwt_token = request.cookies.get('auth-cookie')
    if not jwt_token:
        return make_response(jsonify(unauthorized_error), 401)

    result = jwtmodule.validate_access_token(jwt_token)
    return result


@user_blueprint.route('/get-user-info', methods=['GET'])
@decorators.user_authorized
def get_user_info():
    jwt_info = jwtmodule.validate_access_token(request.cookies.get('auth-cookie'))
    if not jwt_info["status"] == "valid":
        logger.make_api_local_log(request, msg="failed user info request",
                                  data={"email": jwt_info["sub"]}, status_code=403)
        return make_response(jsonify(unauthorized_error), 401)

    user_info = db.get_db_user_info(jwt_info["sub"])
    if not user_info["status"]:
        logger.make_api_local_log(request, msg="failed user info request",
                                  data={"email": jwt_info["sub"]}, status_code=403)
        return make_response(jsonify(forbidden_response), 403)

    logger.make_api_local_log(request, msg="success user info request",
                              data={"email": jwt_info["sub"]}, status_code=200)
    return user_info


@user_blueprint.route('/logout', methods=['GET'])
@decorators.user_authorized
def logout():
    response = make_response(jsonify({"message": "success logout"}))
    response.status_code = 200
    response.set_cookie("auth-cookie", '')
    response.set_cookie("refresh", '')
    return response


@user_blueprint.route('/password/edit', methods=['POST'])
@decorators.user_authorized
@decorators.validate_post_json
def edit_password():

    req_data = request.get_json(silent=True)
    try:
        email = req_data["email"]
        old_password = req_data["old_password"]
        new_password = req_data["new_password"]
        new_password_repeat = req_data["new_password_repeat"]
    except:
        return make_response(jsonify(data_error), 400)

    if not new_password == new_password_repeat:
        return make_response(jsonify(
            {"status": "error", "message": "New password mismatch new password repeat"}), 400)

    old_password_check = db.check_auth_creds(email, old_password)
    if not old_password_check["status"]:
        logger.make_api_local_log(request, msg=old_password_check["message"], status_code=400)
        return make_response(jsonify({"message": "wrong old password"}), 403)

    change_result = db.change_password(email, new_password)
    if not change_result["status"]:
        logger.make_api_local_log(request, msg=change_result["message"], status_code=400)
        return make_response(jsonify(unknown_error), 400)

    logger.make_api_local_log(request, "password changed", {"email": email}, 200)
    return make_response(jsonify(change_result), 200)


@user_blueprint.route('/password/forgot', methods=['POST'])
@decorators.validate_post_json
def password_forgot():
    req_data = request.get_json(silent=True)
    try:
        email = req_data["email"]
    except:
        return make_response(jsonify(data_error), 400)

    code_result = db.generate_multi_factor_code(email, code_long=8)
    if not code_result["status"] or not mail_agent.send_forgot_password_email(email, code_result["code"]):
        return make_response(jsonify(unknown_error), 400)

    otp_cookie = jwtmodule.generate_otp_token(email)
    response = make_response(jsonify(
        {"message": "please send confirmation code. Code was sent to your email"}))

    response.set_cookie("otp_cookie", otp_cookie, secure=True, httponly=True, samesite='Strict')
    response.status_code = 301

    logger.make_api_local_log(request, "restoring password required", {"email": email}, 301)
    return response


@user_blueprint.route('/password/restore', methods=['POST'])
@decorators.validate_post_json
@decorators.otp_cookie_is_valid
def password_restore():
    req_data = request.get_json(silent=True)

    try:
        email = req_data["email"]
        received_code = req_data["pin"]
        new_password = req_data["new_password"]
        new_password_repeat = req_data["new_password_repeat"]
    except:
        return make_response(jsonify(data_error), 400)

    if new_password != new_password_repeat:
        return make_response(jsonify({"message": "New password mismatch new password repeat"}))

    confirm_result = db.check_multi_factor_code(email, received_code)
    change_result = db.change_password(email, new_password)
    if not confirm_result["status"] or not change_result["status"]:
        return make_response(jsonify(unknown_error), 400)

    logger.make_api_local_log(request, msg="password restored",
                              data={"email": email}, status_code=200)
    return make_response(jsonify(change_result), 200)


@user_blueprint.route('/delete', methods=['DELETE'])
@decorators.user_authorized
def delete_user():
    user_data = jwtmodule.validate_access_token(request.cookies.get('auth-cookie'))

    try:
        req_data = request.get_json()
        email = req_data["email"]
        if email != user_data["sub"]:
            logger.make_api_local_log(request,
                                      "Invalid data in delete request",
                                      {"email": user_data["sub"]}, 403)
            return make_response(jsonify(forbidden_response), 403)
    except:
        logger.make_api_local_log(request,
                                  "Invalid data in delete request",
                                  {"email": user_data["sub"]}, 403)
        return make_response(jsonify(forbidden_response), 403)

    result = db.delete_user_from_db(user_data["sub"])

    if not result["status"]:
        logger.make_api_local_log(request, msg=result["message"], status_code=400)
        return make_response(jsonify(unknown_error), 400)

    logger.make_api_local_log(request,
                              "user deleted by himself",
                              {"email": user_data["username"]})
    return make_response(jsonify(result), 200)
