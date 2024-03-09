from flask import request, Blueprint, make_response, jsonify
from modules.validation import isvalid
from modules import decorators
from modules import db


data_error = {"status": "error", "message": "invalid data"}
unknown_error = {"status": "error", "message": "Something was wrong"}

admin_routes = Blueprint('admin_routes', __name__)
user_edit = Blueprint('user_edit', __name__)


@admin_routes.route('/all-users', methods=['GET'])
@decorators.admin_authorized
def all_users():
    limit = request.args.get('limit')
    if limit is not None:
        if not limit.isdigit() or int(limit) < 0:
            return make_response(jsonify({"error": "Invalid limit parameter. Must be an integer and > 0."}), 400)
        limit = int(limit)
    get_users_list = db.get_all_users_list(limit=limit)
    if not get_users_list["status"]:
        return make_response(jsonify(unknown_error), 400)
    return get_users_list["users_list"]


@user_edit.route('/change_status', methods=['POST'])
@decorators.admin_authorized
@decorators.validate_post_json
def change_user_status():
    req_data = request.get_json(silent=True)
    try:
        username = req_data['email']
        new_status = req_data['status']
    except:
        return make_response(jsonify(data_error), 400)
    if not isvalid('email', username):
        return make_response(jsonify(data_error), 400)
    db_result = db.change_status(username, new_status)
    if not db_result["status"]:
        return make_response(jsonify(db_result), 500)
    return make_response(jsonify(db_result), 200)


@user_edit.route('/delete_user', methods=['POST'])
@decorators.admin_authorized
@decorators.validate_post_json
def delete_user():
    try:
        req_data = request.get_json(silent=True)
        username = req_data['email']
    except:
        return make_response(jsonify(data_error), 400)

    if not isvalid('email', username):
        return make_response(jsonify(data_error), 400)

    db_result = db.delete_user_from_db(username)
    if not db_result["status"]:
        return make_response(jsonify(db_result), 500)
    return make_response(jsonify(db_result), 200)
