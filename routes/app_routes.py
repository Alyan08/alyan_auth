from flask import request, Blueprint, jsonify, make_response
from modules import config


app_blueprint = Blueprint('app_bp', __name__)


@app_blueprint.route('/get-cert', methods=["GET"])
def get_cert():
    if request.method == 'GET':
        return make_response(jsonify({"JWT Public key": config.PUBLIC_KEY}))


@app_blueprint.route('/hc', methods=["GET"])
def hc():
    return make_response(jsonify({"service": "up"}))
