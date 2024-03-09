import time
import jwt
from . import config


def generate_access_jwt(payload):
    private_key = config.PRIVATE_KEY
    #  exp time in config. do not configure in this file
    exp_time = config.JWT_EXPIRATION_TIME
    payload['iat'] = int(time.time())
    payload['exp'] = int(time.time()) + exp_time
    payload['iss'] = config.HOSTNAME
    payload["type"] = "access"

    jwt_token = jwt.encode(payload, private_key, algorithm='RS256')
    return jwt_token


def generate_refresh_token(payload):
    private_key = config.PRIVATE_KEY
    #  exp time in config. do not configure in this file
    exp_time = config.REFRESH_JWT_EXPIRATION_TIME
    payload['iat'] = int(time.time())
    payload['exp'] = int(time.time()) + exp_time
    payload['iss'] = config.HOSTNAME
    payload["type"] = "refresh"

    refresh_token = jwt.encode(payload, private_key, algorithm='RS256')
    return refresh_token


def generate_otp_token(username):
    private_key = config.PRIVATE_KEY
    #  exp time in config. do not configure in this file
    exp_time = int(time.time()) + config.AccountConfig.MULTI_FACTOR_LIFE_TIME
    payload = {"sub": username, "type": "otp_token", "exp": exp_time}

    otp_token = jwt.encode(payload, private_key, algorithm='RS256')
    return otp_token


def validate_access_token(jwt_token):
    public_key = config.PUBLIC_KEY
    try:
        payload = jwt.decode(jwt_token, public_key, algorithms=['RS256'])
        print(payload)
        return {
            "status": "valid",
            "sub": payload['sub'],
            "usergroup": payload["usergroup"],
            "iss": payload["iss"],
            "type": payload["type"]
        }
    except jwt.ExpiredSignatureError:
        return {"status": "expired"}
    except:
        return {"status": "invalid"}


def validate_otp_token(opt_token):
    public_key = config.PUBLIC_KEY
    try:
        payload = jwt.decode(opt_token, public_key, algorithms=['RS256'])
        return {"status": "valid", "sub": payload['sub']}
    except jwt.ExpiredSignatureError:
        return {"status": "expired"}
    except:
        return {"status": "invalid"}


def validate_refresh_token(refresh):
    public_key = config.PUBLIC_KEY
    try:
        payload = jwt.decode(refresh, public_key, algorithms=['RS256'])
        return {"status": "valid",
                "sub": payload['sub'],
                "refresh_token_uuid": payload["refresh_token_uuid"],
                "iss": payload["iss"],
                "type": payload["type"]
                }
    except jwt.ExpiredSignatureError:
        return {"status": "expired"}
    except:
        return {"status": "invalid"}


def get_jwt_info(jwt_token):
    public_key = config.PUBLIC_KEY
    try:
        payload = jwt.decode(jwt_token, public_key, algorithms=['RS256'])
        payload["status"] = "valid"
        return payload
    except jwt.ExpiredSignatureError:
        return {"status": "expired"}
    except:
        return {"status": "invalid"}


def is_admin(jwt_token):
    public_key = config.PUBLIC_KEY
    try:
        payload = jwt.decode(jwt_token, public_key, algorithms=['RS256'])
        if payload and payload["usergroup"] == "admin":
            return True
        else:
            return False
    except:
        return False

