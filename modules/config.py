import os


HOSTNAME = "127.0.0.1:5000"

PRIVATE_KEY = os.environ.get('PRIVATE_KEY', None)
PUBLIC_KEY = os.environ.get('PUBLIC_KEY', None)
JWT_EXPIRATION_TIME = 3600
REFRESH_JWT_EXPIRATION_TIME = 24 * 3600


class DataBaseConfig:
    DB_VERSION = 'postgresql'
    DB_HOST = 'localhost'
    DB_USER = 'postgres'
    DB_PASS = 'postgres'
    DB_PORT = 5432
    DB_NAME = 'users'


class MailConfig:
    MAIL_SERVER = 'smtp.alyan.alyan'
    MAIL_PORT = 587
    MAIL_USERNAME = 'alyan@alyan.alyan'
    MAIL_PASSWORD = '123123'


class AccountConfig:
    ACTIVE_STATUSES = ["active"]
    REG_MAX_ATTEMPTS = 15
    RATE_LIMIT_AUTH_PAUSE = 10
    #  RATE_LIMIT_LOGIN_PAUSE in seconds
    REGISTRATION_REQ_PAUSE = 3
    # REGISTRATION_REQ_PAUSE in days
    EMAIL_EDIT_ALLOWED = False
    SHORT_CODE_REQ_PAUSE = 24 * 3600
    MULTI_FACTOR_REQUIRED = False
    MULTI_FACTOR_CHANNEL = "mail"
    MULTI_FACTOR_DAY_COUNT = 30
    MULTI_FACTOR_LIFE_TIME = 60
    MULTI_FACTOR_ATTEMPTS = 3

