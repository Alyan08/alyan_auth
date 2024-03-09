import os
import bcrypt
import psycopg2
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from modules import config


def generate_keys():

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    os.environ["PRIVATE_KEY"] = private_key_pem.decode()
    os.environ["PUBLIC_KEY"] = public_key_pem.decode()

    config.PUBLIC_KEY = os.environ.get('PUBLIC_KEY', None)
    config.PRIVATE_KEY = os.environ.get('PRIVATE_KEY', None)


def check_admin_exists(cursor):
    query = "SELECT * FROM private.users WHERE usergroup = %s"
    cursor.execute(query, ("admin",))
    return cursor.fetchone() is not None


def create_admin():
    cursor = None
    connection_setup = None
    db_config = {
        "host": config.DataBaseConfig.DB_HOST,
        "user": config.DataBaseConfig.DB_USER,
        "password": config.DataBaseConfig.DB_PASS,
        "database": config.DataBaseConfig.DB_NAME
    }

    try:
        connection_setup = psycopg2.connect(**db_config)
        cursor = connection_setup.cursor()

        create_table_query = """
                    CREATE TABLE IF NOT EXISTS private.users (
                        user_id SERIAL PRIMARY KEY,
                        username VARCHAR(255) NOT NULL,
                        password VARCHAR(255) NOT NULL,
                        usergroup VARCHAR(50) NOT NULL,
                        status VARCHAR(50) NOT NULL,
                        last_login INTEGER,
                        reg_date INTEGER
                    )
                """
        cursor.execute(create_table_query)
        connection_setup.commit()

        create_table_query = """
                            CREATE TABLE IF NOT EXISTS private.reg_users (
                                id SERIAL PRIMARY KEY,
                                username VARCHAR(255) NOT NULL,
                                password VARCHAR(255) NOT NULL,
                                reg_token VARCHAR(255) NOT NULL,
                                attempts SMALLINT,
                                reg_req_date INTEGER
                            )
                        """
        cursor.execute(create_table_query)
        connection_setup.commit()

        create_table_query = """
                                    CREATE TABLE IF NOT EXISTS private.refresh_tokens (
                                        id SERIAL PRIMARY KEY,
                                        username VARCHAR(255) NOT NULL,
                                        refresh_jwt VARCHAR(1000)                                        
                                    )
                                """

        cursor.execute(create_table_query)
        connection_setup.commit()

        create_table_query = """
                                            CREATE TABLE IF NOT EXISTS private.multi_factor_codes (
                                                id SERIAL PRIMARY KEY,
                                                username VARCHAR(255) NOT NULL,
                                                code INTEGER,
                                                day_limit_time_mark INTEGER NOT NULL,
                                                create_time INTEGER NOT NULL,
                                                count SMALLINT,
                                                attempts SMALLINT                                       
                                            )
                                        """

        cursor.execute(create_table_query)
        connection_setup.commit()

        if not check_admin_exists(cursor):
            login = input('Enter web-app admin login: ')
            password = input('Enter web-app admin password: ')
            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
            
            query = "INSERT INTO private.users (username, password, usergroup, status) VALUES (%s, %s, %s, %s)"
            values = (login, hashed_password, "admin", "active")
            cursor.execute(query, values)
            connection_setup.commit()

    except (Exception, psycopg2.Error) as error:
        print("Error:", error)
    finally:
        if cursor:
            cursor.close()
        if connection_setup:
            connection_setup.close()


LOG_FILE = f"app_logs/{time.strftime('%Y-%m-%d')}-app.log"

os.makedirs('app_logs', exist_ok=True)
if not os.path.exists(LOG_FILE):
    open(LOG_FILE, 'w').close()
