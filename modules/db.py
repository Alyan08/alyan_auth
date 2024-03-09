import secrets
import time
import uuid
import bcrypt
import psycopg2.pool
from modules.config import DataBaseConfig, AccountConfig
from modules.jwtmodule import generate_refresh_token


def operation_error(message):
    print(message)
    return {"status": False, "message": message}


db_config = {
    "host": DataBaseConfig.DB_HOST,
    "user": DataBaseConfig.DB_USER,
    "password": DataBaseConfig.DB_PASS,
    "database": DataBaseConfig.DB_NAME,
    "port": DataBaseConfig.DB_PORT
}

connection_pool = psycopg2.pool.SimpleConnectionPool(
    minconn=1,
    maxconn=100,
    **db_config
)


def register_new_user(username, password):
    cursor = None
    connection_db = None
    try:
        connection_db = connection_pool.getconn()
        cursor = connection_db.cursor()

        current_time = int(time.time())

        query = "SELECT * FROM private.users WHERE username = %s FOR UPDATE"
        values = (username.lower(),)
        cursor.execute(query, values)
        result = cursor.fetchone()
        if result:
            return operation_error("retrying to register an existing user")

        query = "SELECT * FROM private.reg_users WHERE username = %s FOR UPDATE"
        values = (username.lower(),)
        cursor.execute(query, values)
        reg_was_required = cursor.fetchone()

        if reg_was_required:
            if current_time - reg_was_required[4] < 3 * 86400:
                delete_query = "DELETE FROM private.reg_users WHERE username = %s"
                cursor.execute(delete_query, (username.lower(),))
                connection_db.commit()
            else:
                return operation_error("retrying to register a new user before verifying")

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        reg_token = secrets.token_hex(64)
        insert_query = """INSERT INTO private.reg_users (username, password, reg_token, attempts, reg_req_date) 
            VALUES (%s, %s, %s, %s, %s)"""
        values = (username.lower(), hashed_password, reg_token, AccountConfig.REG_MAX_ATTEMPTS, current_time)
        cursor.execute(insert_query, values)

        connection_db.commit()
        return {
            "status": True,
            "message": "registration request was sent successfully. awaiting confirmation",
            "confirm_token": reg_token
        }

    except Exception as e:
        return operation_error(e)
    finally:
        if cursor:
            cursor.close()
        if connection_db:
            connection_pool.putconn(connection_db)


def approve_user_reg(username, reg_token):
    cursor = None
    connection_db = None
    try:
        connection_db = connection_pool.getconn()
        cursor = connection_db.cursor()

        query = "SELECT * FROM private.users WHERE username = %s FOR UPDATE"
        values = (username.lower(),)
        cursor.execute(query, values)
        result = cursor.fetchone()
        if result:
            return operation_error("retrying to confirm an existing user")

        query = "SELECT reg_token, password, attempts FROM private.reg_users where username = %s"
        cursor.execute(query, (username.lower(),))
        result = cursor.fetchone()

        if result is None:
            return operation_error("attempt to confirm a user without prior registration")

        stored_token, hashed_password_from_reg_users, attempts = result

        if attempts <= 0:
            return operation_error("the number of user verification attempts has been exceeded")

        if reg_token != stored_token:
            return operation_error("invalid registration token")

        query = "UPDATE private.reg_users SET attempts = attempts - 1 WHERE username = %s"
        cursor.execute(query, (username.lower(),))

        query = """INSERT INTO private.users 
            (username, password, usergroup, status, reg_date) 
            VALUES (%s, %s, %s, %s, %s)"""
        cursor.execute(query, (username.lower(), hashed_password_from_reg_users, "default", "active", int(time.time())))

        query = "DELETE FROM private.reg_users WHERE username = %s"
        cursor.execute(query, (username.lower(),))

        connection_db.commit()
        return {"status": True, "message": "user was activated"}
    except Exception as e:
        return operation_error(e)
    finally:
        if cursor:
            cursor.close()
        if connection_db:
            connection_pool.putconn(connection_db)


def delete_reg_req(username, reg_token):
    cursor = None
    connection_db = None
    try:
        connection_db = connection_pool.getconn()
        cursor = connection_db.cursor()

        query = "SELECT reg_token FROM private.reg_users where username = %s"
        cursor.execute(query, (username.lower(),))
        result = cursor.fetchone()

        if not result:
            return operation_error("incorrect email for registration cancel")

        if reg_token != result[0]:
            return operation_error("invalid token for registration cancel")

        query = "DELETE FROM private.reg_users WHERE username = %s"
        cursor.execute(query, (username.lower(),))
        return {"status": True, "message": "registration request was removed successfully"}

    except Exception as e:
        return operation_error(e)
    finally:
        if cursor:
            cursor.close()
        if connection_db:
            connection_pool.putconn(connection_db)


def check_auth_creds(username, received_password):
    cursor = None
    connection_db = None
    try:
        connection_db = connection_pool.getconn()
        cursor = connection_db.cursor()

        query = "SELECT password, usergroup, status, last_login FROM private.users WHERE username = %s"
        cursor.execute(query, (username.lower(),))
        result = cursor.fetchone()

        if not result:
            return operation_error("user is not defined")

        last_login_time = result[3]
        current_time = int(time.time())
        if last_login_time and (current_time - last_login_time) < AccountConfig.RATE_LIMIT_AUTH_PAUSE:
            return operation_error("too many requests. rate-limit block")

        update_query = "UPDATE private.users SET last_login = %s WHERE username = %s"
        cursor.execute(update_query, (current_time, username.lower()))
        connection_db.commit()

        if result[2] not in AccountConfig.ACTIVE_STATUSES:
            return operation_error("user is not active")

        stored_password = result[0]
        hash_pass = stored_password.encode('utf-8')

        if not bcrypt.checkpw(received_password.encode('utf-8'), hash_pass):
            return operation_error("wrong password")

        return {
            "status": True,
            "user_info": {"sub": username, "usergroup": result[1]},
            "message": "login successful"
        }

    except Exception as e:
        return operation_error(e)
    finally:
        if cursor:
            cursor.close()
        if connection_db:
            connection_pool.putconn(connection_db)


def get_db_user_info(username):
    cursor = None
    connection_db = None
    try:
        connection_db = connection_pool.getconn()
        cursor = connection_db.cursor()
        query = "SELECT usergroup, status, reg_date FROM private.users WHERE username = %s"
        cursor.execute(query, (username.lower(),))

        result = cursor.fetchone()
        return {
            "status": True,
            "username": username,
            "usergroup": result[0],
            "user_status": result[1],
            "reg_date": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(result[2])),
            "message": "success user info request"
        }

    except Exception as e:
        return operation_error(e)
    finally:
        if cursor:
            cursor.close()
        if connection_db:
            connection_pool.putconn(connection_db)


def create_refresh_token(username):
    cursor = None
    connection_db = None
    try:
        connection_db = connection_pool.getconn()
        cursor = connection_db.cursor()
        payload = {"sub": username.lower(), "refresh_token_uuid": str(uuid.uuid4())}
        refresh = generate_refresh_token(payload)

        query = "SELECT * FROM private.refresh_tokens WHERE username =  %s"
        cursor.execute(query, (username.lower(),))

        if not cursor.fetchone():
            query = "INSERT INTO private.refresh_tokens (username, refresh_jwt) VALUES (%s, %s)"
            cursor.execute(query, (username.lower(), 1))

        query = "UPDATE private.refresh_tokens SET refresh_jwt = %s WHERE username = %s"
        values = (refresh, username.lower())
        cursor.execute(query, values)
        connection_db.commit()

        return {"status": True, "message": "refresh token created", "refresh": refresh}

    except Exception as e:
        return operation_error(e)
    finally:
        if cursor:
            cursor.close()
        if connection_db:
            connection_pool.putconn(connection_db)


def use_and_update_refresh_token(refresh):
    cursor = None
    connection_db = None
    try:
        connection_db = connection_pool.getconn()
        cursor = connection_db.cursor()

        query = "SELECT username FROM private.refresh_tokens WHERE refresh_jwt = %s"
        cursor.execute(query, (refresh,))
        result = cursor.fetchone()

        if not result:
            return operation_error("wrong refresh token")

        payload = {"sub": result[0], "refresh_token_uuid": str(uuid.uuid4())}
        new_refresh = generate_refresh_token(payload)
        query = "UPDATE private.refresh_tokens SET refresh_jwt = %s WHERE username = %s"
        values = (new_refresh, result[0])
        cursor.execute(query, values)
        connection_db.commit()

        return {"status": True, "username": result[0], "message": "new refresh token created", "refresh": new_refresh}

    except Exception as e:
        return operation_error(e)
    finally:
        if cursor:
            cursor.close()
        if connection_db:
            connection_pool.putconn(connection_db)


def generate_multi_factor_code(username, code_long=None):
    cursor = None
    connection_db = None
    try:
        connection_db = connection_pool.getconn()
        cursor = connection_db.cursor()

        query = "SELECT day_limit_time_mark, create_time, count FROM private.multi_factor_codes WHERE username = %s"
        cursor.execute(query, (username.lower(),))
        result = cursor.fetchone()

        current_time = int(time.time())

        if not result:
            # if user never required pin code
            if not code_long:
                code_long = 6
            multi_factor_code = ''.join(secrets.choice('0123456789') for _ in range(code_long))
            print(multi_factor_code, "code generated")

            query = """INSERT INTO private.multi_factor_codes 
                           (username, code, day_limit_time_mark, create_time, count, attempts) 
                           VALUES (%s, %s, %s, %s, %s, %s)
                    """
            values = (username.lower(), multi_factor_code, current_time, current_time, 1, 0)
            cursor.execute(query, values)
            connection_db.commit()

            return {
                "status": True,
                "message": "short code created",
                "code": multi_factor_code
            }

        # checking that last generated code is stile alive
        if current_time - result[1] < AccountConfig.MULTI_FACTOR_LIFE_TIME:
            return operation_error(f"too frequent requests")

        # checking for day rate-limit
        if ((current_time - result[0]) <= 24 * 60 * 60) and result[2] > AccountConfig.MULTI_FACTOR_DAY_COUNT:
            return operation_error("daily limit exceeded")

        multi_factor_code = ''.join(secrets.choice('0123456789') for _ in range(6))
        print(multi_factor_code, "code RE-generated")
        query = f"""UPDATE private.multi_factor_codes 
                    SET code = %s,
                        count = count + 1,
                        create_time = %s,
                        attempts = 0
                    WHERE username = %s"""
        values = (multi_factor_code, current_time, username.lower())
        cursor.execute(query, values)
        connection_db.commit()

        if (current_time - result[0]) > 24 * 60 * 60:
            query = f"""UPDATE private.multi_factor_codes 
                        SET day_limit_time_mark = {current_time},
                            count = 1"""
            cursor.execute(query)
            connection_db.commit()

        return {
            "status": True,
            "message": "short code created",
            "code": multi_factor_code
        }

    except Exception as e:
        return operation_error(e)
    finally:
        if cursor:
            cursor.close()
        if connection_db:
            connection_pool.putconn(connection_db)


def check_multi_factor_code(username, received_code):
    cursor = None
    connection_db = None
    try:
        connection_db = connection_pool.getconn()
        cursor = connection_db.cursor()

        query = "SELECT code, create_time, attempts FROM private.multi_factor_codes WHERE username = %s"
        cursor.execute(query, (username.lower(),))
        result = cursor.fetchone()

        if not result:
            return operation_error(f"code was not requested by the {username}")

        if (int(time.time()) - result[1]) > AccountConfig.MULTI_FACTOR_LIFE_TIME:
            return operation_error("PIN-code lifetime expired")

        if result[2] > AccountConfig.MULTI_FACTOR_ATTEMPTS:
            return operation_error("too many attempts")

        if int(received_code) != result[0]:
            query = f"""UPDATE private.multi_factor_codes 
                                SET attempts = attempts + 1
                                WHERE username = %s"""
            values = (username.lower(), )
            cursor.execute(query, values)
            connection_db.commit()
            return operation_error("wrong PIN-code 1111111111111111111")

        query = f"""UPDATE private.multi_factor_codes 
                                        SET code = NULL
                                        WHERE username = %s"""
        values = (username.lower(),)
        cursor.execute(query, values)
        connection_db.commit()
        return {"status": True, "message": "PIN-code confirmed"}

    except Exception as e:
        return operation_error(e)
    finally:
        if cursor:
            cursor.close()
        if connection_db:
            connection_pool.putconn(connection_db)


def change_password(username, new_password):
    cursor = None
    connection_db = None
    try:
        connection_db = connection_pool.getconn()
        cursor = connection_db.cursor()

        new_password_hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        query = "UPDATE private.users SET password = %s WHERE username = %s"
        cursor.execute(query, (new_password_hashed, username.lower()))
        connection_db.commit()
        return {"status": True, "message": "password was changed"}

    except Exception as e:
        return operation_error(e)
    finally:
        if cursor:
            cursor.close()
        if connection_db:
            connection_pool.putconn(connection_db)


def change_usergroup(username, new_usergroup):
    cursor = None
    connection_db = None
    try:
        connection_db = connection_pool.getconn()
        cursor = connection_db.cursor()

        query = "SELECT usergroup FROM private.users WHERE username = %s FOR UPDATE"
        cursor.execute(query, (username.lower(),))
        query = "UPDATE private.users SET usergroup = %s WHERE username = %s"
        cursor.execute(query, (new_usergroup, username.lower()))
        connection_db.commit()
        return {"status": True, "message": f"usergroup was changed to {new_usergroup}"}

    except Exception as e:
        return operation_error(e)
    finally:
        if cursor:
            cursor.close()
        if connection_db:
            connection_pool.putconn(connection_db)


def change_status(username, new_status):
    cursor = None
    connection_db = None
    try:
        connection_db = connection_pool.getconn()
        cursor = connection_db.cursor()

        query = "SELECT * FROM private.users WHERE username = %s FOR UPDATE"
        cursor.execute(query, (username.lower(),))
        query = "UPDATE private.users SET status = %s WHERE username = %s"
        cursor.execute(query, (new_status, username.lower()))
        connection_db.commit()
        return {"status": True, "message": f"status was changed to '{new_status}'"}

    except Exception as e:
        return operation_error(e)
    finally:
        if cursor:
            cursor.close()
        if connection_db:
            connection_pool.putconn(connection_db)


def delete_user_from_db(username):
    cursor = None
    connection_db = None
    try:
        connection_db = connection_pool.getconn()
        cursor = connection_db.cursor()
        query = "DELETE FROM private.users WHERE username = %s"
        cursor.execute(query, (username.lower(),))
        connection_db.commit()
        return {"status": True, "message": f"user {username} was deleted"}

    except Exception as e:
        return operation_error(e)
    finally:
        if cursor:
            cursor.close()
        if connection_db:
            connection_pool.putconn(connection_db)


def get_all_users_list(limit=None):
    cursor = None
    connection_db = None
    try:
        connection_db = connection_pool.getconn()
        cursor = connection_db.cursor()

        if limit is not None:
            query = "SELECT username, usergroup, status, reg_date FROM private.users LIMIT %s"
            cursor.execute(query, (limit,))
        else:
            query = "SELECT username, usergroup, status,reg_date FROM private.users"
            cursor.execute(query)

        result = cursor.fetchall()
        return {"status": True, "users_list": result}

    except Exception as e:
        return operation_error(e)
    finally:
        if cursor:
            cursor.close()
        if connection_db:
            connection_pool.putconn(connection_db)
