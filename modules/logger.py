import time
import json
import os


def make_api_local_log(req, msg=None, data=None, status_code=None):
    try:
        log_file = f"app_logs/{time.strftime('%Y-%m-%d')}-app.log"

        os.makedirs('app_logs', exist_ok=True)
        if not os.path.exists(log_file):
            open(log_file, 'w').close()

        report = {
            "date": time.strftime("%Y-%m-%d", time.localtime(time.time())),
            "timestamp": time.strftime("%H:%M:%S", time.localtime(time.time())),
            "entity": "application",
            "host": req.host,
            "path": req.path,
            "source_ip": req.remote_addr
        }
        if req.headers.get('X-Forwarded-For'):
            report["X-Forwarded-For"] = req.headers.get('X-Forwarded-For')
        if msg:
            report["message"] = str(msg)
        if status_code:
            report["status_code"] = status_code

        if data:
            for key, value in data.items():
                report[key] = value

        with open(log_file, 'a') as f:
            f.write(json.dumps(report) + "\n")

    except Exception as e:
        print(e)
        pass


def make_db_local_log():
    report = {

    }
