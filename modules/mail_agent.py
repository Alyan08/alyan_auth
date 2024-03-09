import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from modules.config import MailConfig, HOSTNAME


def send_reg_confirm_email(recipient, token):
    try:
        smtp_server = smtplib.SMTP(host=MailConfig.MAIL_SERVER, port=MailConfig.MAIL_PORT)
        smtp_server.starttls()
        smtp_server.login(MailConfig.MAIL_USERNAME, MailConfig.MAIL_PASSWORD)

        msg = MIMEMultipart()
        msg["From"] = MailConfig.MAIL_USERNAME
        msg["To"] = recipient
        msg["Subject"] = f"Registration {HOSTNAME}"

        text = f"""Your email was indicated in the registration request on website {HOSTNAME}.\n 
            Please confirm your account: \n
            https://{HOSTNAME}/user/confirm?email={recipient}&token={token}\n
            \n
            If you have not submitted a registration request, please follow the link\n
            https://{HOSTNAME}/user/cancel?email={recipient}&token={token}
            """

        msg.attach(MIMEText(text, "plain"))
        smtp_server.sendmail(MailConfig.MAIL_USERNAME, recipient, msg.as_string())
        smtp_server.quit()
        return True
    except Exception as e:
        return False


def send_forgot_password_email(recipient, code):
    try:
        smtp_server = smtplib.SMTP(host=MailConfig.MAIL_SERVER, port=MailConfig.MAIL_PORT)
        smtp_server.starttls()
        smtp_server.login(MailConfig.MAIL_USERNAME, MailConfig.MAIL_PASSWORD)

        msg = MIMEMultipart()
        msg["From"] = MailConfig.MAIL_USERNAME
        msg["To"] = recipient
        msg["Subject"] = f"Restoring password {HOSTNAME}"

        text = f""" You recieved restoring password on {HOSTNAME}.
        \n If you recieved restoring password, enter this code in restoring form: {code}
        \n If it was not you, please, just ignore this message.
            """

        msg.attach(MIMEText(text, "plain"))
        smtp_server.sendmail(MailConfig.MAIL_USERNAME, recipient, msg.as_string())
        smtp_server.quit()
        return True
    except:
        return False


def send_2fa_email(recipient, code):
    try:
        smtp_server = smtplib.SMTP(host=MailConfig.MAIL_SERVER, port=MailConfig.MAIL_PORT)
        smtp_server.starttls()
        smtp_server.login(MailConfig.MAIL_USERNAME, MailConfig.MAIL_PASSWORD)

        msg = MIMEMultipart()
        msg["From"] = MailConfig.MAIL_USERNAME
        msg["To"] = recipient
        msg["Subject"] = f"confirm authentication {HOSTNAME}"

        text = f""" You enter {HOSTNAME}.
        \n verification code: {code}
        \n If it was not you, please, just ignore this message.
            """

        msg.attach(MIMEText(text, "plain"))
        smtp_server.sendmail(MailConfig.MAIL_USERNAME, recipient, msg.as_string())
        smtp_server.quit()
        return True
    except:
        return False
