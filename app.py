from flask import Flask
from routes import admin_routes, app_routes
from routes import user_routes
import setup
from modules import config


setup.generate_keys()
setup.create_admin()

app = Flask(__name__)

app.config.from_object(config.MailConfig)

app.register_blueprint(admin_routes.admin_routes, url_prefix='/admin')
app.register_blueprint(admin_routes.user_edit, url_prefix='/admin/user_edit')
app.register_blueprint(user_routes.user_blueprint, url_prefix='/user')
app.register_blueprint(app_routes.app_blueprint, url_prefix='/app')


if __name__ == '__main__':
    app.run(debug=False)
