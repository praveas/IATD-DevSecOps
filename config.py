import os
import connexion
from flask_sqlalchemy import SQLAlchemy
import sqlite3  
from constants import APPLICATION_JSON, INVALID_TOKEN

vuln_app = connexion.App(__name__, specification_dir='./openapi_specs')

SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(vuln_app.app.root_path, 'database/database.db')
vuln_app.app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
vuln_app.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

vuln_app.app.config['SECRET_KEY'] = os.getenv("VULVAPP_SECRETKEY")
# start the db
db = SQLAlchemy(vuln_app.app)
vuln_conn = sqlite3.connect(os.path.join(vuln_app.app.root_path, 'database/database.db') , check_same_thread=False)

vuln_app.add_api('openapi3.yml')