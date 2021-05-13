from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from os import path
import confuse
import jinja2
import random


def make_random_yml_token(length):
    # Make character list
    chars = ''.join([chr(i) for i in range(33, 122)])
    token = ''.join([random.choice(chars) for _ in range(length)])
    # Keep making tokens until get a good one.
    while token[0] in ',@&*#->!':  # TODO filter tokens better then this
        token = ''.join([random.choice(chars) for _ in range(length)])
    return token


# Make the Flask object
app = Flask(__name__)

# Check config.yml and if not found make one
config_file = confuse.Configuration('WebApp', __name__)
if not path.isfile('config.yml'):  # if there is no config, we will make one.
    template = jinja2.Template(open('WebApp/config_template.yml', 'r').read())
    with open('config.yml', 'w') as fo:
        admin_password = make_random_yml_token(15)
        # Print this once and never again
        print(f'[**] The randomly generated admin password is: {admin_password}')
        print('[**] Note, you will need to change the admin password.')
        buff = template.render(secret=make_random_yml_token(64),
                               default_admin_password=admin_password
                               )
        # Make the config file
        fo.write(buff)

# load config file
config_file.set_file('config.yml')

# Set Flask Configurations
app.config['SECRET_KEY'] = config_file['Flask']['secret'].get(str)
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{ config_file['Flask']['database_name'].get(str) }"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# a place for holding invite keys
inviteKeyList = []

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# If there is no database we make one
dbPath = path.abspath("WebApp/" + config_file['Flask']['database_name'].get(str))

# Make the database if there isn't one
if not path.exists(dbPath):
    from WebApp import functions
    functions.makeDB()

#  We have to do it this way I guess
#  https://flask.palletsprojects.com/en/1.1.x/patterns/packages/
from WebApp import routes









