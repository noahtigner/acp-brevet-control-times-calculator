"""
Replacement for RUSA ACP brevet time calculator
(see https://rusa.org/octime_acp.html)

"""

import flask
from flask import Flask, redirect, url_for, request, render_template, flash, session
from flask_restful import Resource, Api
import arrow  # Replacement for datetime, based on moment.js
import acp_times  # Brevet time calculations
import config
import logging
import pymongo
from pymongo import MongoClient
import os
from forms import LoginForm, RegisterForm
from flask_login import (LoginManager, current_user, login_required,
                            login_user, logout_user, UserMixin, 
                            confirm_login, fresh_login_required)
from password import hash_password, verify_password
import random
from itsdangerous import (TimedJSONWebSignatureSerializer \
                                  as Serializer, BadSignature, \
                                  SignatureExpired)
import time
from flask_wtf.csrf import CSRFProtect
from urllib.parse import urlparse, urljoin



###
# Globals
###

app = Flask(__name__)
api = Api(app)
CONFIG = config.configuration()
app.secret_key = CONFIG.SECRET_KEY
csrf = CSRFProtect(app)
# client = MongoClient(os.environ['DB_PORT_27017_TCP_ADDR'], 27017)
client = MongoClient('mongodb://mongodb:27017/')
db = client.tododb
DEFAULT = 10 # top default for resources

users = db.usersdb

RECORDS = {}

###
# Pages
###


@app.route("/")
@app.route("/index")
def index():
    app.logger.debug("Main page entry")
    return flask.render_template('calc.html')


@app.errorhandler(404)
def page_not_found(error):
    app.logger.debug("Page not found")
    flask.session['linkback'] = flask.url_for("index")
    return flask.render_template('404.html'), 404


###############
#
# AJAX request handlers
#   These return JSON, rather than rendering pages.
#
###############
@app.route("/_calc_times")
def _calc_times():
    """
    Calculates open/close times from miles, using rules
    described at https://rusa.org/octime_alg.html.
    Expects one URL-encoded argument, the number of miles.
    """
    app.logger.debug("Got a JSON request")
    km = request.args.get('km', type=float)
    app.logger.debug("km={}".format(km))
    app.logger.debug("request.args: {}".format(request.args))

    distance = request.args.get('distance', type=float)
    begin_date = request.args.get('bd', "", type=str)
    begin_time = request.args.get('bt', "", type=str)
    row = request.args.get("row")
    begin = arrow.get(begin_date + " " + begin_time, 'YYYY-MM-DD HH:mm').isoformat()

    if km is None:
        del RECORDS[row]    
        result = {"failed": True}
    else:

        open_time = acp_times.open_time(km, distance, begin)
        close_time = acp_times.close_time(km, distance, begin)
        result = {"failed": False, "open": open_time, "close": close_time}

        # RECORDS[str(int(km))] = (open_time, close_time) # Add an entry's times to the list of entries
        print("//////////////////// kilometers:" + str(km))
        RECORDS[row] = [km, open_time, close_time]  # Add an entry's times to the list of entries

    return flask.jsonify(result=result)

@app.route("/submit")
def _submit():
    """
    Save the entries listed on screen into the database
    """
    
    try:
        if len(RECORDS) == 0:
            result = {"success": False, "error": "Nothing to submit"}
            return flask.jsonify(result=result)
            
        db.tododb.delete_many({})    # Clear the old db

        # Add each record in RECORDS to the db
        for value in RECORDS.values():
            record = {
                # 'key': key,
                'km': value[0],
                'open': value[1],
                'close': value[2]
            }
            db.tododb.insert_one(record)
            # db.tododb.update_one({'key': key}, {'open': value[0], 'close': value[1]}, True)

        result = {"success": True}
    except:
        result = {"success": False, "error": "Failed to submit to db"}

    return flask.jsonify(result=result)

@app.route("/display")
@login_required
def _display():
    """
    Display all saved brevet times
    """
    RECORDS.clear()

    _items = db.tododb.find()
    items = [item for item in _items]

    for item in items:
        # Formatting
        item['open'] = arrow.get(item['open']).format('dddd D/M HH:mm')
        item['close'] = arrow.get(item['close']).format('dddd D/M HH:mm')

    return render_template('display.html', items=items)

class All(Resource):
    def get(self):

        # Grab token from session variable or request arg
        if "token" in session:
            if session['token'] == None:
                token = request.args.get('token')
            else:
                token = session['token']
        else:
            token = request.args.get('token')

        # Authentication failure
        if token == None:
            return "Please login and access /api/token to be issued a token", 401
        elif verify_auth_token(token) == None:
            return "Authentication Failed, 401", 401


        top = request.args.get("top")

        if(top==None):
            top = DEFAULT

        _items = db.tododb.find().sort("open", pymongo.ASCENDING).limit(int(top))
        items = [item for item in _items]

        return {
            'open': [arrow.get(item['open']).format('dddd D/M HH:mm') for item in items],
            'close': [arrow.get(item['close']).format('dddd D/M HH:mm') for item in items]
        }

class AllJSON(Resource):
    def get(self):

        # Grab token from session variable or request arg
        if "token" in session:
            if session['token'] == None:
                token = request.args.get('token')
            else:
                token = session['token']
        else:
            token = request.args.get('token')
            
        # Authentication failure
        if token == None:
            return "Please login and access /api/token to be issued a token", 401
        elif verify_auth_token(token) == None:
            return "Authentication Failed, 401", 401

        top = request.args.get("top")

        if(top==None):
            top = DEFAULT

        _items = db.tododb.find().sort("open", pymongo.ASCENDING).limit(int(top))
        items = [item for item in _items]

        return {
            'open': [arrow.get(item['open']).format('dddd D/M HH:mm') for item in items],
            'close': [arrow.get(item['close']).format('dddd D/M HH:mm') for item in items]
        }

class AllCSV(Resource):
    def get(self):

        # Grab token from session variable or request arg
        if "token" in session:
            if session['token'] == None:
                token = request.args.get('token')
            else:
                token = session['token']
        else:
            token = request.args.get('token')
            
        # Authentication failure
        if token == None:
            return "Please login and access /api/token to be issued a token", 401
        elif verify_auth_token(token) == None:
            return "Authentication Failed, 401", 401

        top = request.args.get("top")

        if(top==None):
            top = DEFAULT

        _items = db.tododb.find().sort("open", pymongo.ASCENDING).limit(int(top))
        items = [item for item in _items]

        all_csv = ""
        for item in items:
            all_csv += arrow.get(item['open']).format('dddd D/M HH:mm') + ',' + arrow.get(item['close']).format('dddd D/M HH:mm') + ','
        return all_csv

class Open(Resource):
    def get(self):

        # Grab token from session variable or request arg
        if "token" in session:
            if session['token'] == None:
                token = request.args.get('token')
            else:
                token = session['token']
        else:
            token = request.args.get('token')
            
        # Authentication failure
        if token == None:
            return "Please login and access /api/token to be issued a token", 401
        elif verify_auth_token(token) == None:
            return "Authentication Failed, 401", 401

        top = request.args.get("top")

        if(top==None):
            top = DEFAULT

        _items = db.tododb.find().sort("open", pymongo.ASCENDING).limit(int(top))
        items = [item for item in _items]

        return {
            'open': [arrow.get(item['open']).format('dddd D/M HH:mm') for item in items]
        }

class OpenJSON(Resource):
    def get(self):

        # Grab token from session variable or request arg
        if "token" in session:
            if session['token'] == None:
                token = request.args.get('token')
            else:
                token = session['token']
        else:
            token = request.args.get('token')
            
        # Authentication failure
        if token == None:
            return "Please login and access /api/token to be issued a token", 401
        elif verify_auth_token(token) == None:
            return "Authentication Failed, 401", 401

        top = request.args.get("top")

        if(top==None):
            top = DEFAULT

        _items = db.tododb.find().sort("open", pymongo.ASCENDING).limit(int(top))
        items = [item for item in _items]

        return {
            'open': [arrow.get(item['open']).format('dddd D/M HH:mm') for item in items]
        }

class OpenCSV(Resource):
    def get(self):

        # Grab token from session variable or request arg
        if "token" in session:
            if session['token'] == None:
                token = request.args.get('token')
            else:
                token = session['token']
        else:
            token = request.args.get('token')
            
        # Authentication failure
        if token == None:
            return "Please login and access /api/token to be issued a token", 401
        elif verify_auth_token(token) == None:
            return "Authentication Failed, 401", 401

        top = request.args.get("top")

        if(top==None):
            top = DEFAULT

        _items = db.tododb.find().sort("open", pymongo.ASCENDING).limit(int(top))
        items = [item for item in _items]

        open_csv = ""
        for item in items:
            open_csv += arrow.get(item['open']).format('dddd D/M HH:mm') + ','
        return open_csv

class Close(Resource):
    def get(self):

        # Grab token from session variable or request arg
        if "token" in session:
            if session['token'] == None:
                token = request.args.get('token')
            else:
                token = session['token']
        else:
            token = request.args.get('token')
            
        # Authentication failure
        if token == None:
            return "Please login and access /api/token to be issued a token", 401
        elif verify_auth_token(token) == None:
            return "Authentication Failed, 401", 401

        top = request.args.get("top")

        if(top==None):
            top = DEFAULT

        _items = db.tododb.find().sort("close", pymongo.ASCENDING).limit(int(top))
        items = [item for item in _items]

        return {
            'close': [arrow.get(item['close']).format('dddd D/M HH:mm') for item in items]
        }

class CloseJSON(Resource):
    def get(self):

        # Grab token from session variable or request arg
        if "token" in session:
            if session['token'] == None:
                token = request.args.get('token')
            else:
                token = session['token']
        else:
            token = request.args.get('token')
            
        # Authentication failure
        if token == None:
            return "Please login and access /api/token to be issued a token", 401
        elif verify_auth_token(token) == None:
            return "Authentication Failed, 401", 401

        top = request.args.get("top")

        if(top==None):
            top = DEFAULT

        _items = db.tododb.find().sort("close", pymongo.ASCENDING).limit(int(top))
        items = [item for item in _items]

        return {
            'close': [arrow.get(item['close']).format('dddd D/M HH:mm') for item in items]
        }

class CloseCSV(Resource):
    def get(self):

        # Grab token from session variable or request arg
        if "token" in session:
            if session['token'] == None:
                token = request.args.get('token')
            else:
                token = session['token']
        else:
            token = request.args.get('token')
            
        # Authentication failure
        if token == None:
            return "Please login and access /api/token to be issued a token", 401
        elif verify_auth_token(token) == None:
            return "Authentication Failed, 401", 401

        top = request.args.get("top")

        if(top==None):
            top = DEFAULT

        _items = db.tododb.find().sort("close", pymongo.ASCENDING).limit(int(top))
        items = [item for item in _items]

        close_csv = ""
        for item in items:
            close_csv += arrow.get(item['close']).format('dddd D/M HH:mm') + ','
        return close_csv

api.add_resource(All, '/listAll')
api.add_resource(AllJSON, '/listAll/json')
api.add_resource(AllCSV, '/listAll/csv')

api.add_resource(Open, '/listOpenOnly')
api.add_resource(OpenJSON, '/listOpenOnly/json')
api.add_resource(OpenCSV, '/listOpenOnly/csv')

api.add_resource(Close, '/listCloseOnly')
api.add_resource(CloseJSON, '/listCloseOnly/json')
api.add_resource(CloseCSV, '/listCloseOnly/csv')

# For testing
@app.route('/api/a', methods=['GET', 'POST'])
def a():
    _users = db.usersdb.find()
    users = [user for user in _users]
    result = {}
    for user in users:
        flash(user['username'])
    return flask.jsonify(result=result)

@app.route('/api/login', methods=['GET', 'POST'])
def login():
    """
    Verifies that the user exists and the password matches
    """
    form = LoginForm()
    if form.validate_on_submit():
        # flash('Login requested for user {}, remember_me={}'.format(
        #     form.username.data, form.remember_me.data))
        # flash('Pass: {} -> {}'.format(form.password.data, hash_password(form.password.data)))

        user = users.find_one({"username": form.username.data})
        if user == None:
            flash("Username not found. Please register.")
            return redirect(url_for('register'))


        password = user['password']
        if not verify_password(form.password.data, password):
            flash("Incorrect Password")
            return redirect(url_for('login'))

        u = User(user['id'])
        session['id'] = user['id']
        if login_user(u, remember=form.remember_me.data):
            flash("login successful")
            # u.set_authenticated(True)
        else:
            flash("failed to login")

        next = request.args.get("next")
        if not is_safe_url(next):
            return flask.abort(400)
        if next:
            return redirect(next)
        return redirect('/')

    return render_template('login.html',  title='Sign In', form=form)

@app.route('/api/register', methods=['GET', 'POST'])
def register():
    """
    Stores the username and password, along with a unique id
    """
    form = RegisterForm()
    if form.validate_on_submit():
        # flash('Register requested for user {}, remember_me={}'.format(
        #     form.username.data, form.remember_me.data))
        # flash('Pass: {} -> {}'.format(form.password.data, hash_password(form.password.data)))

        new_ID = newID()
        new_hash = hash_password(form.password.data)

        new_user = {
            "id": new_ID,
            "username": form.username.data,
            "password": new_hash
        }
        users.insert_one(new_user)

        results = {
            "Location": new_ID,
            "username": form.username.data,
            "password": new_hash
        }

        session['token'] = None

        return flask.jsonify({'Location': url_for('get_user', username=form.username.data, _external=True), 'id': new_ID, 'username': form.username.data, 'password': new_hash}), 201

    return render_template('register.html',  title='Register', form=form)


@app.route('/api/users/<username>')
def get_user(username):
    """
    Utility for getting the URI of the new user
    """
    user = db.usersdb.find({'username': username})
    if not user:
        flask.abort(400)
    return flask.jsonify({'username': user['username'],'id':user['id']})


def newID():
    """
    Generates a new unique id
    """
    return random.randint(1, 999999)

class User(UserMixin):

    def __init__(self, id, active=True):
        self.id = id #.decode('utf8')
        self.active = active
        # self.authenticated = False

    # def is_active(self):
    #     return self.active

    # def is_authenticated(self):
    #     return True

    # # def set_authenticated(self, auth):
    # #         self.authenticated = auth

    # def is_anonymous(self):
    #     return False

    def get_id(self):
        return self.id

login_manager = LoginManager()
login_manager.setup_app(app)
login_manager.session_protection = "strong"
login_manager.login_view = u"login"
login_manager.login_message = u"Please log in to access this page."
login_manager.refresh_view = u"reauth"

@login_manager.user_loader
def load_user(ID):
    # return USERS.get(int(id))
    user = users.find_one({"id": ID})
    if user != None: return User(ID)
    return None

# For testing
@app.route("/secret")
@fresh_login_required
def secret():
    return render_template("404.html")  # Test

@app.route("/reauth", methods=["GET", "POST"])
@login_required
def reauth():
    if request.method == "POST":
        confirm_login()
        flash("Reauthenticated.")
        return redirect(request.args.get("next") or url_for("index"))
    return render_template("reauth.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.")
    session['token'] = None
    # u.set_authenticated(False)
    return redirect(url_for("index"))

def generate_auth_token(id, expiration=600):
    s = Serializer(app.secret_key, expires_in=expiration)
    token = s.dumps({'id': id})
    return {'token': token, 'duration': expiration}

def verify_auth_token(token):
    s = Serializer(app.secret_key)
    try:
        data = s.loads(token)
    except SignatureExpired:
        return None    # valid token, but expired
    except BadSignature:
        return None    # invalid token
    return "Success"

#@login_required
@app.route("/api/token")
@login_required
def token():
    """
    Generates a token if the user has successfully logged in.
    This token can be copy/pasted by the user, and is stored in the session variable
    """

    try:

        
        # Generate a token
        id = session.get('id')
        # user = User(id)
        # if user.is_autheticated():

        tokenInfo = generate_auth_token(id, 600)
        t = tokenInfo['token'].decode('utf-8')
        result = {'token': t, 'duration': 60}
        session['token'] = t
        return flask.jsonify(result=result)
        # else:
        #     return "Unauthorized", 401
        
    except:
        return "Unauthorized", 401

# From flask documentation
def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc

################################################################################################################################

app.debug = CONFIG.DEBUG
if app.debug:
    app.logger.setLevel(logging.DEBUG)

if __name__ == "__main__":
    print("Opening for global access on port {}".format(CONFIG.PORT))
    app.run(port=CONFIG.PORT, host="0.0.0.0")
    csrf.init_app(app)
