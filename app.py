import json
import random
import string
from functools import wraps

import httplib2
import requests
from flask import Flask, render_template, \
    request, flash, redirect, url_for, jsonify
from flask import make_response
from flask import session as login_session
from flask_sqlalchemy import SQLAlchemy
from oauth2client.client import FlowExchangeError
from oauth2client.client import flow_from_clientsecrets
from sqlalchemy import asc
from sqlalchemy.orm.exc import NoResultFound

from database_setup import *

# import requests

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
app = Flask(__name__)
app.secret_key = "super secret key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///catalogues.db'
db = SQLAlchemy(app)


@app.route('/')
def index():
    items = db.session.query(Item).all()
    categories = db.session.query(Category).order_by(asc(Category.name)).all()
    if 'username' in login_session:
        logged = True
        userid = login_session['userid']
    else:
        logged = False
        userid = None
    return render_template('home.html', Items=items,
                           Categories=categories, loggedin=logged,
                           UserID=userid, HomePage=True)


# creates login state for connection with 3rd parties auth
@app.route('/login')
def login():
    state = ''.join(
        random.choices(string.ascii_uppercase + string.digits, k=32))
    login_session['state'] = state
    loggedin = False
    if 'username' in login_session:
        loggedin = True
    return render_template('login.html', STATE=state, loggedin=loggedin)


# function to connect with google authentication
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1].decode('utf-8'))
    print(result)
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'),
            200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['email'] = data['email']
    userID = getUserID(login_session['email'])
    if userID is None:
        userID = createUser(login_session)
        login_session['userid'] = userID

    else:
        login_session['userid'] = userID

    output = ''
    output += '<h4>Welcome, '
    output += login_session['username']
    output += '!</h4>'
    return output


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return redirect(url_for('index'))

    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % \
          login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print('result is ')
    print(result)
    if result['status'] == '200':
        del login_session['access_token']

        del login_session['username']
        del login_session['email']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return redirect(url_for('index'))
        return redirect(url_for('index'))
    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return redirect(url_for('index'))


@app.route('/aa')
def aa():
    del login_session['access_token']

    del login_session['username']
    del login_session['email']
    return "done "


# display category items
@app.route('/<int:category_id>')
def category(category_id):
    items = db.session.query(Item).filter_by(category_id=category_id)
    categories = db.session.query(Category).order_by(asc(Category.name)).all()
    if 'username' in login_session:
        logged = True
        userid = login_session['userid']
    else:
        logged = False
        userid = None
    return render_template('home.html', Items=items, Categories=categories,
                           category=category_id, loggedin=logged,
                           UserID=userid)


# display item
@app.route('/<int:category_id_url>/<int:item_id>')
def items_path(category_id_url, item_id):
    item = db.session.query(Item).filter_by(id=item_id).one()
    categories = db.session.query(Category).order_by(asc(Category.name)).all()
    loggedin = False
    if 'username' in login_session:
        loggedin = True

    return render_template('item.html', Item=item, Categories=categories,
                           loggedin=loggedin)


# creates new item
@app.route('/<int:category_id_url>/new/', methods=['GET', 'POST'])
def new_item(category_id_url):
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newItem = Item(name=request.form['name'],
                       description=request.form['description'],
                       category_id=category_id_url,
                       user_id=login_session['userid'])
        db.session.add(newItem)
        db.session.commit()

        return redirect(url_for('items_path', category_id_url=category_id_url,
                                item_id=newItem.id, loggedin=True))
    else:
        return render_template('additem.html', category_id=category_id_url,
                               loggedin=True)


# edit an existing item
@app.route('/<int:category_id_url>/<int:item_id>/edit/',
           methods=['GET', 'POST'])
def editItem(category_id_url, item_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = db.session.query(Item).filter_by(id=item_id,
                                                  category_id=category_id_url).one()
    if editedItem.user_id != login_session['userid']:
        return redirect('/')
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']

        db.session.add(editedItem)
        db.session.commit()

        return redirect(url_for('items_path', category_id_url=category_id_url,
                                item_id=editedItem.id, loggedin=True))
    else:
        return render_template('edititem.html', rcategory_id=category_id_url,
                               Item=editedItem, loggedin=True)


# delete an existing item
# @app.login_required
@app.route('/<int:category_id_url>/<int:item_id>/delete/',
           methods=['GET', 'POST'])
def deleteItem(category_id_url, item_id):
    if 'username' not in login_session:
        return redirect('/login')
    itemToDelete = db.session.query(Item).filter_by(id=item_id,
                                                    category_id=category_id_url).one()
    if itemToDelete.user_id != login_session['userid']:
        return redirect('/')
    if request.method == 'POST':
        db.session.delete(itemToDelete)
        db.session.commit()
        flash(' Item Successfully Deleted')
        return redirect(url_for('index'))
    else:
        return render_template('deleteitem.html', Item=itemToDelete,
                               loggedin=True)


# json endpoints
# json endpoint for specific item
@app.route('/<int:category_id_url>/<int:item_id>/json/',
           methods=['GET', 'POST'])
def jsonItem(category_id_url, item_id):
    item = db.session.query(Item).filter_by(id=item_id,
                                            category_id=category_id_url).one()
    # if request.method == 'POST':

    return jsonify(Item=item.serialize)


# json endpoint for displaying items in specific category
@app.route('/<int:category_id_url>/json/', methods=['GET', 'POST'])
def jsoncategory(category_id_url):
    items = db.session.query(Item).filter_by(category_id=category_id_url).all()
    # if request.method == 'POST':

    return jsonify(Item=[i.serialize for i in items])


# doesnt work
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' in login_session:
            return f(*args, **kwargs)
        else:
            flash("You are not allowed to access there")
            return redirect('/login')

    return decorated_function


if __name__ == '__main__':
    app.run(host='localhost', port=5000)


# User Helper Functions

# creates new user
def createUser(login_session_):
    newUser = User(name=login_session_['username'], email=login_session_[
        'email'])
    db.session.add(newUser)
    db.session.commit()
    user = db.session.query(User).filter_by(email=login_session_['email']).one()
    return user.id


# get user id by mail
def getUserID(email):
    try:
        user = db.session.query(User).filter_by(email=email).one()
        return user.id
    except NoResultFound:
        return None
