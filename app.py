from flask import Flask, render_template, redirect, session, abort, request, url_for, flash, send_file
from pymongo import MongoClient, DESCENDING
from bson.objectid import ObjectId
from datetime import datetime, timedelta
from generator_qr_code import generatorQR
from flask_login import LoginManager, UserMixin, login_user, logout_user

from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests

import functools
from flask import request
from flask_socketio import SocketIO, emit, send

import os
import pathlib
import requests
import logging
import pandas as pd
import json
import jwt
import time
import pytz

app = Flask("Door Lock App")
app.secret_key = "DoorlockSystem.com"
app.config['FILE_UPLOADS'] = os.getcwd()+'/static/uploads'
app.permanent_session_lifetime = timedelta(days=60)

login_manager = LoginManager(app)
socketio = SocketIO(app)

# client = MongoClient('localhost', 27017)
client = MongoClient('db', 27017, username='root',
                     password='******')
db = client.door_lock_db
users = db.users
admins = db.admins
doors = db.doors
logs = db.logs

os.environ['TZ'] = 'Asia/Bangkok'
time.tzset()


logging.basicConfig(level=logging.DEBUG)

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
REDIRECT_URL = os.environ["REDIRECT_URL"]

GOOGLE_CLIENT_ID = "1089412775107-9ifbih9ibh0tap0quddg9coo0ttrgcf3.apps.googleusercontent.com"
client_secrets_file = os.path.join(
    pathlib.Path(__file__).parent, "client_secret_108941*****.com.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri=f"http://{REDIRECT_URL}/callback"
)


def is_admin_email():
    all_admin = admins.find()
    all_email = []
    for i in all_admin:
        is_email = i['email']
        all_email.append(is_email)
    return all_email


def is_user_email():
    all_user = users.find()
    all_email = []
    for i in all_user:
        is_email = i['email']
        all_email.append(is_email)
    return all_email

# _____init_admin_____


def _init_admin_():
    if "woranat.bo.62@ubu.ac.th" not in is_admin_email():
        admins.insert_one({'adminName': "Audy wb", 'email': "woranat.bo.62@ubu.ac.th",
                           'is_admin': True, 'createTime': datetime.utcnow(), 'updateTime': datetime.utcnow()
                           })
    elif "wayo.p@ubu.ac.th" not in is_admin_email():
        admins.insert_one({'adminName': "Wayo Puyati", 'email': "wayo.p@ubu.ac.th",
                           'is_admin': True, 'createTime': datetime.utcnow(), 'updateTime': datetime.utcnow()
                           })
    else:
        pass


_init_admin_()
# ______________________


def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Auth required
        elif session['email'] not in is_admin_email():
            return abort(401)  # Auth required
        else:
            return function()
    wrapper.__name__ = function.__name__
    return wrapper


def login_is_required_user(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            flash('Please login.')
            return redirect(url_for('index'))  # Auth required
        # อีเมลที่ login เข้ามาไม่ตรงกับอีเมลที่มีใน DB
        elif session['email'] not in is_user_email():
            flash('Login failed, Please contact admin.')
            return redirect(url_for('index'))
        else:
            return function()
    wrapper.__name__ = function.__name__
    return wrapper


class User(UserMixin):
    def __init__(self, id):
        self.id = id


@login_manager.user_loader
def load_user(user_id):
    return User(user_id)


def check_login_admin():
    if "google_id" not in session:
        return abort(401)
    elif session['email'] not in is_admin_email():
        return abort(401)
    else:
        pass


def jwt_token(token):
    decoded_jwt = jwt.decode(
        token, "comsci-project-doorlock-2023", algorithms="HS256")
    return decoded_jwt


@socketio.on('connect')
def on_connect():
    token = request.args.get('token')
    if token != None:
        if jwt_token(token) == {"rpi": "connection"}:
            emit('start esp', 'Server connected, Start esp', broadcast=True)
            send('connected')
        else:
            return False
    else:
        logging.info("No token")
        return False
    logging.info("Client connected")


@socketio.on('message')
def message(data):
    logging.info(data)


@socketio.on('err')
def event_error(msg):
    logging.info(msg)


@app.route("/")
def index():

    try:
        if "google_id" in session:
            if session['is_admin'] == True:
                return redirect(url_for('dashboard'))
            else:
                pass
    except:
        pass

    return render_template("index.html")


@app.route('/login')
def login():

    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    session['state'] = state
    return redirect(authorization_url)


@app.route("/logout")
def logout():
    session.clear()
    logout_user()
    return redirect("/")


@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)
    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(
        session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID,
        clock_skew_in_seconds=10
    )

    user = User(id=id_info['sub'])
    login_user(user, remember=True, duration=timedelta(days=60))

    session.permanent = True
    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    session["email"] = id_info.get("email")
    session["picture"] = id_info.get("picture")

    if session['email'] in is_admin_email():
        admin = admins.find_one({'email': session["email"]})
        if admin['is_admin'] == True:
            session['is_admin'] = True
            return redirect(url_for('dashboard'))
        else:
            return abort(404)
    else:
        user = users.find_one({'email': session["email"]})
        if user:
            if user['is_admin'] == False:
                session['is_admin'] = False
                return redirect(url_for('user'))
            else:
                return abort(404)
        else:
            flash(
                'There was an error in accessing the system, please contact the system administrator.')
            return redirect(url_for('index'))


@app.route("/dashboard")
@login_is_required
def dashboard():
    name = session['name']
    email = session['email']
    photoUrl = session['picture']

    door = doors.find()
    for i in doors.find():
        status = i['status']
        if status == 'open':
            time.sleep(5)
            doors.find_one_and_update(
                {"_id": ObjectId(i['_id'])},
                {"$set": {'status': "close", 'updateTime': datetime.utcnow()}}
            )
            return redirect(url_for('dashboard'))
        else:
            pass
    return render_template("dashboard.html", userName=name, userEmail=email, photoUrl=photoUrl, doors=door)


@app.route('/manage/admin')
@login_is_required
def manage():

    photoUrl = session['picture']
    name = session['name']

    all_admin = admins.find()

    return render_template('manage.html', photoUrl=photoUrl, userName=name, admins=all_admin)


@app.route('/manage/user')
@login_is_required
def manageUser():
    photoUrl = session['picture']
    name = session['name']

    all_users = []
    doors = allDoor()

    for user in users.find():
        door = []
        for door_id in range(len(user['doors'])):
            dt = findDoor(user['doors'][door_id])
            door.append(dt['name'])
        user['doors'] = door
        door = []
        all_users.append(user)

    return render_template('manageUser.html', photoUrl=photoUrl, userName=name, users=all_users, doors=doors)


def findDoor(id):
    f_door = doors.find_one({'_id': ObjectId(id)})
    return f_door


def allDoor():
    all_door = doors.find()
    return all_door


@app.route('/addUser', methods=('GET', 'POST'))
@login_is_required
def addUser():

    photoUrl = session['picture']
    admin_name = session['name']
    all_door = allDoor()

    if request.method == 'POST':

        if request.files:
            df = pd.read_csv(request.files.get('fileuerName'))
            try:
                mask = (df.columns[0] == 'studentID') & (df.columns[1] == 'userName') & (
                    df.columns[2] == 'email') & (df.columns[3] == 'doors')
                if mask == True:
                    pass
                else:
                    return abort(404)
            except:
                flash(
                    'The columns must include studentID, userName, email, and doors only.')
                return redirect('addUser')
            df['doors'] = df['doors'].str.split(",")
            for door in df['doors']:
                try:
                    fdoor = findDoor(door[0])
                    pass
                except:
                    flash('Invalid Door ID, There is no Door ID.')
                    return redirect(url_for('addUser'))
            for mail in df['email']:
                if mail not in is_user_email():
                    pass
                else:
                    flash(f'{mail}, This email already exists.')
                    return redirect(url_for('addUser'))
            data = df.dropna()
            data['is_admin'] = False
            data['createTime'] = datetime.utcnow()
            data['updateTime'] = datetime.utcnow()
            payload = data.to_dict(orient='records')
            users.insert_many(payload)
            flash('Successfully added user.')
            return redirect(url_for('manageUser'))

        studentID = request.form['id']
        name = request.form['name']
        email = request.form['email']
        doors = request.form.getlist('door')
        is_admin = False
        now = datetime.now()

        if email not in is_user_email():
            users.insert_one(
                {'studentID': studentID, 'userName': name, 'email': email, 'doors': doors, 'is_admin': is_admin, 'createTime': now, 'updateTime': datetime.utcnow()})
            flash('Successfully added user.')
        else:
            flash('This email already exists.')
        return redirect(url_for('addUser'))

    return render_template('manage/addUser.html', photoUrl=photoUrl, userName=admin_name, door=all_door)


@app.route('/update/user/<id>', methods=['GET', 'POST'])
def updateUser(id):

    check_login_admin()

    photoUrl = session['picture']
    name = session['name']

    find_user = users.find_one({"_id": ObjectId(id)})
    userName = find_user['userName']
    userEmail = find_user['email']
    studentID = find_user['studentID']
    doors_user = find_user['doors']
    door = []
    for door_id in range(len(doors_user)):
        dt = findDoor(doors_user[door_id])
        door.append(dt['name'])
    doors_user = door
    all_door = allDoor()

    if request.method == 'POST':
        update_ID = request.form['id']
        update_name = request.form['name']
        update_email = request.form['email']
        doors = request.form.getlist('door')
        if update_email not in is_user_email():
            users.find_one_and_update({"_id": ObjectId(id)}, {
                "$set": {'userName': update_name,
                         'email': update_email,
                         'studentID': update_ID,
                         'doors': doors,
                         'updateTime': datetime.utcnow()}})
            flash('Successfully updated user.')
        else:
            if update_email == find_user['email']:
                users.find_one_and_update({"_id": ObjectId(id)}, {
                    "$set": {'userName': update_name,
                             'email': update_email,
                             'studentID': update_ID,
                             'doors': doors,
                             'updateTime': datetime.utcnow()}})
                flash('Successfully updated user.')
            else:
                flash('This email already exists.')
                return redirect(url_for('updateUser', id=id))

        return redirect(url_for('manageUser'))

    return render_template('manage/editUser.html',
                           photoUrl=photoUrl,
                           userName=name,
                           name=userName,
                           email=userEmail,
                           studentID=studentID,
                           doors=all_door,
                           door_user=doors_user
                           )


@app.route('/delete/user/list/', methods=('GET', 'POST'))
@login_is_required
def deleteUser():

    if request.method == 'POST':
        id = request.form.getlist('check_delete')
        for i in id:
            users.delete_one({"_id": ObjectId(i)})
    return redirect(url_for('manageUser'))


@app.route('/addAdmin', methods=('GET', 'POST'))
@login_is_required
def addAdmin():

    photoUrl = session['picture']
    admin_name = session['name']
    is_admin = True
    if request.method == 'POST':
        if request.files:
            df = pd.read_csv(request.files.get('filename'))
            data = df.dropna()
            mask = (data.columns[0] == 'adminName') & (
                data.columns[1] == 'email')
            
            try:
                mask = (data.columns[0] == 'adminName') & (
                    data.columns[1] == 'email')
                if mask == True:
                    pass
                else:
                    return abort(404)
            except:
                flash('The columns must consist of adminName and email only.')
                return redirect('addAdmin')
            
            for mail in df['email']:
                if mail not in is_admin_email():
                    pass
                else:
                    flash(f'{mail}, This email already exists.')
                    return redirect(url_for('addAdmin'))

            data['is_admin'] = is_admin
            data['createTime'] = datetime.utcnow()
            data['updateTime'] = datetime.utcnow()
            payload = data.to_dict(orient='records')
            admins.insert_many(payload)
            flash('Successfully added admin.')
            return redirect(url_for('manage'))

        name = request.form['name']
        email = request.form['email']

        if email not in is_admin_email():
            admins.insert_one({'adminName': name, 'email': email, 'is_admin': is_admin,
                              'createTime': datetime.utcnow(), 'updateTime': datetime.utcnow()})
            flash('Successfully added admin.')
        else:
            flash('This email already exists.')
        return redirect(url_for('addAdmin'))

    return render_template('manage/addAdmin.html', photoUrl=photoUrl, userName=admin_name)


@app.route('/update/admin/<id>', methods=['GET', 'POST'])
def updateAdmin(id):

    check_login_admin()

    photoUrl = session['picture']
    name = session['name']

    find_admin = admins.find_one({"_id": ObjectId(id)})
    adminName = find_admin['adminName']
    adminEmail = find_admin['email']

    if request.method == 'POST':
        update_name = request.form['name']
        update_email = request.form['email']

        if update_email not in is_admin_email():
            admins.find_one_and_update({'adminName': adminName}, {
                "$set": {'adminName': update_name, 'email': update_email, 'updateTime': datetime.utcnow()}})
            flash('Successfully updated admin.')
        else:
            if update_email == find_admin['email']:
                admins.find_one_and_update({'adminName': adminName}, {
                    "$set": {'adminName': update_name, 'email': update_email, 'updateTime': datetime.utcnow()}})
                flash('Successfully updated admin.')
                return redirect(url_for('manage'))
            else:
                flash('This email already exists.')
                return redirect(url_for('updateAdmin', id=id))

        return redirect(url_for('manage'))

    return render_template('manage/editAdmin.html',
                           photoUrl=photoUrl,
                           userName=name,
                           name=adminName,
                           email=adminEmail
                           )


@app.route('/delete/admin/list/', methods=('GET', 'POST'))
@login_is_required
def deleteAdmin():
    if request.method == 'POST':
        id = request.form.getlist('check_delete')
        for i in id:
            admins.delete_one({"_id": ObjectId(i)})
    return redirect(url_for('manage'))


@app.route('/add/door', methods=['GET', 'POST'])
@login_is_required
def addDoor():

    photoUrl = session['picture']
    name = session['name']

    if request.method == 'POST':
        door_name = request.form['door_name']
        room_name = request.form['room_name']
        detail = request.form['detail']
        for i in doors.find():
            if door_name == i['name']:
                flash('This door name already exists.')
                return redirect(url_for('addDoor'))
            else:
                pass
        _id = doors.insert_one({
            'name': door_name,
            'room': room_name,
            'detail': detail,
            'status': "close",
            'createTime': datetime.utcnow(),
            'updateTime': datetime.utcnow()
        }).inserted_id
        generatorQR(_id)
        flash('Successfully added a door')
        return redirect(url_for('addDoor'))

    return render_template('manage/addDoor.html', photoUrl=photoUrl, userName=name)


@app.route('/edit/door/<id>', methods=['GET', 'POST'])
def editDoor(id):

    check_login_admin()

    photoUrl = session['picture']
    name = session['name']

    door = doors.find_one({"_id": ObjectId(id)})

    if request.method == 'POST':
        door_name = request.form['door_name']
        room_name = request.form['room_name']
        detail = request.form['detail']

        for i in doors.find():
            if door_name == i['name']:
                if ObjectId(id) == i['_id']:
                    doors.find_one_and_update({'_id': ObjectId(id)}, {
                        "$set": {
                            'name': door_name,
                            'room': room_name,
                            'detail': detail,
                            'updateTime': datetime.utcnow()
                        }})
                else:
                    flash('This door name already exists.')
                    return redirect(url_for('getDoor', id=id))
            else:
                doors.find_one_and_update({'_id': ObjectId(id)}, {
                    "$set": {
                        'name': door_name,
                        'room': room_name,
                        'detail': detail,
                        'updateTime': datetime.utcnow()
                    }})
        flash('Successfully updated a door')
        return redirect(url_for('getDoor', id=id))

    return render_template('manage/editDoor.html', photoUrl=photoUrl, userName=name, door=door)


@app.route('/delete/door/<id>')
def deleteDoor(id):

    check_login_admin()

    doors.delete_one({"_id": ObjectId(id)})
    users.update_many({}, {'$pull': {'doors': id}})

    return redirect(url_for('dashboard'))


@app.route('/get/edit/door/<id>', methods=['GET', 'POST'])
def getDoor(id):
    return redirect(url_for('editDoor', id=id))


@app.route('/open/door/<id>', methods=['GET', 'POST'])
def openDoor(id):

    if "google_id" not in session:
        flash('Please login.')
        return redirect(url_for('index'))
    else:
        pass

    door = doors.find_one({"_id": ObjectId(id)})
    send_message(id)
    if door['status'] == "close":
        doors.find_one_and_update(
            {"_id": ObjectId(id)},
            {"$set": {'status': "open", 'updateTime': datetime.utcnow()}}
        )
        if session['is_admin'] == True:
            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('user_unlock_door', id=door['_id']))
    else:
        doors.find_one_and_update(
            {"_id": ObjectId(id)},
            {"$set": {'status': "close", 'updateTime': datetime.utcnow()}}
        )
        if session['is_admin'] == True:
            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('user_unlock_door', id=door['_id']))


def send_message(door):
    # send_open_door
    email = session['email']
    is_admin = session['is_admin']

    find_door = doors.find_one({'_id': ObjectId(door)})

    if is_admin == True:
        admin = admins.find_one({'email': session['email']})
        logs.insert_one(
            {'id': admin['_id'], 'sID': 'admin', 'name': admin['adminName'], 'email': admin['email'],
             'door': door, 'doorName': find_door['name'], 'unlockTime': datetime.now()})
    else:
        user = users.find_one({'email': session['email']})
        logs.insert_one({'id': user['_id'], 'sID': user['studentID'], 'name': user['userName'],
                        'email': user['email'], 'door': door, 'doorName': find_door['name'], 'unlockTime': datetime.now()})
    socketio.emit('response', door)
    return "Message sent!"


@app.route('/dashboard/door/user')
@login_is_required_user
def user():

    try:
        if session['door_id']:
            return redirect(url_for('user_unlock_door', id=session['door_id']))
    except:
        # flash("Please scan the QR code at the door.")
        return redirect(url_for('userSelectDoor'))


@app.route('/select/door/user')
@login_is_required_user
def userSelectDoor():

    user = users.find_one({'email': session['email']})
    door_id = user['doors']
    door_list = []

    for id in door_id:
        door = doors.find_one({'_id': ObjectId(id)})
        door_list.append(door)

    return render_template('user/selectDoor.html', doors=door_list)


@app.route('/dashboard/door/user/unlock/<id>')
def user_unlock_door(id):

    if "google_id" not in session:
        flash('Please login.')
        session.permanent = True
        session['door_id'] = id
        return redirect(url_for('index'))
    elif session['email'] not in is_user_email():
        flash('Login failed, Please contact admin.')
        return redirect(url_for('index'))
    else:
        pass

    find_door = doors.find_one({'_id': ObjectId(id)})

    name = session['name']
    email = session['email']
    photoUrl = session['picture']

    user = users.find_one({'email': session['email']})
    if id in user['doors']:
        status = find_door['status']
        if status == 'open':
            time.sleep(5)
            doors.find_one_and_update(
                {"_id": ObjectId(find_door['_id'])},
                {"$set": {'status': "close", 'updateTime': datetime.utcnow()}}
            )
            return redirect(url_for('user_unlock_door', id=id))
        else:
            pass
    else:
        flash('You do not have access to this door.')
        return redirect(url_for('index'))
    return render_template('user/user.html', userName=name, userEmail=email, photoUrl=photoUrl, door=find_door)


@app.route('/download/image/qrCode/<id>')
def download_qr(id):
    filename = f'static/qrCode/{id}.png'
    return send_file(filename, as_attachment=True)


@app.route('/history')
@login_is_required
def history():

    name = session['name']
    photoUrl = session['picture']

    log = logs.find().sort('unlockTime', DESCENDING)

    return render_template('show_log.html', logs=log, userName=name, photoUrl=photoUrl)


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
