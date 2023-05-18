import paho.mqtt.client as mqtt
import socketio
import requests
import time
import jwt

from flask import Flask, render_template, request, redirect, url_for, abort

app = Flask(__name__)

encoded_jwt = jwt.encode({"***": "***"},
                         "****", algorithm="HS256")

sio = socketio.Client()

sio.connect('http://192.****?token='+encoded_jwt)
# sio.connect('http://192.168.0.100:5000?token='+encoded_jwt)


@sio.event
def connect():
    print("I'm connected server")


@sio.event
def connect_error(data):
    print("The connection failed!")


@sio.event
def disconnect():
    print("I'm disconnected!")


mqttc = mqtt.Client()
mqttc.connect('localhost', 1883, 60)
mqttc.loop_start()


pins = {
    4: {'name': 'GPIO 4', 'board': 'esp8266', 'topic': 'esp8266_01/4', 'state': 'False'},
    5: {'name': 'GPIO 5', 'board': 'esp8266', 'topic': 'esp8266_01/5', 'state': 'False'}
}

pins2 = {
    4: {'name': 'GPIO 4', 'board': 'esp8266', 'topic': 'esp8266_02/4', 'state': 'False'},
    5: {'name': 'GPIO 5', 'board': 'esp8266', 'topic': 'esp8266_02/5', 'state': 'False'}
}


templateData = {
    'pins': pins,
}

templateData2 = {
    'pins2': pins2
}


@app.route("/")
def main():

    return abort(404)


@app.route("/<board>/<changePin>/<action>/<token>")
def action(board, changePin, action, token):
    print(board)

    if token != None:
        if jwt_token(token) == {"unlock": "door"}:
            pass
        else:
            sio.emit('err', 'invalid_request')
            return redirect(url_for('main'))

    changePin = int(changePin)

    if action == "1" and board == 'esp8266_01':
        mqttc.publish(pins[changePin]['topic'], "1")
        pins[changePin]['state'] = 'True'

    elif action == "0" and board == 'esp8266_01':
        mqttc.publish(pins[changePin]['topic'], "0")
        pins[changePin]['state'] = 'False'

    elif action == "1" and board == 'esp8266_02':
        mqttc.publish(pins2[changePin]['topic'], "1")
        pins2[changePin]['state'] = 'True'

    elif action == "0" and board == 'esp8266_02':
        mqttc.publish(pins2[changePin]['topic'], "0")
        pins2[changePin]['state'] = 'False'

    templateData = {
        'pins': pins,
    }

    templateData2 = {
        'pins2': pins2
    }

   #  return render_template('main.html', **templateData, **templateData2)
    return abort(404)


@sio.on('start esp')
def startesp(data):
    print(data)
    encoded_jwt = jwt.encode(
        {"unlock": "door"}, "unlockdoor-dssi-sci-2023", algorithm="HS256")
    r = requests.get(f'http://127.0.0.1:8181/esp8266_02/4/1/{encoded_jwt}')


@sio.on('response')
def response(data):
    door = data
    esp = "error"
    print(door)
    pin = 4
    pin2 = 5
    encoded_jwt = jwt.encode(
        {"unlock": "door"}, "unlockdoor-dssi-sci-2023", algorithm="HS256")

    if door == "63ef37a189e45e64e84d0f1d":
        esp = "esp8266_01"
    elif door == "63fdb98e46b361765d6ce31b":
        esp = "esp8266_02"
    else:
        esp = "ESP not found"
    print(pin)

    r = requests.get(
        f'http://127.0.0.1:8181/{esp}/{pin}/0/{encoded_jwt}')
    time.sleep(5)
    r = requests.get(
        f'http://127.0.0.1:8181/{esp}/{pin}/1/{encoded_jwt}')


def jwt_token(token):
    decode_jwt = jwt.decode(
        token, "unlockdoor-dssi-sci-2023", algorithms="HS256"
    )
    return decode_jwt


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8181, debug=True)