from flask import Flask, jsonify, request
from flask_pymongo import PyMongo
import bcrypt
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import json
import re
from bson import json_util
# from auth.auth import create_access_token


from datetime import datetime, timedelta
import jwt


def create_access_token(*, data: dict, expires_delta: timedelta = None):
    secret_key = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
    algorithm = "HS256"
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode["exp"] = expire
    return jwt.encode(to_encode, secret_key, algorithm=algorithm)


def parse_json(data):
    return json.loads(json_util.dumps(data))


app = Flask(__name__)
CORS(app)
bcrypt = Bcrypt(app)
app.config['MONGO_DBNAME'] = 'selectric'
app.config['MONGO_URI'] = 'mongodb+srv://dimeji:kushalpatel@cluster0.tbprf.mongodb.net/selectric?ssl=true&ssl_cert_reqs=CERT_NONE'
mongo = PyMongo(app)
secret = 'brodie-secret'


class SchemaValidator(object):
    def __init__(self, response={}):
        self.response = response

    def isTrue(self):
        errorMessages = []
        try:
            username = self.response.get("username", None)
            if username is None or len(username <= 1):
                raise Exception("Error")
        except Exception as e:
            'username is required'
        try:
            password = self.response.get("username", None)
            if password is None or len(password <= 1):
                raise Exception("Error")
        except Exception as e:
            errorMessages.append('password is required')
        try:
            email = self.response.get("email", None)
            if email is None or len(password <= 1):
                raise Exception("Error")
        except Exception as e:
            errorMessages.append('email is required')
        return errorMessages


# login post route
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    # _instance = SchemaValidator(response=data)
    # response = _instance.isTrue()
    # if len(response) > 0:
    #     _ = {
    #         "status": "error",
    #         "message": response
    #     }
    #     return _, 400
    email = data['email']
    password = data['password']
    if len(email) < 2 or email == None:
        return {"message": "Enter a valid email"}, 403
    if len(password) < 2 or password == None:
        return {"message": "Enter a valid password"}, 403
    found_user = mongo.db.selectric.find_one({"email": f'{email}'})
    if not found_user:
        return {"message": "wrong login credentials"}, 400
    if found_user and bcrypt.check_password_hash(found_user['password'], password):
        token = create_access_token(data=parse_json(found_user))
        return {"token": parse_json(token)}, 200
    else:
        return {"message": "wrong credential"}


# register post route


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()  # request.json
    # _instance = SchemaValidator(response=data)
    # response = _instance.isTrue()
    # if len(response) > 0:
    #     _ = {
    #         "message": response
    #     }
    #     return _, 403

    email = data['email']
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    username = data['username']
    password = data['password']
    if len(email) < 2 or email == None or not(re.fullmatch(email_pattern, email)):
        return {"message": "Enter a valid email"}, 403
    if len(password) < 2 or password == None:
        return {"message": "Enter a valid password"}, 403
    if len(username) < 2 or username == None:
        return {"message": "Enter a valid username"}, 403
    found_user = mongo.db.selectric.find_one({"email": "email"})
    if found_user:
        return {"message": "Email already registered"}
    hashed_pass = bcrypt.generate_password_hash(password).decode('utf8')

    new_user = {'email': email, 'username': username,
                'password': hashed_pass}
    mongo.db.selectric.save(new_user)
    token = create_access_token(data=parse_json(new_user))
    print(token)
    return {"token": parse_json(token)}, 201

    # get user by id


@app.route('/user', methods=['GET', 'PATCH', 'DELETE'])
def user():
    token = request.headers['auth-token']
    secret_key = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
    algorithm = "HS256"
    user = jwt.decode(token, key=secret_key, algorithms=algorithm)
    found_user = mongo.db.selectric.find_one({"email": user['email']})
    if request.method == 'GET':
        return parse_json(found_user), 200
    if request.method == 'PATCH':
        for update in request.get_json()['updates']:
            found_user[f'{update["name"]}'] = update['value']
            if 'profile_image' in request.files:
                profile_image = request.files['profile_image']
                mongo.save_file(profile_image.filename, profile_image)
                found_user['profile_image_name'] = profile_image
        mongo.db.selectric.save(found_user)
        return parse_json(found_user), 201
    if request.method == 'DELETE':
        mongo.db.selectric.delete_one(found_user)
        return '<h1>successfully deleted</h1>', 200


@app.route('/cars', methods=['GET', 'POST'])
def cars():
    if request.method == 'GET':
        found_cars = mongo.db.cars.find({})
        return jsonify(parse_json(found_cars)), 200
    if request.method == 'POST':
        data = request.get_json()
        new_car = {
            "brand": data['brand'],
            "model": data['model'],
            "range_km": data['range_km'],
            "efficiency_whkm": data['efficiency_whkm'],
            "fast_charge_kmh": data['fast_charge_kmh'],
            "rapid_charge": data['rapid_charge'],
            "power_train": data['power_train'],
            "plug_type": data['plug_type'],
            "body_style": data['body_style'],

        }
        mongo.db.cars.save(new_car)
        return '<h1>Successfully added</h1>', 201


if __name__ == '__main__':
    app.run(debug=True)
