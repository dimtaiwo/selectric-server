from flask import Flask, jsonify, request
from flask_pymongo import PyMongo
import bcrypt
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import json
from bson import json_util
from werkzeug import exceptions
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


# login post route
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data['email']
    password = data['password']
    print(data)
    print(email)
    found_user = mongo.db.selectric.find_one({"email": f'{email}'})
    if found_user and bcrypt.check_password_hash(found_user['password'], password):
        token = create_access_token(data=parse_json(found_user))
        return {"token": parse_json(token)}, 200

# register post route


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()  # request.json
    email = data['email']
    username = data['username']
    password = data['password']
    print(data)
    hashed_pass = bcrypt.generate_password_hash(password).decode('utf8')

    new_user = {'email': email, 'username': username, 'password': hashed_pass}
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
    found_user = mongo.db.selectric.find_one({"email":user['email']})
    if request.method == 'GET':
        return parse_json(found_user),200
    if request.method == 'PATCH':
        for update in request.get_json()['updates']:
            found_user[f'{update["name"]}'] = update['value']
        mongo.db.selectric.save(found_user)
        return parse_json(found_user), 201
    if request.method == 'DELETE':
        mongo.db.selectric.delete_one(found_user)
        return '<h1>successfully deleted</h1>',201

@app.route('/cars',methods=['GET','POST'])
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
        return '<h1>Successfully added</h1>',201


# Error Handling
@app.errorhandler(exceptions.NotFound)
def handle_404(err):
    return {'message': f'Oops! {err}'}, 404

@app.errorhandler(exceptions.BadRequest)
def handle_400(err):
    return {'message': f'Oops! {err}'}, 400

@app.errorhandler(exceptions.InternalServerError)
def handle_500(err):
    return {'message': f"It's not you, it's us"}, 500

@app.errorhandler(exceptions.Unauthorised)
def handle_401(err):
    return {'message': f"You shouldn't be here"}, 401

@app.errorhandler(exceptions.Forbidden)
def handle_403(err):
    return {'message': f"You don't have permission for this"}, 403

@app.errorhandler(exceptions.MethodNotAllowed)
def handle_405(err):
    return {'message': f"Oops! {err}"}, 405

@app.errorhandler(exceptions.RequestTimeout)
def handle_408(err):
    return {'message': f"Your request has timed out"}, 408

if __name__ == '__main__':
    app.run(debug=True)
