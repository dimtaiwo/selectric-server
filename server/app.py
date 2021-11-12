from flask import Flask, jsonify, request
from flask_pymongo import PyMongo
import bcrypt
import json
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

app.config['MONGO_DBNAME'] = 'selectric'
app.config['MONGO_URI'] = 'mongodb+srv://dimeji:kushalpatel@cluster0.tbprf.mongodb.net/selectric?ssl=true&ssl_cert_reqs=CERT_NONE'
mongo= PyMongo(app)
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
    if found_user and bcrypt.checkpw(str(password.encode('utf8')),found_user['password'].encode('utf8')):
        token = create_access_token(parse_json(found_user))
        return parse_json(token), 200

# register post route
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json() #request.json
    email = data['email']
    username = data['username']
    password = data['password']
    
    hashed_pass = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
    
    new_user = {'email': email, 'username': username, 'password': hashed_pass}
    mongo.db.selectric.save(new_user)
    token = create_access_token(data=parse_json(new_user))
    print(token)
    return parse_json(token), 201
    


# get user by id
@app.route('/user', methods=['POST','PATCH', 'DELETE'])
def user():
    return



if __name__ == '__main__':
    app.run(debug=True)
