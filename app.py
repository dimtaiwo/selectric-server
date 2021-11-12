from flask import Flask, jsonify, request
from flask_pymongo import PyMongo


app = Flask(__name__)

app.config['MONGO_DBNAME'] = 'selectric'
app.config['MONGO_URI'] = 'mongodb+srv://dimeji:kushalpatel@cluster0.tbprf.mongodb.net/selectric?retryWrites=true&w=majority'
db = PyMongo(app)


if __name__ == '__main__':
    app.run(debug=True)
