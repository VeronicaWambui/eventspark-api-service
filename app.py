from flask import Flask, request, jsonify, make_response
from flask.helpers import send_from_directory
from flask_sqlalchemy import SQLAlchemy
import jwt
from functools import wraps
import uuid
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

app = Flask(__name__)

app.config['SECRET_KEY'] =  "ALX_APP_eventspark"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
CORS(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(100))
    admin = db.Column(db.Boolean)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    description = db.Column(db.String(100))


def token_required(f):
    @wraps(f)
    def check_auth(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.header['x-access-token']
        if not token:
            return jsonify({'message': 'Token missing'})
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id'].first())
        except:
            return jsonify({'message': 'Token is invalid'}), 401 
        
        return f(current_user, *args, **kwargs)
    return check_auth


@app.route('/api/v1//user', methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function'})
    data = request.get_json()
    hashed_password  = generate_password_hash(data['password'], method='pbkdf2')
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'status': 'success', 'message': 'New user created'})

@app.route('/api/v1//user', methods=['GET'])
def get_all_users():
    users = User.query.all()
    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin

        output.append(user_data)
    return jsonify({'users': output})


@app.route('/api/v1//user/<public_id>', methods=['GET'])
def get_single_user(public_id):
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})
   
    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user': user_data})

@app.route('/api/v1//user/<public_id>', methods=['PUT'])
def elevate_user(public_id):
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'No user found!'})
    user.admin = True
    db.session.commit()

    return jsonify({'message': 'The user has been promoted!'})

@app.route('/api/v1//user/<public_id>', methods=['DELETE'])
def delete_user(public_id):
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'No user found!'})
    
    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': f'user with id {user.public_id} deleted successfully!'})


@app.route('/api/v1//login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    
    user = User.query.filter_by(name=auth.username).first()
    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
    
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'token': token})

    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})



@app.route('/api/v1//event', methods=['POST'])
def publish_event():
    data = request.get_json()
    new_event = Event(event_id=str(uuid.uuid4()), name=data['name'], description=data['description'])
    db.session.add(new_event)
    db.session.commit()
    return jsonify({'message' : "Event published successfully!"})

@app.route('/api/v1//event', methods=['GET'])
def get_all_events():
    events = Event.query.all()

    output = []

    for event in events:
        event_data = {}
        event_data['event_id'] = event.event_id
        event_data['name'] = event.name
        event_data['description'] = event.description
        output.append(event_data)

    return jsonify({'events' : output})

@app.route('/api/v1//event/<event_id>', methods=['GET'])
def get_single_event(event_id):
    event = Event.query.filter_by(event_id=event_id).first()

    if not event:
        return jsonify({'message' : f'No event found for id {event.event_id}!'})

    event_data = {}
    event_data['event_id'] = event.event_id
    event_data['name'] = event.name
    event_data['description'] = event.description

    return jsonify(event_data)



@app.route('/api/v1//event/<event_id>', methods=['PUT'])
def edit_published_event(event_id):
    event = Event.query.filter_by(event_id=event_id).first()

    if not event:
        return jsonify({'message' : f'No event found for id {event.event_id}!'})
    
    name = request.json['name']
    description = request.json['description']
    event.name = name
    event.description = description

    db.session.commit()
    return jsonify({'message' : f'Event with id {event.event_id} updated successfully'})

@app.route('/api/v1/event/<event_id>', methods=['DELETE'])
# @token_required
def delete_event(event_id):
    event = Event.query.filter_by(event_id=event_id).first()

    if not event:
        return jsonify({'message' : f'No event listed with id {event.event_id}!'})

    db.session.delete(event)
    db.session.commit()

    return jsonify({'message' : f'Event {event.event_id} deleted successfully!'})


@app.route('/')
def root():
    return jsonify({'message': "Welcome to the eventspark api."})



if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8080)