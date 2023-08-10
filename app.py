"""
    Project: Eventspark API service.
    Author : Veronica Wambui Wanjiku.
    Description: API service for an event management application.
    August 2023 - Project done in fulfilment of the ALX software engineering programme.
    Portfolio Project.
"""
#Application based imports.
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from typing import TypedDict
import jwt
from functools import wraps
import uuid
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS


# Initialize Flask application
app = Flask(__name__)

app.config['SECRET_KEY'] =  "ALX_APP_eventspark" #Secret key configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db' #Database configuration.
db = SQLAlchemy(app) # Initialize database
CORS(app) # Handle Cross-Origin request policy.

class User(db.Model):
    """
    @USER model
    @PROPERTIES public_id | name | password | role
    """
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(100))
    admin = db.Column(db.Boolean)

class Event(db.Model):
    """
    @EVENT model
    @PROPERTIES event_id | name | description.
    """
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    description = db.Column(db.String(100))


def token_required(f):
    """@Decorator to restrict specific route access."""
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


"""USER routes"""
@app.route('/api/v1/user', methods=['POST'])
# @token_required
def create_user(current_user):
    """
    @POSTrequest
    Creates a new user to the database
    @properties: public_id | name | password | role
    """
    # if not current_user.admin:
    #     return jsonify({'message': 'Cannot perform that function'})
    data = request.get_json()
    hashed_password  = generate_password_hash(data['password'], method='pbkdf2')
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'status': 'success', 'message': 'New user created'})

@app.route('/api/v1/user', methods=['GET'])
def get_all_users():
    """
    @GET request
    Gets all the users from the database.
    @Returns all users.
    """
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


@app.route('/api/v1/user/<public_id>', methods=['GET'])
def get_single_user(public_id):
    """
    @GET request
    Retrieves a user from the database based on the id.
    @properties: public_id
    """
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})
   
    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user': user_data})

@app.route('/api/v1/user/<public_id>', methods=['PUT'])
def elevate_user(public_id):
    """
    @PUT request
    Gives user elevated access as administrator
    @properties: public_id
    """
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'No user found!'})
    user.admin = True
    db.session.commit()

    return jsonify({'message': 'The user has been promoted!'})

@app.route('/api/v1/user/<public_id>', methods=['DELETE'])
def delete_user(public_id):
    """
    @DELETE request
    Removes a user from the database based on the id.
    @properties: public_id
    """
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'No user found!'})
    
    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': f'user with id {user.public_id} deleted successfully!'})

"""Authentication Routes"""
@app.route('/api/v1/login')
def login():
    """
    @POST request
    Provides authorization token for authentication
    @returns a token
    """
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



"""EVENT routes"""
@app.route('/api/v1/event', methods=['POST'])
def publish_event():
    """@POST request
        Creates a new event with a unique ID
        @properties: name | description
    """
    data = request.get_json()
    new_event = Event(event_id=str(uuid.uuid4()), name=data['name'], description=data['description'])
    db.session.add(new_event)
    db.session.commit()
    return jsonify({'message' : "Event published successfully!"})

@app.route('/api/v1/event', methods=['GET'])
def get_all_events():
    """@GET request
        Returns all event listings
        @properties: event_id | name | description
    """
    events = Event.query.all()

    output = []

    for event in events:
        event_data = {}
        event_data['event_id'] = event.event_id
        event_data['name'] = event.name
        event_data['description'] = event.description
        output.append(event_data)

    return jsonify({'events' : output})

@app.route('/api/v1/event/<event_id>', methods=['GET'])
def get_single_event(event_id):
    """@GET request
        Returns a single event given its ID.
        @properties: event_id | name | description
    """
    event = Event.query.filter_by(event_id=event_id).first()

    if not event:
        return jsonify({'message' : f'No event found for id {event.event_id}!'})

    event_data = {}
    event_data['event_id'] = event.event_id
    event_data['name'] = event.name
    event_data['description'] = event.description

    return jsonify(event_data)



@app.route('/api/v1/event/<event_id>', methods=['PUT'])
def edit_published_event(event_id):
    """@PUT request
        Modifies data for a single event given its ID.
        @properties: event_id | name | description
    """
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
    """@DELETE request
        Removes an event from the database given its id
        @properties: event_id 
    """
    event = Event.query.filter_by(event_id=event_id).first()
    if not event:
        return jsonify({'message' : f'No event listed with id {event.event_id}!'})

    db.session.delete(event)
    db.session.commit()

    return jsonify({'message' : f'Event {event.event_id} deleted successfully!'})


@app.route('/')
def root():
    """Root"""
    return jsonify({'root': {
        "Project": "Eventspark-api-service", 
        "Author": "Veronica Wambui Wanjiku.", 
        "Programme": "ALX Software Engineering Programme",
        "version": "0.1.0.0"
    }})


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8080)