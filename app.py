from flask import Flask, request, jsonify
from models.user import User
from database import db
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:admin@217.0.0.1:3306/'

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)

login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/login', methods=['POST'])
def login():
    global user
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Missing username or password'}), 400
    user = User.query.filter_by(username=username).first()
    if user and user.password == hashed_password:
        login_user(user)
        print(current_user.is_authenticated)
        return jsonify({'message': 'Logged in'}), 200
    else:
        return jsonify({'error': 'Invalid username or password'}), 401


@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out'})


@app.route('/user', methods=['POST'])
def create_user():
    global hashed_password 
    hashed_password = bcrypt.hashpw(str.encode[password], bcrypt.gensalt())
    global is_admin
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    if username == 'admin':
        is_admin = True
    else:
        is_admin = False

    if not username or not email or not password:
        return jsonify({'error': 'Missing required fields'}), 400

    user = User(username=username, email=email, password=password, is_admin=is_admin)
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'User created'})


@app.route('/user/<int>:id', methods=['GET'])
@login_required
def get_user(id):
    user = User.query.get(id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    return jsonify({'username': user.username, 'email': user.email, 'is_admin': user.is_admin})


@app.route('/user/<int>:id', methods=['PUT'])
@login_required
def update_user(id):
    data = request.json
    user = User.query.get(id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    user.email = data.get('email', user.email)
    user.password = data.get('password', user.password)
    user.is_admin = data.get('is_admin', user.is_admin)

    db.session.commit()

    return jsonify({'message': f'User {id} updated'})


@app.route('/user/<int>:id', methods=['DELETE'])
@login_required
def delete_user(id):
    user = User.query.get(id)
    if not user and id != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'User not found'}), 404

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': f'User {id} deleted'})


@app.route('/hello-world', methods=['GET'])
def hello_world():
    return jsonify({'message': 'Hello, World!'})


if __name__ == '__main__':
    app.run(debug=True)