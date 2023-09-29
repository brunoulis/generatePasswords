from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
import random
import string
import hashlib
import os
from flask_session import Session

# Obtén la ruta del directorio actual del script
current_dir = os.path.abspath(os.path.dirname(__file__))


app = Flask(__name__)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
# Configura la clave secreta de la sesión
app.config['SECRET_KEY'] = 'clave_secreta'
db_path = os.path.join(current_dir, 'passwords.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
Session(app)
db = SQLAlchemy(app)

class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    username = db.Column(db.String(50), nullable=False)
    platform = db.Column(db.String(50), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/home')
def index():
    user_id = session.get('user_id')
    if user_id:
        passwords = Password.query.filter_by(user_id=user_id).all()
        return render_template('index.html', passwords=passwords)
    else:
        return redirect(url_for('login'))

@app.route('/generate_password')
def generate_password_route():
    user_id = session.get('user_id')
    if user_id:
        password = generate_password()
        passwords = Password.query.filter_by(user_id=user_id).all()
        return render_template('index.html', generated_password=password, passwords=passwords)
    else:
        return redirect(url_for('login'))

@app.route('/save_password', methods=['POST'])
def save_password():
    user_id = session.get('user_id')
    if user_id:
        username = request.form['username']
        platform = request.form['platform']
        password = request.form['password']
        password_hash = hash_password(password)

        new_password = Password(user_id=user_id, username=username, platform=platform, password_hash=password_hash)
        db.session.add(new_password)
        db.session.commit()

        return redirect(url_for('index'))
    else:
        return redirect(url_for('login'))

@app.route('/delete_password/<int:password_id>', methods=['GET', 'POST'])
def delete_password(password_id):
    user_id = session.get('user_id')
    if user_id:
        password = Password.query.get_or_404(password_id)

        if request.method == 'POST':
            db.session.delete(password)
            db.session.commit()
            return redirect(url_for('index'))

        return render_template('delete_password.html', password=password)
    else:
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_hash = hash_password(request.form['password'])
        user = User.query.filter_by(username=username, password_hash=password_hash).first()
        if user:
            session['user_id'] = user.id
            return redirect(url_for('index'))
        else:
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/')
def root():
    return render_template('root.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password_hash = hash_password(request.form['password'])
        user = User(username=username, password_hash=password_hash)
        db.session.add(user)
        db.session.commit()

        session['user_id'] = user.id
        return redirect(url_for('login'))
    return render_template('register.html')


# Ruta para el formulario de inicio de sesión
# Ruta para el formulario de inicio de sesión y autenticación
@app.route('/loginpasswords', methods=['GET', 'POST'])
def login_passwords():
    session.clear()
    if request.method == 'POST':
        # Obtiene los datos del formulario
        username = request.form['username']
        password = request.form['password']

        # Realiza la verificación del usuario (esto puede variar según tu implementación)
        user = User.query.filter_by(username=username, password_hash=hash_password(password)).first()
        if user:
            # Usuario autenticado con éxito, establece la sesión
            session['user_id'] = user.id
            session['logged_in'] = True
            return redirect(url_for('passwords'))

    # Renderiza el formulario de inicio de sesión
    return render_template('login_passwords.html')

    

# Ruta para mostrar las contraseñas
@app.route('/passwords', methods=['GET', 'POST'])
def passwords():
    # Verifica si el usuario está autenticado
    if session.get('logged_in'):
        # Muestra las contraseñas (deberías recuperarlas desde tu base de datos)
        # passwords = Password.query.filter_by(user_id=session['user_id']).all()
        # return render_template('passwords.html', passwords=passwords)
        passwords = Password.query.filter_by(user_id=session['user_id']).all()
        return render_template('passwords.html', passwords=passwords)
    else:
        # Redirige al formulario de inicio de sesión si no está autenticado
        return redirect(url_for('login_passwords'))  
    

    

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    app.run(debug=True)
