from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
import random
import string
import hashlib
import os

# Inicialización de la aplicación Flask
app = Flask(__name__)

# Obtén la ruta del directorio actual del script

current_dir = os.path.abspath(os.path.dirname(__file__))

# Obtén la ruta de la base de datos SQLite
db_path = os.path.join(current_dir, 'passwords.db')
# Configuración de la base de datos SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Definición del modelo de datos para almacenar contraseñas en la base de datos
class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    #Añadimos el id del usuario que ha creado la contraseña
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    username = db.Column(db.String(50), nullable=False)
    platform = db.Column(db.String(50), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

#Creamos otro modelo de datos para almacenar el usuario que despues accedera a sus contraseñas

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)


# Función para generar contraseñas aleatorias
def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    return password

# Función para hashear contraseñas usando SHA-256
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Ruta principal que muestra las contraseñas almacenadas
@app.route('/home')
def index():
    passwords = Password.query.all()
    return render_template('index.html', passwords=passwords)

# Ruta para generar una contraseña aleatoria
@app.route('/generate_password')
def generate_password_route():
    password = generate_password()
    passwords = Password.query.all()
    return render_template('index.html', generated_password=password ,passwords=passwords)

# Ruta para guardar una nueva contraseña en la base de datos
@app.route('/save_password', methods=['POST'])
def save_password():
    # Obtener los datos del formulario
    username = request.form['username']
    platform = request.form['platform']
    password = request.form['password']
    password_hash = hash_password(password)

    # Crear un nuevo objeto Password y agregarlo a la sesión de la base de datos
    new_password = Password(username=username, platform=platform, password_hash=password_hash)
    db.session.add(new_password)
    db.session.commit()

    # Redirigir a la página principal después de guardar la contraseña
    return redirect(url_for('index'))

@app.route('/delete_password/<int:password_id>', methods=['GET', 'POST'])
def delete_password(password_id):
    password = Password.query.get_or_404(password_id)

    if request.method == 'POST':
        db.session.delete(password)
        db.session.commit()
        return redirect(url_for('index'))

    return render_template('delete_password.html', password=password)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_hash = hash_password(request.form['password'])
        user = User.query.filter_by(username=username, password_hash=password_hash).first()
        if user:
            return redirect(url_for('index'))
        else:
            return redirect(url_for('login'))
    return render_template('login.html')

#Ruta raiz que nos redirige que tendra un boton para ir a registrarse o a logearse
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
        return redirect(url_for('login'))
    return render_template('register.html')

# Inicialización y ejecución de la aplicación Flask
if __name__ == '__main__':
    # Crear todas las tablas en la base de datos antes de iniciar la aplicación
    with app.app_context():
        db.create_all()

    # Iniciar la aplicación en modo de depuración
    app.run(debug=True)
