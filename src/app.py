from flask import Flask, request, jsonify, make_response, render_template, session, redirect, url_for
import jwt
from datetime import datetime, timedelta
from functools import wraps
import os
from dotenv import load_dotenv

app = Flask(__name__)
secret = os.environ.get('SECRET_KEY')
print(secret)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Se obtiene el token de la cabecera
        token = request.headers.get('Authorization')
        # Si no se envía el token
        if not token:
            return jsonify({'message': 'Token is missing'}), 403
        try:
            # Se decodifica el token
            data = jwt.decode(token, secret)
        except:
            return jsonify({'message': 'Token is invalid'}), 403
        # Si el token es válido, se devuelve la función
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def home():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        return "Logged in currently"
    


# NOTE: PROTEGIDA
@app.route('/auth')
@token_required
def protected():
    return jsonify({'message': 'This is only available for people with valid tokens.'})

# NOTE: PÚBLICA
@app.route('/public')
def unprotected():
    return jsonify({'message': 'This is available for everyone.'})

@app.route('/login', methods=['POST'])
def login():
    # Si coincide el usuario y la contraseña
    if request.form['username'] and request.form['password'] == '123':
        session['logged_in'] = True # Inicia sesión
        # Se genera el token con el usuario y la fecha de expiración
        token = jwt.encode({
            'user': request.form['username'],
            'exp': datetime.utcnow() + timedelta(minutes=30)}, 
            app.config['SECRET_KEY']) # Se usa la clave secreta
        # Se devuelve el token
        return jsonify({'token': token})
    else:
        # Si no coincide, se devuelve un error 403
        return make_response('Unable to verify', 403, {'WWW-Authenticate': 'Basic realm="Login Required"'})

@app.route('/logout')
def logout():
    session['logged_in'] = False
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)