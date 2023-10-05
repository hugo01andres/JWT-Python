from flask import Flask, request, jsonify, make_response, render_template, session, redirect, url_for
import jwt
from datetime import datetime, timedelta
from functools import wraps
import os
from dotenv import load_dotenv

app = Flask(__name__)
SECRET_KEY = os.environ.get('SECRET_KEY')
print(SECRET_KEY)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

def generar_token(username):
    token = jwt.encode({'username': username}, SECRET_KEY, algorithm='HS256')
    return token

def verificar_token(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'mensaje': 'Token faltante'}), 401

        try:
            datos = jwt.decode(token.split()[1], SECRET_KEY, algorithms=['HS256'])
            username = datos['username']
        except jwt.ExpiredSignatureError:
            return jsonify({'mensaje': 'Token expirado'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'mensaje': 'Token inválido'}), 401

        return func(*args, **kwargs)

    return wrapper

@app.route('/login', methods=['POST'])
def login():
    datos = request.json
    username = datos.get('username')
    contraseña = datos.get('password')

    if username and contraseña == '123':
        token = generar_token(username)
        return jsonify({'token': token}), 200
    else:
        return jsonify({'mensaje': 'Credenciales inválidas'}), 401
    
@app.route('/auth', methods=['GET'])
@verificar_token
def recurso_protegido():
    return jsonify({'mensaje': 'Hola! Este es un recurso protegido.'})

@app.route('/noauth', methods=['GET'])
def desprotegido():
    return jsonify({'mensaje': f'Hola, ! Este es un recurso protegido.'})




if __name__ == '__main__':
    app.run(debug=True)