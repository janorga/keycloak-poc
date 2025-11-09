from flask import Flask, redirect, request, url_for, session, jsonify
import requests
import os # Para variables de entorno o configuración

app = Flask(__name__)
app.secret_key = os.urandom(24) # Clave para la sesión de Flask

# --- Configuración de Keycloak ---
KEYCLOAK_URL = "http://192.168.1.76:8080/realms/Laboratorio"
CLIENT_ID = "flask-client"
CLIENT_SECRET = "jXCDvmLhiRvwwnDYNVh0JcI3Lo7HIgaG" # Usar el secreto de Keycloak

AUTH_ENDPOINT = f"{KEYCLOAK_URL}/protocol/openid-connect/auth"
TOKEN_ENDPOINT = f"{KEYCLOAK_URL}/protocol/openid-connect/token"

# --- Rutas de la Aplicación Cliente ---

@app.route('/')
def index():
    if 'access_token' in session:
        return f"Hola, has iniciado sesión. <a href='{url_for('protected')}'>Acceder a Recurso Protegido</a> | <a href='{url_for('logout')}'>Cerrar Sesión</a>"
    return f"Bienvenido. <a href='{url_for('login')}'>Iniciar Sesión con Keycloak</a>"

@app.route('/login')
def login():
    # 1. Redirigir al usuario a Keycloak para autenticarse
    params = {
        'client_id': CLIENT_ID,
        'redirect_uri': url_for('callback', _external=True),
        'response_type': 'code',
        'scope': 'openid profile email' # Solicitar tokens OIDC
    }
    auth_url = f"{AUTH_ENDPOINT}?{'&'.join([f'{k}={v}' for k, v in params.items()])}"
    return redirect(auth_url)

@app.route('/callback')
def callback():
    # 2. Keycloak nos devuelve el código de autorización
    auth_code = request.args.get('code')
    if not auth_code:
        return "Error: No se recibió código de autorización", 400

    # 3. Intercambiar el código por tokens (POST request)
    token_data = {
        'grant_type': 'authorization_code',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'redirect_uri': url_for('callback', _external=True),
        'code': auth_code
    }

    response = requests.post(TOKEN_ENDPOINT, data=token_data)
    response_json = response.json()

    if response.status_code != 200:
        return jsonify({'error': 'Fallo al obtener tokens', 'details': response_json}), 500

    # Guardar tokens en la sesión de Flask
    session['access_token'] = response_json.get('access_token')
    session['id_token'] = response_json.get('id_token')
    
    return redirect(url_for('index'))

@app.route('/protected')
def protected():
    # Usar el token para acceder a un recurso (Simulación)
    access_token = session.get('access_token')
    
    if not access_token:
        return "Acceso denegado. <a href='/login'>Iniciar Sesión</a>", 401

    # (Opcional) Llamar al endpoint /userinfo de Keycloak para obtener datos del usuario
    USERINFO_ENDPOINT = f"{KEYCLOAK_URL}/protocol/openid-connect/userinfo"
    
    headers = {'Authorization': f'Bearer {access_token}'}
    user_info_response = requests.get(USERINFO_ENDPOINT, headers=headers)
    
    if user_info_response.status_code == 200:
        user_data = user_info_response.json()
        return jsonify({
            "msg": "Acceso exitoso al Recurso Protegido",
            "usuario": user_data.get('preferred_username'),
            "token_info": user_data
        })
    else:
        return "Error: El Access Token no es válido o está caducado.", 401

@app.route('/logout')
def logout():
    session.pop('access_token', None)
    session.pop('id_token', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    # Nota: Usar host='0.0.0.0' para asegurar que Docker pueda acceder a localhost:9090
    app.run(debug=True, port=9090, host='0.0.0.0')
