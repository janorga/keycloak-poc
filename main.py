from flask import Flask, redirect, request, url_for, session, jsonify
import requests
import os
import json
from pathlib import Path


# --- Cargar configuración desde archivo JSON ---
def load_config(config_path="config.json"):
    """Carga la configuración desde un archivo JSON local."""
    config_file = Path(config_path)

    if not config_file.exists():
        raise FileNotFoundError(
            f"No se encontró el archivo de configuración: {config_path}\n"
            f"Copia config.json.example a config.json y configura tus valores."
        )

    with open(config_file, "r", encoding="utf-8") as f:
        return json.load(f)


# Cargar configuración
config = load_config()

app = Flask(__name__)

# Configurar Flask
flask_config = config.get("flask", {})
app.secret_key = flask_config.get("secret_key") or os.urandom(24)
BASE_URL = flask_config.get("base_url")  # URL base de la aplicación para callbacks

# --- Configuración de Keycloak ---
keycloak_config = config.get("keycloak", {})
KEYCLOAK_URL = keycloak_config.get("url")
CLIENT_ID = keycloak_config.get("client_id")
CLIENT_SECRET = keycloak_config.get("client_secret")

# Validar que se hayan configurado los valores requeridos
if not all([KEYCLOAK_URL, CLIENT_ID, CLIENT_SECRET]):
    raise ValueError(
        "Faltan valores de configuración requeridos en config.json:\n"
        "keycloak.url, keycloak.client_id, keycloak.client_secret"
    )

AUTH_ENDPOINT = f"{KEYCLOAK_URL}/protocol/openid-connect/auth"
TOKEN_ENDPOINT = f"{KEYCLOAK_URL}/protocol/openid-connect/token"
LOGOUT_ENDPOINT = f"{KEYCLOAK_URL}/protocol/openid-connect/logout"

# Configuración OAuth
oauth_config = config.get("oauth", {})
OAUTH_SCOPE = oauth_config.get("scope", "openid profile email")


# --- Rutas de la Aplicación Cliente ---


@app.route("/")
def index():
    if "access_token" in session:
        return f"Hola, has iniciado sesión. <a href='{url_for('protected')}'>Acceder a Recurso Protegido</a> | <a href='{url_for('logout')}'>Cerrar Sesión</a>"
    return f"Bienvenido. <a href='{url_for('login')}'>Iniciar Sesión con Keycloak</a>"


@app.route("/login")
def login():
    # 1. Redirigir al usuario a Keycloak para autenticarse
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": url_for("callback", _external=True),
        "response_type": "code",
        "scope": OAUTH_SCOPE,
    }
    auth_url = f"{AUTH_ENDPOINT}?{'&'.join([f'{k}={v}' for k, v in params.items()])}"
    return redirect(auth_url)


@app.route("/callback")
def callback():
    # 2. Keycloak nos devuelve el código de autorización
    auth_code = request.args.get("code")
    if not auth_code:
        return "Error: No se recibió código de autorización", 400

    # 3. Intercambiar el código por tokens (POST request)
    token_data = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": url_for("callback", _external=True),
        "code": auth_code,
    }

    response = requests.post(TOKEN_ENDPOINT, data=token_data)
    response_json = response.json()

    if response.status_code != 200:
        return jsonify(
            {"error": "Fallo al obtener tokens", "details": response_json}
        ), 500

    # Guardar tokens en la sesión de Flask
    session["access_token"] = response_json.get("access_token")
    session["id_token"] = response_json.get("id_token")
    session["refresh_token"] = response_json.get("refresh_token")

    return redirect(url_for("index"))


def renew_access_token():
    """Intenta usar el refresh token para obtener un nuevo access token."""
    refresh_token = session.get("refresh_token")

    if not refresh_token:
        # No hay refresh token, forzar el re-login
        return False

    renewal_data = {
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": refresh_token,
    }

    # Petición POST al mismo endpoint usado para el intercambio inicial
    response = requests.post(TOKEN_ENDPOINT, data=renewal_data)
    response_json = response.json()

    if response.status_code == 200:
        # Renovación exitosa: Actualizar los tokens en la sesión
        session["access_token"] = response_json.get("access_token")
        # El refresh token también puede rotar. Si se devuelve uno nuevo, guárdalo.
        if response_json.get("refresh_token"):
            session["refresh_token"] = response_json.get("refresh_token")
        return True
    else:
        # Fallo en la renovación (ej. refresh token caducado o revocado)
        # Limpiar la sesión para forzar el re-login completo
        session.pop("access_token", None)
        session.pop("refresh_token", None)
        return False


@app.route("/protected")
def protected():
    access_token = session.get("access_token")

    if not access_token:
        return "Acceso denegado. Token no encontrado.", 401

    USERINFO_ENDPOINT = f"{KEYCLOAK_URL}/protocol/openid-connect/userinfo"

    # --- Intento 1: Usar el token actual ---
    headers = {"Authorization": f"Bearer {access_token}"}
    user_info_response = requests.get(USERINFO_ENDPOINT, headers=headers)

    if user_info_response.status_code == 401:
        # --- Intento 2: El token caducó. Intentar renovar ---
        if renew_access_token():
            # Renovación exitosa. Obtener el nuevo token y reintentar la llamada
            new_access_token = session.get("access_token")
            if new_access_token:
                headers = {"Authorization": f"Bearer {new_access_token}"}
                user_info_response = requests.get(USERINFO_ENDPOINT, headers=headers)
            else:
                # Esto no debería pasar si la renovación tuvo éxito, pero por seguridad...
                return "Fallo interno después de la renovación.", 500
        else:
            # Renovación fallida (ej. refresh token caducado/revocado)
            return (
                "Sesión caducada. Por favor, <a href='/login'>inicie sesión</a> de nuevo.",
                401,
            )

    # --- Si llegamos aquí, user_info_response debería ser 200 (después de 1 o 2) ---
    if user_info_response.status_code == 200:
        user_data = user_info_response.json()
        return jsonify(
            {
                "msg": "Acceso exitoso al Recurso Protegido (Token renovado si fue necesario)",
                "usuario": user_data.get("preferred_username"),
                "token_info": user_data,
            }
        )
    else:
        # Cualquier otro error del IdP
        return "Error inesperado al acceder al recurso.", 500


@app.route("/logout")
def logout():
    # Obtener el id_token antes de limpiar la sesión (necesario para Keycloak)
    id_token = session.get("id_token")

    # Limpiar la sesión local de Flask
    session.pop("access_token", None)
    session.pop("id_token", None)
    session.pop("refresh_token", None)

    # Redirigir a Keycloak para cerrar la sesión completa
    if id_token:
        # Construir URL de logout de Keycloak con redirect configurado
        if BASE_URL:
            # Usar la URL base configurada en config.json
            post_logout_redirect_uri = BASE_URL
        else:
            # Fallback: usar url_for si no está configurada la base_url
            post_logout_redirect_uri = url_for("index", _external=True)

        logout_url = f"{LOGOUT_ENDPOINT}?id_token_hint={id_token}&post_logout_redirect_uri={post_logout_redirect_uri}"
        return redirect(logout_url)

    # Si no hay id_token, solo redirigir al inicio
    return redirect(url_for("index"))


if __name__ == "__main__":
    # Obtener configuración de Flask
    flask_config = config.get("flask", {})
    app.run(
        debug=flask_config.get("debug", True),
        port=flask_config.get("port", 9090),
        host=flask_config.get("host", "0.0.0.0"),
    )
