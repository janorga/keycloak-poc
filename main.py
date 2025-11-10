import json
import logging
import os
from pathlib import Path

import jwt
import requests
from flask import Flask, jsonify, redirect, request, session, url_for

# Create a logger with default settings
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

if not logger.hasHandlers():
    handler = logging.StreamHandler()
    formatter = logging.Formatter('[%(asctime)s] %(levelname)s in %(module)s: %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)


# --- Load configuration from JSON file ---
def load_config(config_path="config.json"):
    """Loads configuration from a local JSON file."""
    config_file = Path(config_path)

    if not config_file.exists():
        raise FileNotFoundError(  # noqa: TRY003
            f"Configuration file not found: {config_path}\n"
            f"Copy config.json.example to config.json and configure your values."
        )

    with open(config_file, encoding="utf-8") as f:
        return json.load(f)


# Load configuration
config = load_config()

app = Flask(__name__)

# Configure Flask
flask_config = config.get("flask", {})
app.secret_key = flask_config.get("secret_key") or os.urandom(24)
BASE_URL = flask_config.get("base_url")  # Application base URL for callbacks

# --- Keycloak Configuration ---
keycloak_config = config.get("keycloak", {})
KEYCLOAK_URL = keycloak_config.get("url")
CLIENT_ID = keycloak_config.get("client_id")
CLIENT_SECRET = keycloak_config.get("client_secret")

# Validate required configuration values
if not all([KEYCLOAK_URL, CLIENT_ID, CLIENT_SECRET]):
    raise ValueError(  # noqa: TRY003
        "Missing required configuration values in config.json:\n"
        "keycloak.url, keycloak.client_id, keycloak.client_secret"
    )

AUTH_ENDPOINT = f"{KEYCLOAK_URL}/protocol/openid-connect/auth"
TOKEN_ENDPOINT = f"{KEYCLOAK_URL}/protocol/openid-connect/token"
LOGOUT_ENDPOINT = f"{KEYCLOAK_URL}/protocol/openid-connect/logout"
USERINFO_ENDPOINT = f"{KEYCLOAK_URL}/protocol/openid-connect/userinfo"
JWKS_URL = f"{KEYCLOAK_URL}/protocol/openid-connect/certs"

# OAuth Configuration
oauth_config = config.get("oauth", {})
OAUTH_SCOPE = oauth_config.get("scope", "openid profile email")


# --- Client Application Routes ---


@app.route("/")
def index():
    logger.info(f"New request to index route (IP: {request.remote_addr})")
    if "access_token" in session:
        logger.debug("User is logged in with access token.")
        return (
            "Hello, you are logged in. "
            f"<a href='{url_for('protected')}'>Access Protected Resource</a> | "
            f"<a href='{url_for('logout')}'>Logout</a>"
        )
    logger.debug("User is not logged in with access token.")
    return f"Welcome. <a href='{url_for('login')}'>Login with Keycloak</a>"


@app.route("/login")
def login():
    # 1. Redirect user to Keycloak for authentication
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
    # 2. Keycloak returns the authorization code
    auth_code = request.args.get("code")
    if not auth_code:
        return "Error: Authorization code not received", 400

    # 3. Exchange the code for tokens (POST request)
    token_data = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": url_for("callback", _external=True),
        "code": auth_code,
    }

    response = requests.post(TOKEN_ENDPOINT, data=token_data, timeout=10)
    response_json = response.json()

    if response.status_code != 200:
        return jsonify({"error": "Failed to obtain tokens", "details": response_json}), 500

    # Save tokens in Flask session
    session["access_token"] = response_json.get("access_token")
    session["id_token"] = response_json.get("id_token")
    session["refresh_token"] = response_json.get("refresh_token")

    logger.debug(f"Access token: {session['access_token']}\n")
    logger.debug(f"ID token: {session['id_token']}\n")
    logger.debug(f"Refresh token: {session['refresh_token']}\n")

    return redirect(url_for("index"))


def renew_access_token():
    """Attempts to use the refresh token to obtain a new access token."""
    refresh_token = session.get("refresh_token")

    if not refresh_token:
        # No refresh token, force re-login
        return False

    renewal_data = {
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": refresh_token,
    }

    # POST request to the same endpoint used for initial exchange
    response = requests.post(TOKEN_ENDPOINT, data=renewal_data, timeout=10)
    response_json = response.json()

    if response.status_code == 200:
        # Successful renewal: Update tokens in session
        session["access_token"] = response_json.get("access_token")
        # Refresh token may also rotate. If a new one is returned, save it.
        if response_json.get("refresh_token"):
            session["refresh_token"] = response_json.get("refresh_token")
        return True
    else:
        # Renewal failed (e.g. refresh token expired or revoked)
        # Clear session to force complete re-login
        session.pop("access_token", None)
        session.pop("refresh_token", None)
        return False


def verify_access_token(access_token: str | bytes) -> bool:
    """Verifies the JWT signature using Keycloak's JWKS endpoint."""
    try:
        jwks_client = jwt.PyJWKClient(JWKS_URL)
        signing_key = jwks_client.get_signing_key_from_jwt(access_token)
        # Decode and verify the token
        decoded_token = jwt.decode(
            access_token,
            signing_key.key,
            algorithms=["RS256"],
            audience="account",
            options={"verify_exp": True},
        )
        logger.debug(f"Token verified successfully for user: {decoded_token.get('preferred_username')}")
    except jwt.ExpiredSignatureError:
        logger.warning("Token has expired")
        raise
    except jwt.InvalidTokenError:
        logger.exception("Invalid token")
        return False
    except Exception:
        logger.exception("Token verification failed")
        return False

    return True


@app.route("/protected")
def protected():
    def return_protected_info():
        access_token = session.get("access_token")
        headers = {"Authorization": f"Bearer {access_token}"}
        user_info_response = requests.get(USERINFO_ENDPOINT, headers=headers, timeout=10)
        user_data = user_info_response.json()
        return jsonify(
            {
                "msg": "Successful access to Protected Resource (Token renewed if necessary)",
                "user": user_data.get("preferred_username"),
                "token_info": user_data,
            }
        )

    access_token = session.get("access_token")

    if not access_token:
        return "Access denied. Token not found.", 401

    try:
        if verify_access_token(access_token):
            logger.debug("Access token is valid. Accessing protected resource.")
            return return_protected_info()
        else:
            return (
                "Session error. Please <a href='/login'>log in</a> again.",
                401,
            )
    except jwt.ExpiredSignatureError:
        if renew_access_token():
            # Renewal successful. Get new token and retry the call
            logger.info("Access token renewed successfully.")
            new_access_token = session.get("access_token")
            if new_access_token:
                return return_protected_info()
            else:
                logger.exception("Internal failure after renewal.")
                return "Internal failure after renewal.", 500
        else:
            logger.exception("Token renewal failed.")
            return (
                "Session error. Please <a href='/login'>log in</a> again.",
                401,
            )


@app.route("/logout")
def logout():
    logger.info(f"Logout request from IP: {request.remote_addr}")
    # Get id_token before clearing session (needed for Keycloak)
    id_token = session.get("id_token")

    # Clear Flask local session
    session.pop("access_token", None)
    session.pop("id_token", None)
    session.pop("refresh_token", None)

    # Redirect to Keycloak to close complete session
    if id_token:
        # Build Keycloak logout URL with configured redirect
        post_logout_redirect_uri = BASE_URL or url_for("index", _external=True)

        logout_url = (
            f"{LOGOUT_ENDPOINT}?id_token_hint={id_token}&post_logout_redirect_uri={post_logout_redirect_uri}"
        )
        logger.debug(f"Redirecting to Keycloak logout URL: {logout_url}")
        return redirect(logout_url)

    # If no id_token, just redirect to home
    logger.debug("No id_token found; redirecting to home without Keycloak logout.")
    return redirect(url_for("index"))


if __name__ == "__main__":
    # Get Flask configuration
    flask_config = config.get("flask", {})
    app.run(
        debug=flask_config.get("debug", True),
        port=flask_config.get("port", 9090),
        host=flask_config.get("host", "0.0.0.0"),  # noqa: S104
    )
