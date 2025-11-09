import json
import os
from pathlib import Path

import requests
from flask import Flask, jsonify, redirect, request, session, url_for


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

# OAuth Configuration
oauth_config = config.get("oauth", {})
OAUTH_SCOPE = oauth_config.get("scope", "openid profile email")


# --- Client Application Routes ---


@app.route("/")
def index():
    if "access_token" in session:
        return ("Hello, you are logged in. "
                f"<a href='{url_for('protected')}'>Access Protected Resource</a> | "
                "<a href='{url_for('logout')}'>Logout</a>")
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


@app.route("/protected")
def protected():
    access_token = session.get("access_token")

    if not access_token:
        return "Access denied. Token not found.", 401

    USERINFO_ENDPOINT = f"{KEYCLOAK_URL}/protocol/openid-connect/userinfo"

    # --- Attempt 1: Use current token ---
    headers = {"Authorization": f"Bearer {access_token}"}
    user_info_response = requests.get(USERINFO_ENDPOINT, headers=headers, timeout=10)

    if user_info_response.status_code == 401:
        # --- Attempt 2: Token expired. Try to renew ---
        if renew_access_token():
            # Renewal successful. Get new token and retry the call
            new_access_token = session.get("access_token")
            if new_access_token:
                headers = {"Authorization": f"Bearer {new_access_token}"}
                user_info_response = requests.get(USERINFO_ENDPOINT, headers=headers, timeout=10)
            else:
                # This shouldn't happen if renewal succeeded, but for safety...
                return "Internal failure after renewal.", 500
        else:
            # Renewal failed (e.g. refresh token expired/revoked)
            return (
                "Session expired. Please <a href='/login'>log in</a> again.",
                401,
            )

    # --- If we get here, user_info_response should be 200 (after 1 or 2 attempts) ---
    if user_info_response.status_code == 200:
        user_data = user_info_response.json()
        return jsonify(
            {
                "msg": "Successful access to Protected Resource (Token renewed if necessary)",
                "user": user_data.get("preferred_username"),
                "token_info": user_data,
            }
        )
    else:
        # Any other IdP error
        return "Unexpected error accessing resource.", 500


@app.route("/logout")
def logout():
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
        return redirect(logout_url)

    # If no id_token, just redirect to home
    return redirect(url_for("index"))


if __name__ == "__main__":
    # Get Flask configuration
    flask_config = config.get("flask", {})
    app.run(
        debug=flask_config.get("debug", True),
        port=flask_config.get("port", 9090),
        host=flask_config.get("host", "0.0.0.0"),  # noqa: S104
    )
