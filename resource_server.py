import logging
from pathlib import Path

import jwt
import requests
import yaml
from flask import Flask, jsonify, request

# Create a logger with default settings
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

if not logger.hasHandlers():
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(asctime)s] %(levelname)s in %(module)s: %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)


# --- Load configuration from YAML file ---
def load_config(config_path="config.yaml"):
    """Loads configuration from a local YAML file."""
    config_file = Path(config_path)

    if not config_file.exists():
        raise FileNotFoundError(  # noqa: TRY003
            f"Configuration file not found: {config_path}\n"
            f"Copy config.yaml.example to config.yaml and configure your values."
        )

    with open(config_file, encoding="utf-8") as f:
        return yaml.safe_load(f)


# Load configuration
config = load_config()

app = Flask(__name__)

# --- Keycloak Configuration ---
keycloak_config = config.get("keycloak", {})
KEYCLOAK_URL = keycloak_config.get("url")
JWKS_URL = f"{KEYCLOAK_URL}/protocol/openid-connect/certs"
USERINFO_ENDPOINT = f"{KEYCLOAK_URL}/protocol/openid-connect/userinfo"


def verify_access_token(access_token: str) -> bool:
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
    except jwt.ExpiredSignatureError:
        logger.warning("Token has expired")
        return False
    except jwt.InvalidTokenError:
        logger.exception("Invalid token")
        return False
    except Exception:
        logger.exception("Token verification failed")
        return False

    logger.debug(f"Token verified successfully for user: {decoded_token.get('preferred_username')}")
    return True


@app.route("/api/protected-resource")
def protected_resource():
    """
    Endpoint that serves protected resources.
    Requires a valid Bearer token in the Authorization header.
    """
    # Extract the Authorization header
    auth_header = request.headers.get("Authorization")
    logger.debug(f"Accessing protected resource endpoint from IP: {request.remote_addr}")
    logger.debug(f"Authorization header received: {auth_header}")

    if not auth_header:
        logger.warning("No Authorization header provided")
        return jsonify({"error": "No authorization header provided"}), 401

    # Check if it's a Bearer token
    if not auth_header.startswith("Bearer "):
        logger.warning("Invalid authorization header format")
        return jsonify({"error": "Invalid authorization header format"}), 401

    # Extract the token
    access_token = auth_header.split(" ")[1]

    # Verify the token
    if not verify_access_token(access_token):
        logger.warning("Invalid or expired access token")
        return jsonify({"error": "Invalid or expired access token"}), 401

    # Token is valid, fetch user info and return protected resource
    try:
        headers = {"Authorization": f"Bearer {access_token}"}
        user_info_response = requests.get(USERINFO_ENDPOINT, headers=headers, timeout=10)

        if user_info_response.status_code != 200:
            logger.error(f"Failed to fetch user info: {user_info_response.status_code}")
            return jsonify({"error": "Failed to fetch user information"}), 500

        user_data = user_info_response.json()

        logger.info(f"Protected resource accessed by user: {user_data.get('preferred_username')}")

        logger.debug(f"User info: {user_data}")

        # Return the protected resource data
        return jsonify(
            {
                "msg": "Access granted to protected resource",
                "resource_data": {
                    "resource_type": "confidential_data",
                    "resource_id": "12345",
                    "description": "This is sensitive information that requires authentication",
                },
                "user": user_data.get("preferred_username"),
                "user_info": user_data,
            }
        ), 200

    except Exception:
        logger.exception("Error processing protected resource request")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/health")
def health():
    """Health check endpoint."""
    return jsonify({"status": "healthy", "service": "resource_server"}), 200


if __name__ == "__main__":
    # Get resource server configuration or use defaults
    resource_config = config.get("resource_server", {})
    app.run(
        debug=resource_config.get("debug", True),
        port=resource_config.get("port", 9091),
        host=resource_config.get("host", "0.0.0.0"),  # noqa: S104
    )
