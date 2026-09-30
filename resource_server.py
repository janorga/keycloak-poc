"""
Bearer-token API server for the OAuth2/OIDC teaching lab.

Validates the access tokens minted by Keycloak (RS256 signature checked against
Keycloak's JWKS) and authorizes each request with a realm role carried in the
`realm_access.roles` claim. All claims are read from the access token itself:
Keycloak 26.6.2+ refuses "lightweight" access tokens at `/userinfo`, so
calling that endpoint is a known trap in this lab.
"""

import logging
from functools import wraps
from pathlib import Path

import jwt
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
        raise FileNotFoundError( # noqa: TRY003
            f"Configuration file not found: {config_path}\n"
            f"Copy config.yaml.example to config.yaml and configure your values."
        )

    with open(config_file, encoding="utf-8") as f:
        return yaml.safe_load(f)


# Load configuration
config = load_config()

app = Flask(__name__)

# --- Keycloak Configuration ---
# internal_url is the container-to-container address; the browser cannot resolve it.
keycloak_config = config.get("keycloak", {})
KEYCLOAK_INTERNAL_URL = keycloak_config.get("internal_url")
KEYCLOAK_AUDIENCE = keycloak_config.get("audience")

# Validate required configuration values
if not KEYCLOAK_INTERNAL_URL or not KEYCLOAK_AUDIENCE:
    raise ValueError(  # noqa: TRY003
        "Missing required configuration values in config.yaml:\n"
        "keycloak.internal_url, keycloak.audience"
    )

JWKS_URL = f"{KEYCLOAK_INTERNAL_URL}/protocol/openid-connect/certs"

UNAUTHORIZED_HEADERS = {"WWW-Authenticate": 'Bearer realm="lab"'}


# --- Token verification ---


def verify_access_token(access_token: str) -> dict | None:
    """
    Verifies the RS256 signature against Keycloak's JWKS and returns the claims.

    Returns None when the token cannot be trusted (bad signature, expired, malformed).
    The audience claim is NOT validated here: a token minted for another API is
    still cryptographically valid, it is just not for us.
    """
    try:
        jwks_client = jwt.PyJWKClient(JWKS_URL)
        signing_key = jwks_client.get_signing_key_from_jwt(access_token)
        decoded_token = jwt.decode(
            access_token,
            signing_key.key,
            algorithms=["RS256"],
            options={"verify_aud": False, "verify_exp": True},
        )
    except jwt.ExpiredSignatureError:
        logger.warning("Token has expired")
        return None
    except jwt.InvalidTokenError:
        logger.warning("Invalid token rejected by signature or claim validation")
        return None
    except Exception:
        logger.exception("Token verification failed")
        return None

    logger.debug(f"Token verified successfully for user: {decoded_token.get('preferred_username')}")
    return decoded_token


def bearer_token_from_request() -> str | None:
    """Extracts the token from the Authorization header, or None if unusable."""
    auth_header = request.headers.get("Authorization")
    logger.debug(f"Accessing {request.path} from IP: {request.remote_addr}")

    if not auth_header:
        logger.warning("No Authorization header provided")
        return None

    scheme, _, token = auth_header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        logger.warning("Invalid authorization header format, expected 'Bearer <token>'")
        return None

    return token.strip()


def roles_from_claims(claims: dict) -> list:
    """Reads the realm role list out of the `realm_access.roles` claim."""
    realm_access = claims.get("realm_access") or {}
    roles = realm_access.get("roles") or []
    return list(roles)


def display_user(claims: dict) -> str | None:
    """Best available human identifier for an ACCESS token.

    `preferred_username` lives in the id_token, not the access token, so on an
    access token it is simply absent. Falling back keeps the projected page from
    showing "null" where a name should be.
    """
    return claims.get("preferred_username") or claims.get("email") or claims.get("given_name")


# --- Authorization helper ---


def require_role(required_role: str):
    """
    Guards a route with the shared token/audience/role pipeline.

    Returns a 401 for an unusable token, 403 for a valid token that is not for
    this API or that lacks `required_role`, and lets the route run on success.
    """

    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            access_token = bearer_token_from_request()
            if not access_token:
                return (
                    jsonify(
                        {
                            "error": "unauthorized",
                            "msg": "Falta la cabecera Authorization con un token Bearer.",
                        }
                    ),
                    401,
                    UNAUTHORIZED_HEADERS,
                )

            claims = verify_access_token(access_token)
            if claims is None:
                return (
                    jsonify(
                        {
                            "error": "unauthorized",
                            "msg": (
                                "El token es invalido: firma incorrecta, "
                                "token manipulado o token expirado."
                            ),
                        }
                    ),
                    401,
                    UNAUTHORIZED_HEADERS,
                )

            # The token is authentic, so this is a 403 and not a 401.
            audience = claims.get("aud")
            audiences = [audience] if isinstance(audience, str) else list(audience or [])
            if KEYCLOAK_AUDIENCE not in audiences:
                logger.warning(f"Token audience {audiences} does not include {KEYCLOAK_AUDIENCE}")
                return (
                    jsonify(
                        {
                            "error": "forbidden",
                            "msg": (
                                "Este token no fue emitido para esta API. "
                                "El claim 'aud' debe contener 'api-resource'."
                            ),
                            "required_audience": KEYCLOAK_AUDIENCE,
                            "aud": audience,
                        }
                    ),
                    403,
                )

            roles = roles_from_claims(claims)
            if required_role not in roles:
                logger.warning(f"User {display_user(claims)} lacks role {required_role}")
                return (
                    jsonify(
                        {
                            "error": "forbidden",
                            "msg": (
                                f"Falta el rol de realm '{required_role}' en el claim "
                                "'realm_access.roles' de este token."
                            ),
                            "required_role": required_role,
                            "roles": roles,
                        }
                    ),
                    403,
                )

            return view(claims, roles, *args, **kwargs)

        return wrapper

    return decorator


# --- API Endpoints ---


@app.route("/api/user-only")
@require_role("user")
def user_only(claims, roles):
    """Endpoint that requires the realm role `user`."""
    logger.info(f"user-only granted to {display_user(claims)}")
    return (
        jsonify(
            {
                "msg": (
                    "Acceso permitido porque tu token incluye el rol 'user', "
                    "que es el rol de realm exigido por esta estacion."
                ),
                "endpoint": "/api/user-only",
                "required_role": "user",
                "granted_role": "user",
                "roles": roles,
                "aud": claims.get("aud"),
                "preferred_username": display_user(claims),
                "user": display_user(claims),
            }
        ),
        200,
    )


@app.route("/api/admin-only")
@require_role("admin")
def admin_only(claims, roles):
    """Endpoint that requires the realm role `admin`."""
    logger.info(f"admin-only granted to {display_user(claims)}")
    return (
        jsonify(
            {
                "msg": (
                    "Acceso permitido porque tu token incluye el rol 'admin', "
                    "que es el rol de realm exigido por esta estacion."
                ),
                "endpoint": "/api/admin-only",
                "required_role": "admin",
                "granted_role": "admin",
                "roles": roles,
                "aud": claims.get("aud"),
                "preferred_username": display_user(claims),
                "user": display_user(claims),
            }
        ),
        200,
    )


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
