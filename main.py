"""AuthLab - the Flask side of the OAuth2/OIDC teaching demo.

One route per station of the class. Every screen exists to make one idea visible:

    station 1  the four legs of the authorization code flow
    station 2  what is inside a JWT, and what a scope adds
    station 3  OAuth2 alone is not login
    station 4  authentication is not authorization

The JWT decoding in here is deliberately naive and clearly labelled as such.
Verifying a signature needs the JWKS dance, and the point of this file is to let
the class *look* at the claims. The resource server, which is the component that
actually enforces something, verifies properly.
"""

import base64
import hashlib
import json
import logging
import secrets
import time
from pathlib import Path

import requests
import yaml
from flask import Flask, redirect, render_template, request, session, url_for

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


config = load_config()

app = Flask(__name__)

# --- Flask configuration ---
flask_config = config.get("flask", {})
app.secret_key = flask_config.get("secret_key") or secrets.token_hex(24)
BASE_URL = (flask_config.get("base_url") or "http://localhost:9090").rstrip("/")

# --- Claim history, kept OUTSIDE the session cookie ---
# Flask stores the session in a cookie, and cookies are capped at ~4 KB. Keeping
# decoded access tokens in there overflowed it (Werkzeug warned, then the browser
# dropped the cookie and the session silently vanished between requests). The
# snapshots are server-side state, not client state, so they belong here: a plain
# dict keyed by a random id kept in the session. One classroom, one browser at a
# time, so an in-process store is the right amount of machinery. A restart clears
# it, which is fine: the class starts from a clean stack anyway.
_claim_history: dict[str, list] = {}

# --- Keycloak configuration ---
# Two URLs, and the difference is the whole point of station 1.
#   INTERNAL_URL is container -> container. The compose DNS name `keycloak` exists
#     only inside the docker network.
#   PUBLIC_URL is browser -> container. This is the one that goes into the address
#     bar and into redirect_uri.
# Get these the wrong way round and the login silently breaks the moment you fix
# the "obvious" hostname.
keycloak_config = config.get("keycloak", {})
INTERNAL_URL = keycloak_config.get("internal_url")
PUBLIC_URL = keycloak_config.get("public_url")
CLIENT_ID = keycloak_config.get("client_id")
CLIENT_SECRET = keycloak_config.get("client_secret")
PUBLIC_CLIENT_ID = keycloak_config.get("public_client_id")
AUDIENCE = keycloak_config.get("audience")

if not all([INTERNAL_URL, PUBLIC_URL, CLIENT_ID, CLIENT_SECRET, PUBLIC_CLIENT_ID]):
    raise ValueError(  # noqa: TRY003
        "Missing required configuration: keycloak.internal_url, keycloak.public_url, "
        "keycloak.client_id, keycloak.client_secret, keycloak.public_client_id"
    )


def _internal(endpoint):
    """URL the Flask container uses to call Keycloak."""
    return f"{INTERNAL_URL.rstrip('/')}/{endpoint}"


def _public(endpoint):
    """URL the BROWSER uses to reach Keycloak."""
    return f"{PUBLIC_URL.rstrip('/')}/{endpoint}"


# The authorize endpoint is the ONE place where the browser, not the container,
# follows the URL. Building it from the internal url produces
# `http://keycloak:8080/...` and the login breaks with a DNS error in the
# browser, while the server keeps working fine. That asymmetry is the trap.
AUTH_ENDPOINT = _public("protocol/openid-connect/auth")
AUTH_ENDPOINT_INTERNAL = _internal("protocol/openid-connect/auth")

# These three are back-channel only: the Flask container calls them, never the
# browser, so they must use the internal name.
TOKEN_ENDPOINT = _internal("protocol/openid-connect/token")
USERINFO_ENDPOINT = _internal("protocol/openid-connect/userinfo")
JWKS_URL = _internal("protocol/openid-connect/certs")

LOGOUT_ENDPOINT = _public("protocol/openid-connect/logout")
DISCOVERY_URL = _public(".well-known/openid-configuration")

oauth_config = config.get("oauth", {})
SCOPE = oauth_config.get("scope", "openid")
SCOPE_WITHOUT_OPENID = oauth_config.get("scope_without_openid", "profile")
SCOPE_EXTENDED = oauth_config.get("scope_extended", "openid demo-perfil")

RESOURCE_SERVER_URL = config.get("resource_server", {}).get("url", "http://resource-server:9091")

# Refresh this many seconds before the access token actually dies, so a page
# rendered at the right moment does not hand a dead token to the resource server.
REFRESH_MARGIN_SECONDS = 10

# How many past logins station 2 can diff against. Two is the minimum that makes
# the diff work; a few more so a student who fumbles the first attempt does not
# have to start over.
MAX_CLAIM_SNAPSHOTS = 4

# Variant name -> Flask endpoint. The variants carry hyphens, endpoint names
# cannot, so this mapping is explicit rather than built by string surgery.
CALLBACK_ENDPOINTS = {
    "oidc": "callback_oidc",
    "scope-extended": "callback_scope_extended",
    "no-openid": "callback_no_openid",
    "pkce": "callback_pkce",
}

# Used to keep the session cookie bounded: traces are stored per variant, so
# there must be a closed set of names to filter against.
KNOWN_VARIANTS = frozenset(CALLBACK_ENDPOINTS) | {"refresh"}


def public_url_for(endpoint, **values):
    """url_for(..., _external=True) but pinned to the browser-visible base URL.

    Flask would otherwise build the callback URL from the Host header, which is
    `main-app:9090` when compose calls the app. That hostname is not registered
    and not resolvable from a laptop.
    """
    return f"{BASE_URL}{url_for(endpoint, **values)}"


# --- Deliberately naive JWT decoding, for looking only ---

def decode_jwt_claims(token):
    """Base64url-decodes the payload of a JWT without verifying anything.

    This is NOT validation. It is a projector. Anything you do with the result of
    this function is a decision made on unverified data.
    """
    if not token or token.count(".") < 2:
        return {}
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    try:
        return base64.urlsafe_b64decode(payload)
    except Exception:
        logger.warning("Could not base64url-decode a JWT payload")
        return {}


def import_jwt_claims(token):
    """decode_jwt_claims, but returning a dict."""
    return json.loads(decode_jwt_claims(token) or b"{}")


def seconds_until_expiry(token):
    """Seconds left before the access token dies. Negative once expired."""
    claims = import_jwt_claims(token)
    return int(claims.get("exp", 0)) - int(time.time())


# --- Session helpers ---

def store_tokens(token_response, variant):
    """Puts a token endpoint response into the session and records the trace."""
    session["access_token"] = token_response.get("access_token")
    session["refresh_token"] = token_response.get("refresh_token")
    session["variant"] = variant

    id_token = token_response.get("id_token")
    if id_token:
        session["id_token"] = id_token
    else:
        # Station 3 lives on exactly this: no `openid` in the scope, no id_token.
        session.pop("id_token", None)

    claims = import_jwt_claims(session.get("access_token"))
    record_claims(variant, claims)

    return claims


def _history_id() -> str:
    """Stable per-browser key for the claim history."""
    hid = session.get("claim_history_id")
    if not hid:
        hid = secrets.token_hex(8)
        session["claim_history_id"] = hid
    return hid


def summarize_token_response(body):
    """Token endpoint response with the JWTs replaced by a length marker.

    Flask keeps the session in a cookie capped at ~4 KB, and a full token
    response carries three JWTs of roughly 2 KB each. Storing them verbatim
    overflowed the cookie and the browser dropped the session, which made the
    app look like it was randomly logging people out. The class only needs to
    see that a token came back, and the real values are on screen anyway.
    """
    if not isinstance(body, dict):
        return body
    return {
        **body,
        **{
            k: f"<JWT {len(v)} chars>"
            for k, v in body.items()
            if isinstance(v, str) and v.count(".") == 2
        },
    }


def record_claims(variant, claims):
    """Appends one login to the history, server-side and bounded."""
    hid = _history_id()
    snapshots = _claim_history.setdefault(hid, [])
    snapshots.append({"variant": variant, "at": int(time.time()), "claims": claims})
    del snapshots[:-MAX_CLAIM_SNAPSHOTS]


def current_claims_diff():
    """Claim-by-claim difference between this login and the one before it.

    Server-side on purpose: the diff is only interesting if you have the previous
    token to compare against, and the class only has one browser. It also has to
    survive the logout that separates the two logins.
    """
    snapshots = _claim_history.get(_history_id()) or []
    if len(snapshots) < 2:
        return None

    previous, current = snapshots[-2], snapshots[-1]
    old, new = previous["claims"], current["claims"]

    return {
        "previous_variant": previous["variant"],
        "current_variant": current["variant"],
        "added": {k: new[k] for k in new if k not in old},
        "removed": {k: old[k] for k in old if k not in new},
        "changed": {k: {"from": old[k], "to": new[k]} for k in old if k in new and old[k] != new[k]},
    }


def do_refresh(reason):
    """Exchanges the refresh token for a new access token, visibly.

    Called automatically when the access token is about to expire. Returns True on
    success. On failure the session is cleared, because a refresh token that no
    longer works is exactly the "log in again" case.
    """
    refresh_token = session.get("refresh_token")
    if not refresh_token:
        logger.warning("No refresh token in session, cannot refresh")
        return False

    payload = {
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": refresh_token,
    }

    response = requests.post(TOKEN_ENDPOINT, data=payload, timeout=10)
    body = response.json()

    trace = {
        "reason": reason,
        "at": int(time.time()),
        "request": {k: v for k, v in payload.items() if k != "client_secret"},
        "client_secret_sent": True,
        "response_status": response.status_code,
        "response": summarize_token_response(body),
    }

    if response.status_code != 200:
        logger.warning("Refresh failed: %s", body)
        session["traces"] = dict(session.get("traces") or {})
        session["traces"]["refresh"] = trace
        session.pop("access_token", None)
        session.pop("refresh_token", None)
        return False

    store_tokens(body, session.get("variant", "oidc"))
    session["refresh_count"] = session.get("refresh_count", 0) + 1
    session["traces"] = dict(session.get("traces") or {})
    session["traces"]["refresh"] = trace
    logger.info("Access token refreshed transparently (%s), total %s", reason, session["refresh_count"])
    return True


def ensure_fresh_access_token():
    """Returns a usable access token, refreshing first if it is about to expire.

    This is what makes checkpoint 5 work: the token lives 60 seconds, you wait,
    you click again, and the call still succeeds. The refresh is recorded so the
    page can tell the class it happened.
    """
    token = session.get("access_token")
    if not token:
        return None
    if seconds_until_expiry(token) <= REFRESH_MARGIN_SECONDS:
        do_refresh("el access token caducaba")
        token = session.get("access_token")
    return token


@app.before_request
def _refresh_before_render():
    """Keeps the access token alive for EVERY page, not just the ones that call
    the resource server.

    This used to live only in station 4, which made the status bar lie: after the
    60 s token expired, the other pages kept rendering "caduca en -565 s" and
    "refreshes transparentes: 0" while station 4 showed a healthy 60 s. Worse than
    cosmetic, station 2 was showing an expired token and station 3 was calling
    /userinfo with it.

    Skips the static files and the endpoints that are themselves about the token
    exchange, so /refresh stays a deliberate, clickable action.
    """
    if request.endpoint in {"static", "refresh", "callback_oidc", "callback_scope_extended",
                            "callback_no_openid", "callback_pkce", "logout", "logout_local"}:
        return
    ensure_fresh_access_token()


def record_trace(variant, trace):
    # Bounded by construction: one entry per known variant, so the session cookie
    # cannot grow without limit across repeated logins in the same browser.
    traces = dict(session.get("traces") or {})
    traces[variant] = trace
    session["traces"] = {k: v for k, v in traces.items() if k in KNOWN_VARIANTS}


def token_state():
    """Small summary every template shows about the current session."""
    token = session.get("access_token")
    if not token:
        return {"logged_in": False}

    return {
        "logged_in": True,
        "variant": session.get("variant"),
        "has_id_token": bool(session.get("id_token")),
        "has_refresh_token": bool(session.get("refresh_token")),
        "expires_in": seconds_until_expiry(token),
        "refresh_count": session.get("refresh_count", 0),
        "access_token": token,
        "id_token": session.get("id_token"),
        "claims": import_jwt_claims(token),
    }


# --- The four legs of the flow, in one place ---

def build_authorize_url(variant, scope, client_id=CLIENT_ID, pkce_challenge=None):
    """Legs 1 and 2: state and nonce, then the redirect to Keycloak."""
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)

    session["oauth_state"] = state
    session["oauth_nonce"] = nonce
    session["oauth_variant"] = variant

    params = {
        "client_id": client_id,
        "redirect_uri": public_url_for(CALLBACK_ENDPOINTS[variant]),
        "response_type": "code",
        "scope": scope,
        "state": state,
        "nonce": nonce,
    }

    if pkce_challenge:
        # The verifier is set by the caller and MUST NOT be touched here: the
        # challenge is its hash, and storing the challenge under this key would
        # make the token exchange send the hash as the verifier and fail.
        params["code_challenge"] = pkce_challenge
        params["code_challenge_method"] = "S256"

    query = "&".join(f"{k}={v}" for k, v in params.items())
    auth_url = f"{AUTH_ENDPOINT}?{query}"

    record_trace(
        variant,
        {
            "at": int(time.time()),
            "scope": scope,
            "client_id": client_id,
            "redirect_uri": params["redirect_uri"],
            "state": state,
            "nonce": nonce,
            "code_challenge": pkce_challenge,
            "authorize_url": auth_url,
        },
    )

    return auth_url


def exchange_code(code, variant, redirect_uri):
    """Leg 4: the code is exchanged at the token endpoint over the back channel."""
    # The PKCE variant authenticated as the PUBLIC client, so the token request
    # has to name that same client. Sending the confidential one here fails with
    # "invalid client credentials".
    is_public = variant == "pkce"
    client_id = PUBLIC_CLIENT_ID if is_public else CLIENT_ID

    payload = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code": code,
    }
    if not is_public:
        payload["client_secret"] = CLIENT_SECRET
    else:
        payload["code_verifier"] = session.get("pkce_verifier")

    is_confidential = not is_public

    response = requests.post(TOKEN_ENDPOINT, data=payload, timeout=10)
    body = response.json()

    trace = {
        "at": int(time.time()),
        "variant": variant,
        "code": code,
        "request": payload,
        "is_confidential": is_confidential,
        "response_status": response.status_code,
        "response": summarize_token_response(body),
        "expires_in": body.get("expires_in"),
        "refresh_expires_in": body.get("refresh_expires_in"),
    }
    record_trace(variant, trace)

    if response.status_code != 200:
        logger.warning("Token exchange failed: %s", body)
        return None, trace

    store_tokens(body, variant)
    return body, trace


def callback_error(title, message):
    """Every rejected callback looks the same on screen."""
    logger.warning("Callback rejected: %s (%s)", title, message)
    return render_template("error.html", title=title, message=message), 400


def handle_callback(variant):
    """Shared callback body for every flow variant."""
    expected_state = session.pop("oauth_state", None)
    expected_nonce = session.pop("oauth_nonce", None)
    session.pop("oauth_variant", None)

    error = request.args.get("error")
    if error:
        return callback_error(
            "Keycloak devolvio un error",
            request.args.get("error_description") or error,
        )

    code = request.args.get("code")
    returned_state = request.args.get("state")

    if not code:
        return callback_error(
            "No llego el authorization code",
            "Keycloak no devolvio ningun parametro `code` en la callback.",
        )

    # state exists to stop someone else feeding us their own code.
    if not expected_state or returned_state != expected_state:
        return callback_error(
            "El state no coincide",
            "El parametro `state` de vuelta no es el que enviamos. "
            "Eso es exactamente el ataque que state previene.",
        )

    redirect_uri = public_url_for(CALLBACK_ENDPOINTS[variant])
    tokens, trace = exchange_code(code, variant, redirect_uri)

    if tokens is None:
        return callback_error(
            "El token endpoint rechazo el code",
            trace["response"].get("error_description") or trace["response"].get("error", "?"),
        )

    # nonce binds the id_token to this browser session. Without the check, an
    # id_token captured elsewhere would still validate.
    if tokens.get("id_token") and expected_nonce:
        id_claims = import_jwt_claims(tokens["id_token"])
        if id_claims.get("nonce") != expected_nonce:
            return callback_error(
                "El nonce no coincide",
                "El id_token no viene ligado a esta sesion.",
            )

    if variant == "pkce":
        session.pop("pkce_verifier", None)

    return redirect(url_for("index"))


@app.template_filter("pretty")
def pretty(value):
    """Renders JSON the way it appears on a slide, not the way it appears in a log."""
    try:
        return json.dumps(value, indent=2, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(value)


@app.template_filter("b64decode")
def b64decode(value):
    """base64url -> text, for showing the parts of a JWT apart."""
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded).decode("utf-8", "replace")


@app.template_filter("fromjson")
def fromjson(value):
    """Parses JSON text into something the `pretty` filter can render."""
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return value


# --- Routes ---

@app.route("/")
def index():
    """Station 0. The credentials are on screen so nobody spends time on login."""
    return render_template(
        "index.html",
        token=token_state(),
        internal_url=INTERNAL_URL,
        public_url=PUBLIC_URL,
        # PUBLIC_URL already carries /realms/lab. The admin console lives at the
        # server root, not inside the realm, so it needs the host on its own.
        public_root=PUBLIC_URL.split("/realms/")[0],
        client_id=CLIENT_ID,
        public_client_id=PUBLIC_CLIENT_ID,
        audience=AUDIENCE,
        traces=session.get("traces") or {},
    )


@app.route("/login")
def login():
    """Legs 1 and 2: bounce the browser to Keycloak."""
    return redirect(build_authorize_url("oidc", SCOPE))


@app.route("/login/scope-extended")
def login_scope_extended():
    """Same flow, one more scope requested. Station 2 diffs the two tokens."""
    return redirect(build_authorize_url("scope-extended", SCOPE_EXTENDED))


@app.route("/login/no-openid")
def login_no_openid():
    """The same request with `openid` removed. Station 3."""
    return redirect(build_authorize_url("no-openid", SCOPE_WITHOUT_OPENID))


@app.route("/login/pkce")
def login_pkce():
    """Public client, so there is no secret. PKCE S256 replaces it."""
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    session["pkce_verifier"] = verifier
    return redirect(build_authorize_url("pkce", SCOPE, client_id=PUBLIC_CLIENT_ID, pkce_challenge=challenge))


@app.route("/callback")
def callback_oidc():
    return handle_callback("oidc")


@app.route("/callback/scope")
def callback_scope_extended():
    return handle_callback("scope-extended")


@app.route("/callback/no-openid")
def callback_no_openid():
    return handle_callback("no-openid")


@app.route("/callback/pkce")
def callback_pkce():
    return handle_callback("pkce")


@app.route("/station/flow")
def station_flow():
    """Station 1: the four legs, with the literal URLs from your own login."""
    return render_template(
        "station_flow.html",
        token=token_state(),
        trace=(session.get("traces") or {}).get(session.get("variant", "oidc")),
        internal_auth=AUTH_ENDPOINT_INTERNAL,
        public_auth=AUTH_ENDPOINT,
        token_endpoint=TOKEN_ENDPOINT,
        resource_server_url=RESOURCE_SERVER_URL,
    )


@app.route("/station/jwt")
def station_jwt():
    """Station 2: the claims, and what one extra scope added."""
    return render_template(
        "station_jwt.html",
        token=token_state(),
        diff=current_claims_diff(),
        scope=SCOPE,
        scope_extended=SCOPE_EXTENDED,
    )


@app.route("/station/not-login")
def station_not_login():
    """Station 3: OAuth2 without `openid` is not login.

    Deliberately calls /userinfo with the access token so the 401 is visible.
    """
    userinfo = None
    token = session.get("access_token")
    if token:
        response = requests.get(USERINFO_ENDPOINT, headers={"Authorization": f"Bearer {token}"}, timeout=10)
        try:
            body = response.json()
        except ValueError:
            body = response.text
        userinfo = {"status": response.status_code, "body": body}

    return render_template(
        "station_not_login.html",
        token=token_state(),
        trace=(session.get("traces") or {}).get("no-openid"),
        userinfo=userinfo,
        scope_without_openid=SCOPE_WITHOUT_OPENID,
        userinfo_endpoint=USERINFO_ENDPOINT,
    )


@app.route("/station/roles")
def station_roles():
    """Station 4: ana and luis, same endpoint, different answer."""
    results = {}
    token = ensure_fresh_access_token()

    if token:
        headers = {"Authorization": f"Bearer {token}"}
        for endpoint in ("user-only", "admin-only"):
            url = f"{RESOURCE_SERVER_URL}/api/{endpoint}"
            try:
                response = requests.get(url, headers=headers, timeout=10)
                try:
                    body = response.json()
                except ValueError:
                    body = {"raw": response.text}
            except requests.exceptions.RequestException as exc:
                body = {"error": f"No se pudo contactar con el resource server: {exc}"}
                response = None
            # `is not None`, never truthiness: a requests.Response with a 4xx is
            # FALSY, which silently turns a correct 403 into a fake 503.
            status = response.status_code if response is not None else 503
            results[endpoint] = {"status": status, "body": body}

    return render_template(
        "station_roles.html",
        token=token_state(),
        results=results,
        refresh_trace=(session.get("traces") or {}).get("refresh"),
    )


@app.route("/station/pkce")
def station_pkce():
    """Bonus station: what PKCE replaces, and why it exists."""
    return render_template(
        "station_pkce.html",
        token=token_state(),
        trace=(session.get("traces") or {}).get("pkce"),
        public_client_id=PUBLIC_CLIENT_ID,
        client_id=CLIENT_ID,
    )


@app.route("/refresh")
def refresh():
    """Forces a refresh so the class can watch it happen on demand."""
    if not session.get("refresh_token"):
        return redirect(url_for("index"))

    ok = do_refresh("pulsado a mano")
    return render_template(
        "station_refresh.html",
        token=token_state(),
        trace=(session.get("traces") or {}).get("refresh"),
        ok=ok,
    )


@app.route("/logout-local")
def logout_local():
    """Forgets the local session but leaves the Keycloak SSO session alone.

    Station 2 needs two different logins out of one browser. The full /logout
    also closes the Keycloak session, which is correct hygiene but forces the
    student to retype credentials for the second login. This one is the quick
    path: it is NOT a real logout and the page says so, because from the user's
    point of view they will still appear logged in at Keycloak.
    """
    session.pop("access_token", None)
    session.pop("refresh_token", None)
    session.pop("id_token", None)
    return redirect(url_for("station_jwt"))


@app.route("/logout")
def logout():
    id_token = session.get("id_token")

    # The claim history lives in _claim_history, keyed by an id held in the
    # session, so session.clear() no longer wipes it. That matters for station 2:
    # the only way to get two different logins out of one browser is to log out in
    # between, and a blanket clear() made the diff impossible to show along the
    # natural sequence of the class.
    session.clear()

    if id_token:
        post_logout_redirect_uri = BASE_URL
        logout_url = (
            f"{LOGOUT_ENDPOINT}?id_token_hint={id_token}"
            f"&post_logout_redirect_uri={post_logout_redirect_uri}"
        )
        logger.debug("Redirecting to Keycloak logout")
        return redirect(logout_url)

    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(
        debug=flask_config.get("debug", True),
        port=flask_config.get("port", 9090),
        host=flask_config.get("host", "0.0.0.0"),  # noqa: S104
    )
