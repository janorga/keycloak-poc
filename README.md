# AuthLab — OAuth2 + OIDC classroom demo

A self-contained teaching lab for a 50–60 minute class on the **concepts** behind
OAuth2 and OpenID Connect: why the flow has four legs, what is actually inside a
JWT, why OAuth2 alone is not login, and why *authenticated* is not the same as
*authorized*.

Everything starts with one command. No manual configuration in the Keycloak Admin
Console — the realm is imported from `realm/lab-realm.json.template` on first
boot (resolved into `.generated/` at startup, see below).

```bash
./start.sh
```

Then open <http://localhost:9090>.

---

## What is in the box

| Path | What it is |
|---|---|
| `docker-compose.yml` | Keycloak 26.7.5 (pinned by digest), the Flask app, the resource server |
| `realm/lab-realm.json.template` | The entire realm: 3 clients, 2 users, roles, scopes, mappers |
| `config_compose.yaml.template` | Config for the compose stack. Demo secret, published on purpose |
| `main.py` | The client app. One route per station |
| `resource_server.py` | The API. Verifies the signature, authorizes on realm roles |
| `templates/` | The projected screens |
| `docs/guion-clase.md` | Minute-by-minute instructor script |
| `docs/guion-alumno.md` | Student exercises with answers |
| `start.sh` / `reset.sh` | Boot / wipe-and-reimport |

## Credentials

| User | Password | Realm roles | Expected |
|---|---|---|---|
| `ana` | `ana` | `admin`, `user` | `/api/user-only` 200, `/api/admin-only` 200 |
| `luis` | `luis` | `user` | `/api/user-only` 200, `/api/admin-only` 403 |

Keycloak admin console: <http://localhost:8080/admin> (`admin` / `admin`).
No station requires clicking inside it.

## The stations

| Route | Idea |
|---|---|
| `/station/flow` | The four legs of the authorization code flow, with your own URLs |
| `/station/jwt` | The three JWT parts, a claims table, and the diff against your previous login |
| `/station/not-login` | The same request without `openid`: no `id_token`, and `/userinfo` refuses |
| `/station/roles` | `ana` vs `luis` on the same endpoint: 200 vs 403, and the claim that decides |
| `/station/pkce` | Bonus: how a public client replaces a secret it cannot keep |

The access token deliberately lives **60 seconds**, so the refresh token can be
demonstrated live: wait, click again, and the page says it renewed on its own.

## Serving it from somewhere other than this machine

For a VM, a shared machine, or anything where the browser address is not
`localhost`, set `AUTHLAB_HOST` to the host the browser will actually use:

```bash
AUTLAB_HOST=192.168.1.50 ./start.sh    # by IP
AUTLAB_HOST=mi-vm.lan ./start.sh       # by DNS name or VM hostname
./start.sh                             # no variable -> localhost
```

It is a **bare host**: no scheme, no port, no path. The ports (8080, 9090) are
added by the compose file. `start.sh` rejects `http://vm:8080`, `0.0.0.0` and
`::` with an explanation, and warns (without failing) if a name does not resolve,
since a bare IP never resolves by design.

The variable is resolved into two files under `.generated/` at startup, and the
compose file mounts those instead of the templates:

| Template | Resolved to | Placeholders |
|---|---|---|
| `config_compose.yaml.template` | `.generated/config.yaml` | `public_url`, `base_url` |
| `realm/lab-realm.json.template` | `.generated/realm/lab-realm.json` | 8 redirect URIs |

Both stay host-agnostic in git, so no IP is ever committed. Only
`keycloak.public_url` and `flask.base_url` change;
`keycloak.internal_url` stays `http://keycloak:8080/...` because that is the
container-to-container name, and the browser cannot resolve it. That asymmetry is
what station 1 is about.

### Changing the host with the stack already running

`start.sh` compares the requested host against `.authlab-host.last` and, if it
changed, wipes Keycloak's data and reimports. It has to: `--import-realm` only
imports when the realm does **not** already exist (strategy `IGNORE_EXISTING`),
and this stack keeps its data inside the container, so a realm imported under a
previous host would keep its old redirect URIs and every login would fail with
`Invalid parameter: redirect_uri`. When it does this it says so out loud.

Starting again with the *same* host does not rebuild anything.

Two things `start.sh` does to keep a bad host from reaching a classroom:

- It recreates the containers. `.generated/config.yaml` is a bind-mounted **file**,
  and those are cached by the kernel: rewriting the file on disk does not change
  what a running container reads, so without `--force-recreate` the app keeps
  serving the previous config.
- It checks the issuer Keycloak actually emits against the host you asked for,
  and warns if they differ. A mismatch enters fine and then fails 60 seconds
  later on refresh with `Invalid token issuer`, which looks like an app bug.

## Running without Docker

```bash
cp config.yaml.example config.yaml   # then fill in the values
uv sync
uv run python main.py                 # :9090
uv run python resource_server.py      # :9091
```

`config.yaml` needs `keycloak.internal_url` (server-to-server) and
`keycloak.public_url` (browser-reachable) to be set separately — see below.

---

## Three things that will waste your afternoon if nobody told you

### 0. The session cookie is a 4 KB ceiling

Flask stores the session in a cookie, and browsers drop cookies above roughly
4093 bytes. Nothing errors: Werkzeug logs a warning and the session silently
vanishes, so the app looks like it is randomly logging people out between page
loads. Two things used to do it here, and both had to be fixed for station 2 to
work at all:

- the token endpoint response was stored verbatim, and one response carries three
  JWTs of roughly 2 KB each. `summarize_token_response()` now replaces each token
  with a `<JWT n chars>` marker;
- the claim history for the station 2 diff lives in a server-side dict
  (`_claim_history`) keyed by a small id kept in the session, instead of in the
  cookie.

If a page renders "no session" when you are clearly logged in, check
`docker compose logs main-app` for `cookie is too large`.

### 1. `internal_url` vs `public_url`

The compose file runs Keycloak as a service called `keycloak`. That name resolves
**only inside the Docker network**.

- `keycloak.internal_url` → container to container (`main-app`, `resource-server`).
- `keycloak.public_url` → browser to container. This is what goes into
  `redirect_uri` and into the address bar.

Build the browser redirect from `internal_url` and the login breaks with a DNS
error in the browser while every container keeps working perfectly. The server
looks healthy, which is exactly what makes it confusing.

### 2. Keycloak's health endpoint needs two things, not one

The obvious healthcheck is wrong twice over:

```yaml
# WRONG, and it fails in two different ways
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8080/health/ready"]
```

- Since 26.x the health endpoints live on the **management port 9000**, not 8080.
- The Keycloak image is UBI-micro based and **ships without `curl`**, so
  `exec: "curl": executable file not found` and the probe never runs at all.

The real healthcheck uses bash's `/dev/tcp`. With this broken, nothing that has
`depends_on: {condition: service_healthy}` ever starts — which is the failure this
repo originally had.

---

## The demo secret

`config_compose.yaml.template` contains a client secret in plain text, and that is
intentional. It is published, documented, and used only by a lab that runs on a
laptop. Leaking a secret into a repository is a better classroom moment than
hypothetical advice about it.

The old config had a real secret and a hard-coded LAN IP. Both are gone.

## Resetting

```bash
./reset.sh        # asks for confirmation
./reset.sh -y     # skips it
```

The `-v` is not optional. Without it, the Keycloak volume survives, the `lab`
realm already exists, and `--import-realm` uses the `IGNORE_EXISTING` strategy:
it imports nothing, and the script would claim to have reset the state when
nothing actually changed.

**It deletes every realm in the volume**, including any created by hand.

## Offline

Images are already local, so a cold `docker compose up -d` needs no network. A
**rebuild** does (`uv sync` hits PyPI), so `start.sh` falls back to the existing
images if the build fails.

Base images: `quay.io/keycloak/keycloak` pinned to
`sha256:37dbaf6f0722c9ec246335f36e1ef8b2e6cb960f7c27e0d8c615121a3d475a85`
(26.7.5), `python:3.13-slim`, `ghcr.io/astral-sh/uv:0.5.29`.

## Requirements

- Docker with Compose v2
- Python 3.13+ (only for running without Docker)
- Keycloak 26.7.5 is bundled in the compose file; nothing to install
