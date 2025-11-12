# AuthLab - Flask + Keycloak OpenID Connect

Sample Flask application that implements authentication and authorization using Keycloak with the OpenID Connect (OIDC) protocol.

## Features

- ✅ Authentication with Keycloak using OpenID Connect
- ✅ Token management (access, refresh, id tokens)
- ✅ Automatic renewal of expired tokens
- ✅ Access to protected resources
- ✅ Separate resource server architecture
- ✅ Complete logout (local session + Keycloak SSO session)
- ✅ Configuration via YAML file

## Requirements

- Python 3.13+
- Keycloak (installed and configured)
- Flask 3.1.2+
- Requests 2.32.5+
- PyJWT 2.10.1+
- Cryptography 46.0.3+
- PyYAML 6.0.2+

## Installation

1. **Clone the repository**
```bash
git clone <your-repository>
cd authlab
```

2. **Install dependencies**
```bash
# With uv (recommended)
uv sync

# Or with pip
pip install flask>=3.1.2 requests>=2.32.5 pyjwt>=2.10.1 cryptography>=46.0.3 pyyaml>=6.0.2
```

3. **Configure the application**
```bash
cp config.yaml.example config.yaml
```

Edit `config.yaml` with your values:

```yaml
keycloak:
  url: "http://keycloak:8080/realms/<your-realm-name>"
  client_id: "<client-id>"
  client_secret: "<client-secret>"

flask:
  debug: true
  port: 9090
  host: "0.0.0.0"
  secret_key: null
  base_url: "http://localhost:9090"

oauth:
  scope: "openid profile email"

resource_server:
  debug: true
  port: 9091
  host: "0.0.0.0"
  url: "http://resource-server:9091"
```

## Keycloak Setup

### Starting a Test Keycloak Server

To start a Keycloak test server using Docker:

```bash
docker run -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  --name keycloak \
  quay.io/keycloak/keycloak:latest start-dev
```

This will start Keycloak in development mode with:
- Admin username: `admin`
- Admin password: `admin`
- Admin console: `http://localhost:8080/admin`

⚠️ **Note**: This is for development/testing only. Do not use in production.

## Keycloak Configuration

### 1. Create a Realm
In the Keycloak admin console, create a new realm (e.g., "Laboratory").

### 2. Create a Client

1. Go to **Clients** > **Create client**
2. Configure the following values:
   - **Client ID**: `flask-client` (or your preferred name)
   - **Client Protocol**: `openid-connect`
   - **Access Type**: `confidential`

3. In the **Settings** tab:
   - **Valid Redirect URIs**: 
     - `http://<client-ip>:9090/callback`
     - `http://localhost:9090/callback`
   - **Valid Post Logout Redirect URIs**:
     - `http://<client-ip>:9090`
     - `http://localhost:9090`
   - **Web Origins**: `*` (allows all valid origins)

4. In Keys tab:
   - Configure a RSA key pair

5. In the **Credentials** tab:
   - Copy the **Client Secret** and put it in `config.yaml`

### 3. Create a Test User

1. Go to **Users** > **Add user**
2. Assign a username
3. In the **Credentials** tab, set a password

## Usage

### Start the servers

This application uses a two-server architecture to simulate a realistic OAuth2/OpenID Connect scenario:

1. **Start the Resource Server** (handles protected resources):
```bash
python resource_server.py
```

The resource server will be available at `http://localhost:9091`.

2. **Start the Main Application** (handles authentication):
```bash
python main.py
```

The main application will be available at `http://localhost:9090`.

### Available routes

#### Main Application (port 9090)

| Route | Description |
|------|-------------|
| `/` | Home page |
| `/login` | Starts authentication flow with Keycloak |
| `/callback` | OAuth2 callback (handles authorization code) |
| `/protected` | Forwards requests to resource server with access token |
| `/logout` | Logs out from Flask and Keycloak |

#### Resource Server (port 9091)

| Route | Description |
|------|-------------|
| `/api/protected-resource` | Protected endpoint requiring valid Bearer token |
| `/health` | Health check endpoint |

## Authentication Flow

1. **Login**: User clicks "Login"
   - Redirects to Keycloak
   - User enters credentials
   - Keycloak returns authorization code

2. **Callback**: Application receives the code
   - Exchanges code for tokens (access, refresh, id)
   - Saves tokens in Flask session

3. **Access Protected Resources**
   - Main application forwards request to resource server with access token
   - Resource server validates the token
   - If token expires, main application attempts to renew it with refresh token
   - If renewal fails, requests re-authentication
   - Resource server retrieves user info from Keycloak and returns protected data

4. **Logout**
   - Clears Flask local session
   - Redirects to Keycloak logout endpoint with `id_token_hint`
   - Keycloak closes SSO session
   - Redirects back to the application

## Project Structure

```
authlab/
├── main.py                 # Main Flask application (authentication server)
├── resource_server.py      # Resource server (protected resources)
├── config.yaml            # Configuration (not versioned)
├── config.yaml.example    # Configuration template
├── pyproject.toml         # Project dependencies
├── uv.lock               # uv lock file
├── Dockerfile            # Docker image for main app
├── Dockerfile.resource   # Docker image for resource server
├── docker-compose.yml    # Docker Compose configuration
├── .gitignore            # Files ignored by git
├── .dockerignore         # Files ignored by Docker
└── README.md             # This file
```

## Architecture

This project demonstrates a realistic OAuth2/OpenID Connect architecture with separate servers:

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│   Browser   │◄───────►│ Main App     │◄───────►│  Keycloak   │
│             │         │ (port 9090)  │         │  (IdP)      │
└─────────────┘         └──────────────┘         └─────────────┘
                              │
                              │ HTTP + Bearer Token
                              ▼
                        ┌──────────────┐         ┌─────────────┐
                        │  Resource    │◄───────►│  Keycloak   │
                        │  Server      │         │  (Verify)   │
                        │ (port 9091)  │         └─────────────┘
                        └──────────────┘
```

1. **Main Application** (main.py):
   - Handles user authentication with Keycloak
   - Manages OAuth2 authorization code flow
   - Stores and renews access tokens
   - Forwards authenticated requests to resource server

2. **Resource Server** (resource_server.py):
   - Validates access tokens independently
   - Serves protected resources
   - Verifies token signature using Keycloak's public keys (JWKS)

## Detailed Configuration

### config.yaml

#### `keycloak` section
- **url**: Complete URL of the Keycloak realm
- **client_id**: Client ID configured in Keycloak
- **client_secret**: Client secret (confidential)

#### `flask` section
- **debug**: Flask debug mode (true/false)
- **port**: Port where the application runs
- **host**: Application host (`0.0.0.0` for external access)
- **secret_key**: Secret key for sessions (null = auto-generated)
- **base_url**: Complete base URL of your application (must match Keycloak)

#### `oauth` section
- **scope**: Requested OpenID Connect scopes

#### `resource_server` section
- **debug**: Resource server debug mode (true/false)
- **port**: Port where the resource server runs
- **host**: Resource server host (`0.0.0.0` for external access)
- **url**: Complete URL of the resource server for internal communication

## Security

⚠️ **Important:**

- **DO NOT** upload `config.yaml` to the repository (already in `.gitignore`)
- Use environment variables in production for sensitive data
- Configure `secret_key` with a fixed value in production
- Use HTTPS in production
- Always validate received tokens

## Troubleshooting

### "Invalid redirect uri"
- Verify that URIs in Keycloak exactly match `base_url` in config.yaml
- Check for no extra spaces or trailing slashes

### "Token not found" at /protected
- Make sure you're authenticated first by visiting `/login`
- Verify that Flask session is working

### "Failed to connect to resource server"
- Ensure the resource server is running on port 9091
- Check that `resource_server.url` in config.yaml is correct
- Verify both servers can communicate (firewall settings)

### Session doesn't close in Keycloak
- Verify that `base_url` is configured correctly
- Ensure "Valid Post Logout Redirect URIs" is configured in Keycloak

### Error loading config.yaml
- Verify the file exists and has valid YAML format
- Copy `config.yaml.example` and rename it to `config.yaml`
- Check for proper indentation (YAML is sensitive to spaces)

## Development

### Run in debug mode
```bash
# Terminal 1 - Resource Server
python resource_server.py

# Terminal 2 - Main Application
python main.py
```

### Change ports
- Main application: Modify `flask.port` in `config.yaml`
- Resource server: Modify `resource_server.port` in `config.yaml`

### View Keycloak logs
In the admin console: **Realm Settings** > **Events**

## License

This is an educational example project. Use it freely.

## Resources

- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [OpenID Connect Specification](https://openid.net/connect/)
- [Flask Documentation](https://flask.palletsprojects.com/)
