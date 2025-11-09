# AuthLab - Flask + Keycloak OpenID Connect

Sample Flask application that implements authentication and authorization using Keycloak with the OpenID Connect (OIDC) protocol.

## Features

- ✅ Authentication with Keycloak using OpenID Connect
- ✅ Token management (access, refresh, id tokens)
- ✅ Automatic renewal of expired tokens
- ✅ Access to protected resources
- ✅ Complete logout (local session + Keycloak SSO session)
- ✅ Configuration via JSON file

## Requirements

- Python 3.13+
- Keycloak (installed and configured)
- Flask
- Requests

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
pip install flask requests
```

3. **Configure the application**
```bash
cp config.json.example config.json
```

Edit `config.json` with your values:

```json
{
  "keycloak": {
    "url": "http://192.168.1.76:8080/realms/YourRealm",
    "client_id": "your-client-id",
    "client_secret": "your-client-secret"
  },
  "flask": {
    "debug": true,
    "port": 9090,
    "host": "0.0.0.0",
    "secret_key": null,
    "base_url": "http://192.168.1.76:9090"
  },
  "oauth": {
    "scope": "openid profile email"
  }
}
```

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
     - `http://192.168.1.76:9090/callback`
     - `http://localhost:9090/callback`
   - **Valid Post Logout Redirect URIs**:
     - `http://192.168.1.76:9090`
     - `http://localhost:9090`
   - **Web Origins**: `+` (allows all valid origins)

4. In the **Credentials** tab:
   - Copy the **Client Secret** and put it in `config.json`

### 3. Create a Test User

1. Go to **Users** > **Add user**
2. Assign a username
3. In the **Credentials** tab, set a password

## Usage

### Start the application

```bash
python main.py
```

The application will be available at `http://192.168.1.76:9090` (or your configured URL).

### Available routes

| Route | Description |
|------|-------------|
| `/` | Home page |
| `/login` | Starts authentication flow with Keycloak |
| `/callback` | OAuth2 callback (handles authorization code) |
| `/protected` | Protected resource that requires authentication |
| `/logout` | Logs out from Flask and Keycloak |

## Authentication Flow

1. **Login**: User clicks "Login"
   - Redirects to Keycloak
   - User enters credentials
   - Keycloak returns authorization code

2. **Callback**: Application receives the code
   - Exchanges code for tokens (access, refresh, id)
   - Saves tokens in Flask session

3. **Access Protected Resources**
   - Uses access token in `Authorization: Bearer <token>` header
   - If token expires, attempts to renew it with refresh token
   - If renewal fails, requests re-authentication

4. **Logout**
   - Clears Flask local session
   - Redirects to Keycloak logout endpoint with `id_token_hint`
   - Keycloak closes SSO session
   - Redirects back to the application

## Project Structure

```
authlab/
├── main.py                 # Main Flask application
├── config.json            # Configuration (not versioned)
├── config.json.example    # Configuration template
├── pyproject.toml         # Project dependencies
├── uv.lock               # uv lock file
├── .gitignore            # Files ignored by git
└── README.md             # This file
```

## Detailed Configuration

### config.json

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

## Security

⚠️ **Important:**

- **DO NOT** upload `config.json` to the repository (already in `.gitignore`)
- Use environment variables in production for sensitive data
- Configure `secret_key` with a fixed value in production
- Use HTTPS in production
- Always validate received tokens

## Troubleshooting

### "Invalid redirect uri"
- Verify that URIs in Keycloak exactly match `base_url` in config.json
- Check for no extra spaces or trailing slashes

### "Token not found" at /protected
- Make sure you're authenticated first by visiting `/login`
- Verify that Flask session is working

### Session doesn't close in Keycloak
- Verify that `base_url` is configured correctly
- Ensure "Valid Post Logout Redirect URIs" is configured in Keycloak

### Error loading config.json
- Verify the file exists and has valid JSON format
- Copy `config.json.example` and rename it to `config.json`

## Development

### Run in debug mode
```bash
python main.py
```

### Change port
Modify `flask.port` in `config.json`.

### View Keycloak logs
In the admin console: **Realm Settings** > **Events**

## License

This is an educational example project. Use it freely.

## Resources

- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [OpenID Connect Specification](https://openid.net/connect/)
- [Flask Documentation](https://flask.palletsprojects.com/)
