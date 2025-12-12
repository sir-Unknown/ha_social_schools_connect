from __future__ import annotations

DOMAIN = "social_schools_connect"

CONF_USERNAME = "username"
CONF_PASSWORD = "password"
CONF_REFRESH_TOKEN = "refresh_token"
CONF_USER_ID = "user_id"
CONF_DISPLAY_NAME = "display_name"

OAUTH_BASE = "https://login.socialschools.eu"
AUTHORIZATION_ENDPOINT = f"{OAUTH_BASE}/connect/authorize"
TOKEN_ENDPOINT = f"{OAUTH_BASE}/connect/token"

CLIENT_ID = "eu.socialschools.webapp"
REDIRECT_URI = "https://app.socialschools.eu/callback.html"
# offline_access zodat je een refresh_token kunt krijgen
SCOPE = "openid SocsWebApi"

API_BASE = "https://api.socialschools.eu"
CURRENT_USER_PATH = "/api/v1/useraccounts/current"
COMMUNITY_POSTS_PATH = "/api/v1/communityposts"

DEFAULT_SCAN_INTERVAL = 300  # seconden
