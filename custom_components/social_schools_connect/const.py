"""Constants for the Social Schools Connect integration."""

from __future__ import annotations

DOMAIN = "social_schools_connect"

CONF_USERNAME = "username"
CONF_PASSWORD = "password"
CONF_REFRESH_TOKEN = "refresh_token"

OAUTH_BASE = "https://login.socialschools.eu"
AUTHORIZATION_ENDPOINT = f"{OAUTH_BASE}/connect/authorize"
TOKEN_ENDPOINT = f"{OAUTH_BASE}/connect/token"

CLIENT_ID = "eu.socialschools.android"
REDIRECT_URI = "eu.socialschools.android:/callback"
# Match the Android app's published OAuth client settings. The login service
# appears to validate this client quite strictly, so keep scope and user agent
# aligned with the first-party app unless Social Schools changes them.
SCOPE = "SocsWebApi offline_access"
USER_AGENT = "Social Schools Connect Home Assistant Integration"

API_BASE = "https://api.socialschools.eu"
CURRENT_USER_PATH = "/api/v1/useraccounts/current"
COMMUNITY_POSTS_PATH = "/api/v1/communityposts"
EVENTS_PATH = "/api/v1/events"
LEAVE_REPORTS_PATH = "/api/v1/leavereports/student"

DEFAULT_SCAN_INTERVAL = 300  # seconds
EVENT_LOOKAHEAD_DAYS = 30

# Keep login/config-flow requests bounded so Home Assistant does not leave the
# user on an indefinite "starting wizard" spinner when Social Schools stalls.
REQUEST_TIMEOUT = 30  # seconds
