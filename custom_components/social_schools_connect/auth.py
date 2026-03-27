"""Authentication helpers for the Social Schools Connect integration."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import re
import secrets
from urllib.parse import parse_qs, urlsplit

from aiohttp import (
    ClientError,
    ClientSession,
    ClientTimeout,
    ContentTypeError,
    NonHttpUrlRedirectClientError,
)

from .const import (
    AUTHORIZATION_ENDPOINT,
    CLIENT_ID,
    OAUTH_BASE,
    REDIRECT_URI,
    REQUEST_TIMEOUT,
    SCOPE,
    TOKEN_ENDPOINT,
    USER_AGENT,
)

_LOGGER = logging.getLogger(__name__)
_OAUTH_NETLOC = urlsplit(OAUTH_BASE).netloc
_REQUEST_TIMEOUT = ClientTimeout(total=REQUEST_TIMEOUT)
_LOGIN_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


class LoginError(Exception):
    """Error during login."""


class TokenError(Exception):
    """Error during token handling."""


class AuthError(TokenError):
    """Error while authenticating with Social Schools."""


class ForbiddenError(AuthError):
    """API returned 403 Forbidden; may be resolved by sending role/school context headers."""


def _safe_url(value: str) -> str:
    """Return URL without query or fragment for logging."""
    split = urlsplit(value)
    return split._replace(query="", fragment="").geturl()


def _parse_code_from_url(url: str) -> tuple[str | None, str | None]:
    """Parse authorization code and state from a URL."""
    qs = parse_qs(urlsplit(url).query)
    return qs.get("code", [None])[0], qs.get("state", [None])[0]


def _absolute_oauth_url(path_or_url: str) -> str:
    """Return an absolute URL for a relative OAuth path."""
    if path_or_url.startswith(("http://", "https://")):
        return path_or_url
    return f"{OAUTH_BASE}/{path_or_url.lstrip('/')}"


class SocialSchoolsAuth:
    """Handle OAuth login and token refresh for Social Schools."""

    def __init__(
        self,
        session: ClientSession,
        *,
        refresh_token: str | None = None,
    ) -> None:
        """Initialize the auth helper."""
        self._session = session
        self._refresh_token = refresh_token
        self._token_lock = asyncio.Lock()
        self._access_token: str | None = None
        self._expires_at: float = 0.0

    @property
    def refresh_token(self) -> str | None:
        """Return the current refresh token, if available."""
        return self._refresh_token

    async def _async_post_tokens(self, data: dict[str, str]) -> tuple[str, str | None, int]:
        """Call the token endpoint and return (access_token, refresh_token, expires_in)."""
        try:
            async with self._session.post(
                TOKEN_ENDPOINT,
                data=data,
                headers={"Accept": "application/json"},
                timeout=_REQUEST_TIMEOUT,
            ) as resp:
                if resp.status != 200:
                    detail: str | None = None
                    try:
                        error_payload = await resp.json()
                    except (ContentTypeError, TypeError, ValueError):
                        error_payload = None
                    if isinstance(error_payload, dict):
                        detail = error_payload.get("error_description") or error_payload.get("error")
                    msg = f"Token endpoint returned {resp.status}" + (f": {detail}" if detail else "")
                    raise (AuthError if resp.status in (400, 401) else TokenError)(msg)
                payload = await resp.json()
        except ClientError as err:
            raise TokenError("Error communicating with token endpoint") from err
        except TimeoutError as err:
            raise TokenError("Token endpoint timed out") from err

        try:
            access_token = payload["access_token"]
        except (KeyError, TypeError) as err:
            raise TokenError("Token endpoint response missing access_token") from err
        return access_token, payload.get("refresh_token"), int(payload.get("expires_in", 3600))

    def _store_tokens(self, access_token: str, refresh_token: str | None, expires_in: int) -> None:
        """Persist tokens returned by the token endpoint."""
        self._access_token = access_token
        self._refresh_token = refresh_token
        self._expires_at = asyncio.get_running_loop().time() + expires_in - 30

    async def async_login_with_credentials(self, username: str, password: str) -> None:
        """Perform a full OAuth2 PKCE login with username and password."""
        code_verifier = secrets.token_urlsafe(64)
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode("ascii")).digest()
        ).decode("ascii").rstrip("=")
        state = secrets.token_urlsafe(16)

        try:
            async with self._session.get(
                AUTHORIZATION_ENDPOINT,
                params={
                    "client_id": CLIENT_ID,
                    "redirect_uri": REDIRECT_URI,
                    "response_type": "code",
                    "scope": SCOPE,
                    "state": state,
                    "login_hint": username,
                    "code_challenge": code_challenge,
                    "code_challenge_method": "S256",
                    "response_mode": "query",
                    "prompt": "login",
                },
                headers=_LOGIN_HEADERS,
                allow_redirects=True,
                timeout=_REQUEST_TIMEOUT,
            ) as resp:
                if resp.status != 200:
                    raise LoginError(f"Failed to start authorize flow: {resp.status}")
                login_page_url = str(resp.url)
                _split = urlsplit(login_page_url)
                authorize_html = (
                    await resp.text()
                    if _split.path != "/home/error" and not parse_qs(_split.query).get("code")
                    else ""
                )
        except ClientError as err:
            raise LoginError("Error starting authorize flow") from err
        except TimeoutError as err:
            raise LoginError("Authorize flow timed out") from err

        _LOGGER.debug("Authorize flow ended at %s", _safe_url(login_page_url))

        if urlsplit(login_page_url).path == "/home/error":
            raise LoginError("Authorization flow ended at /home/error")

        code, returned_state = _parse_code_from_url(login_page_url)
        if code is not None:
            if returned_state != state:
                raise LoginError("State mismatch during login")
            access_token, refresh_token, expires_in = await self._async_post_tokens({
                "grant_type": "authorization_code",
                "redirect_uri": REDIRECT_URI,
                "code": code,
                "code_verifier": code_verifier,
                "client_id": CLIENT_ID,
            })
            self._store_tokens(access_token, refresh_token, expires_in)
            return

        login_qs = parse_qs(urlsplit(login_page_url).query)
        return_url = login_qs.get("ReturnUrl", [None])[0]
        if not return_url:
            raise LoginError("Authorize flow did not provide ReturnUrl for login")

        csrf_match = re.search(
            r'<input[^>]+name="__RequestVerificationToken"[^>]+value="([^"]*)"'
            r'|<input[^>]+value="([^"]*)"[^>]+name="__RequestVerificationToken"',
            authorize_html,
        )
        csrf_token = (csrf_match.group(1) or csrf_match.group(2)) if csrf_match else None

        payload: dict[str, str] = {
            "ReturnUrl": return_url,
            "Username": username,
            "Password": password,
            "button": "login",
        }
        if csrf_token:
            payload["__RequestVerificationToken"] = csrf_token

        action_url = f"{OAUTH_BASE}/Account/Login"

        _LOGGER.debug("Submitting login form to %s", _safe_url(action_url))
        try:
            async with self._session.post(
                action_url,
                params={"ReturnUrl": return_url},
                data=payload,
                headers={**_LOGIN_HEADERS, "Origin": OAUTH_BASE, "Referer": login_page_url},
                allow_redirects=True,
                timeout=_REQUEST_TIMEOUT,
            ) as resp2:
                final_url = str(resp2.url)
        except NonHttpUrlRedirectClientError as err:
            final_url = str(err.args[0])
        except ClientError as err:
            raise LoginError("Error posting the login form") from err
        except TimeoutError as err:
            raise LoginError("Login form submission timed out") from err

        _LOGGER.debug("Login redirect ended at %s", _safe_url(final_url))
        code, returned_state = _parse_code_from_url(final_url)

        if not code:
            callback_url = _absolute_oauth_url(return_url)
            if urlsplit(callback_url).netloc not in ("", _OAUTH_NETLOC):
                raise LoginError(f"Unexpected OAuth callback domain: {urlsplit(callback_url).netloc}")
            try:
                async with self._session.get(
                    callback_url,
                    headers={**_LOGIN_HEADERS, "Referer": login_page_url},
                    allow_redirects=True,
                    timeout=_REQUEST_TIMEOUT,
                ) as resp3:
                    callback_url = str(resp3.url)
            except NonHttpUrlRedirectClientError as err:
                callback_url = str(err.args[0])
            except ClientError as err:
                raise LoginError("Error following authorize callback after login") from err
            except TimeoutError as err:
                raise LoginError("Authorize callback timed out") from err

            _LOGGER.debug("Authorize callback ended at %s", _safe_url(callback_url))
            if urlsplit(callback_url).path == "/home/error":
                raise LoginError("Authorization flow ended at /home/error")
            code, returned_state = _parse_code_from_url(callback_url)

            if not code:
                raise LoginError(
                    f"No authorization code found in redirect URL (ended at {_safe_url(final_url)})"
                )

        if returned_state != state:
            raise LoginError("State mismatch during login")

        access_token, refresh_token, expires_in = await self._async_post_tokens({
            "grant_type": "authorization_code",
            "redirect_uri": REDIRECT_URI,
            "code": code,
            "code_verifier": code_verifier,
            "client_id": CLIENT_ID,
        })
        self._store_tokens(access_token, refresh_token, expires_in)

    async def async_refresh(self) -> None:
        """Refresh the access token using the stored refresh token."""
        if not self._refresh_token:
            raise AuthError("No refresh token available")

        access_token, refresh_token, expires_in = await self._async_post_tokens({
            "grant_type": "refresh_token",
            "refresh_token": self._refresh_token,
            "client_id": CLIENT_ID,
        })
        self._store_tokens(access_token, refresh_token or self._refresh_token, expires_in)

    async def async_ensure_token(self) -> str:
        """Ensure a valid access token exists and return it."""
        if self._access_token and asyncio.get_running_loop().time() < self._expires_at:
            return self._access_token

        async with self._token_lock:
            if self._access_token and asyncio.get_running_loop().time() < self._expires_at:
                return self._access_token

            if not self._refresh_token:
                raise AuthError("No refresh token available")

            await self.async_refresh()
            if self._access_token is None:
                raise TokenError("Token refresh succeeded but access token is not set")
            return self._access_token
