"""API client for the Social Schools Connect integration."""

from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass
import hashlib
import secrets
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

from aiohttp import ClientError, ClientSession
from bs4 import BeautifulSoup
from bs4.element import Tag

from .const import (
    API_BASE,
    CLIENT_ID,
    COMMUNITY_POSTS_PATH,
    CURRENT_USER_PATH,
    OAUTH_BASE,
    REDIRECT_URI,
    SCOPE,
    TOKEN_ENDPOINT,
)


class LoginError(Exception):
    """Error during login."""


class TokenError(Exception):
    """Error during token handling."""


class AuthError(TokenError):
    """Error while authenticating with Social Schools."""


def _pkce_challenge(verifier: str) -> str:
    """Return the PKCE challenge derived from a verifier."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


@dataclass(slots=True)
class Tokens:
    """OAuth2 tokens returned by the login flow."""

    access_token: str
    refresh_token: str | None
    expires_in: int


# Headers that resemble a real browser.
BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8,"
        "application/signed-exchange;v=b3;q=0.7"
    ),
    "Accept-Language": "nl-NL,nl;q=0.9,en-US;q=0.8,en;q=0.7",
    "Cache-Control": "no-cache",
}


class SocialSchoolsClient:
    """Client that handles Social Schools login + API calls."""

    def __init__(
        self,
        session: ClientSession,
        *,
        username: str | None = None,
        password: str | None = None,
        refresh_token: str | None = None,
    ) -> None:
        """Initialize the client."""
        self._session = session
        self._username = username
        self._password = password

        self._token_lock = asyncio.Lock()
        self._access_token: str | None = None
        self._refresh_token: str | None = refresh_token
        self._expires_at: float = 0.0

        self._current_user: dict[str, Any] | None = None
        self._role_type_id: int | None = None
        self._school_id: int | None = None

    @property
    def refresh_token(self) -> str | None:
        """Return the refresh token, if available."""
        return self._refresh_token

    async def _async_post_tokens(self, data: dict[str, str]) -> Tokens:
        """Call the token endpoint and return parsed tokens."""
        try:
            async with self._session.post(
                TOKEN_ENDPOINT,
                data=data,
                headers={"Accept": "application/json"},
            ) as resp:
                if resp.status != 200:
                    if resp.status in (400, 401):
                        raise AuthError(f"Token endpoint returned {resp.status}")
                    raise TokenError(f"Token endpoint returned {resp.status}")
                payload = await resp.json()
        except ClientError as err:
            raise TokenError("Error communicating with token endpoint") from err

        access_token = payload["access_token"]
        refresh_token = payload.get("refresh_token")
        expires_in = int(payload.get("expires_in", 3600))
        return Tokens(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=expires_in,
        )

    async def _async_login_with_credentials(self) -> Tokens:
        """Perform a full OAuth2 + PKCE login with username and password."""
        if not self._username or not self._password:
            raise LoginError("Missing username/password for login")

        code_verifier = secrets.token_urlsafe(64)
        code_challenge = _pkce_challenge(code_verifier)
        state = secrets.token_urlsafe(16)

        # Build ReturnUrl as the web app does.
        auth_query = urlencode(
            {
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "response_type": "code",
                "scope": SCOPE,
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "response_mode": "query",
                "prompt": "login",
                "suppressed_prompt": "login",
            }
        )
        return_url = f"/connect/authorize/callback?{auth_query}"

        login_params = {"ReturnUrl": return_url}

        # 1. Fetch the login page with the CSRF token.
        try:
            async with self._session.get(
                f"{OAUTH_BASE}/Account/Login",
                params=login_params,
                headers=BROWSER_HEADERS,
                allow_redirects=True,
            ) as resp:
                if resp.status != 200:
                    raise LoginError(f"Failed to load login page: {resp.status}")
                html = await resp.text()
        except ClientError as err:
            raise LoginError("Error loading the login page") from err

        soup = BeautifulSoup(html, "html.parser")
        token_el = soup.find("input", {"name": "__RequestVerificationToken"})
        csrf_token = token_el.get("value") if isinstance(token_el, Tag) else None
        if not csrf_token:
            raise LoginError("Could not find csrf token in login page")

        # 2. Post username and password with the CSRF token.
        data = {
            "ReturnUrl": return_url,
            "Username": self._username,
            "Password": self._password,
            "button": "login",
            "__RequestVerificationToken": csrf_token,
        }

        try:
            async with self._session.post(
                f"{OAUTH_BASE}/Account/Login",
                params=login_params,
                data=data,
                headers=BROWSER_HEADERS,
                allow_redirects=True,
            ) as resp2:
                final_url = str(resp2.url)
        except ClientError as err:
            raise LoginError("Error posting the login form") from err

        qs = parse_qs(urlsplit(final_url).query)
        code_list = qs.get("code")
        returned_state_list = qs.get("state")

        code = code_list[0] if code_list else None
        returned_state = returned_state_list[0] if returned_state_list else None

        if not code:
            raise LoginError(
                "No authorization code found in redirect URL (bad credentials or flow)"
            )

        if returned_state != state:
            raise LoginError("State mismatch during login")

        # 3. Exchange code for tokens.
        token_data = {
            "grant_type": "authorization_code",
            "redirect_uri": REDIRECT_URI,
            "code": code,
            "code_verifier": code_verifier,
            "client_id": CLIENT_ID,
        }

        tokens = await self._async_post_tokens(token_data)
        self._access_token = tokens.access_token
        self._refresh_token = tokens.refresh_token
        self._expires_at = asyncio.get_running_loop().time() + tokens.expires_in - 30
        return tokens

    async def _async_refresh(self) -> Tokens:
        """Refresh access token using refresh_token."""
        if not self._refresh_token:
            raise AuthError("No refresh token available")

        data = {
            "grant_type": "refresh_token",
            "refresh_token": self._refresh_token,
            "client_id": CLIENT_ID,
        }

        tokens = await self._async_post_tokens(data)
        self._access_token = tokens.access_token
        self._refresh_token = tokens.refresh_token or self._refresh_token
        self._expires_at = asyncio.get_running_loop().time() + tokens.expires_in - 30
        return Tokens(
            access_token=tokens.access_token,
            refresh_token=self._refresh_token,
            expires_in=tokens.expires_in,
        )

    async def _ensure_token(self) -> None:
        """Ensure there is a valid access token."""
        loop = asyncio.get_running_loop()

        if self._access_token and loop.time() < self._expires_at:
            return

        async with self._token_lock:
            loop = asyncio.get_running_loop()
            if self._access_token and loop.time() < self._expires_at:
                return

            if self._refresh_token:
                try:
                    await self._async_refresh()
                except AuthError:
                    self._access_token = None
                    self._expires_at = 0.0
                else:
                    return

            if not self._username or not self._password:
                raise AuthError("No credentials available for login")

            await self._async_login_with_credentials()

    async def _async_get_json(
        self,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
    ) -> Any:
        """Perform an authenticated GET request against the Social Schools API."""
        await self._ensure_token()
        assert self._access_token is not None

        request_headers = {
            "Authorization": f"Bearer {self._access_token}",
            "Accept": "application/json",
        }
        if headers:
            request_headers.update(headers)

        url = f"{API_BASE}{path}"
        try:
            async with self._session.get(
                url, headers=request_headers, params=params
            ) as resp:
                if resp.status in (401, 403):
                    raise AuthError(f"API returned {resp.status}")
                if resp.status != 200:
                    raise TokenError(f"API returned {resp.status}")
                return await resp.json()
        except ClientError as err:
            raise TokenError("Error communicating with the Social Schools API") from err

    async def async_get(self, path: str) -> Any:
        """Perform an authenticated GET request."""
        return await self._async_get_json(path)

    async def async_get_current_user(self) -> dict[str, Any]:
        """Fetch the current user and cache the main role/school identifiers."""
        data = await self.async_get(CURRENT_USER_PATH)
        self._current_user = data

        roles = data.get("roles") or []
        if roles:
            main_role = roles[0]
            role_type = main_role.get("type")
            try:
                self._role_type_id = int(role_type) if role_type is not None else None
            except (TypeError, ValueError):
                self._role_type_id = None

            school_id = (main_role.get("school") or {}).get("id")
            try:
                self._school_id = int(school_id) if school_id is not None else None
            except (TypeError, ValueError):
                self._school_id = None

        return data

    async def async_get_community_posts(
        self,
        role_type_id: int,
        school_id: int,
        offset: int = 0,
        limit: int = 10,
        filter_type: int = 0,
    ) -> dict[str, Any]:
        """Fetch posts from the community endpoint."""
        headers = {"roletypeid": str(role_type_id), "schoolid": str(school_id)}
        params = {
            "offset": str(offset),
            "limit": str(limit),
            "filterType": str(filter_type),
        }
        return await self._async_get_json(
            COMMUNITY_POSTS_PATH, headers=headers, params=params
        )

    async def async_get_latest_community_posts(
        self,
        offset: int = 0,
        limit: int = 10,
        filter_type: int = 0,
    ) -> dict[str, Any]:
        """Fetch posts using the cached role and school identifiers."""
        if self._role_type_id is None or self._school_id is None:
            await self.async_get_current_user()

        if self._role_type_id is None or self._school_id is None:
            raise TokenError(
                "Cannot determine role_type_id and school_id for communityposts"
            )

        return await self.async_get_community_posts(
            self._role_type_id,
            self._school_id,
            offset=offset,
            limit=limit,
            filter_type=filter_type,
        )
