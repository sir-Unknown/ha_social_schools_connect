"""API client for the Social Schools Connect integration."""

from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass
import hashlib
import logging
import secrets
from typing import Any
from urllib.parse import parse_qs, urlsplit

from aiohttp import ClientError, ClientSession, ContentTypeError
from bs4 import BeautifulSoup
from bs4.element import Tag

from .const import (
    API_BASE,
    AUTHORIZATION_ENDPOINT,
    CLIENT_ID,
    COMMUNITY_POSTS_PATH,
    CURRENT_USER_PATH,
    OAUTH_BASE,
    REDIRECT_URI,
    SCOPE,
    TOKEN_ENDPOINT,
)

_LOGGER = logging.getLogger(__name__)


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


def _safe_url(value: str) -> str:
    """Return URL without query/fragment for logging."""
    split = urlsplit(value)
    return split._replace(query="", fragment="").geturl()


def _parse_code_from_url(url: str) -> tuple[str | None, str | None]:
    """Parse authorization code and state from an URL."""
    qs = parse_qs(urlsplit(url).query)
    code_list = qs.get("code")
    returned_state_list = qs.get("state")
    return (code_list[0] if code_list else None), (
        returned_state_list[0] if returned_state_list else None
    )


def _extract_error_text(html: str) -> str | None:
    """Extract a human-readable error message from HTML, if present."""
    soup = BeautifulSoup(html, "html.parser")

    for selector in (
        ".validation-summary-errors",
        ".validation-summary-valid",
        ".alert.alert-danger",
        ".alert-danger",
        ".error",
    ):
        el = soup.select_one(selector)
        if isinstance(el, Tag):
            text = " ".join(el.stripped_strings)
            if text:
                return text

    title = soup.find("title")
    if isinstance(title, Tag):
        title_text = " ".join(title.stripped_strings)
        if title_text:
            return title_text

    header = soup.find(["h1", "h2"])
    if isinstance(header, Tag):
        header_text = " ".join(header.stripped_strings)
        if header_text:
            return header_text

    return None


def _absolute_oauth_url(path_or_url: str) -> str:
    """Return an absolute URL for a relative OAuth path."""
    if path_or_url.startswith(("http://", "https://")):
        return path_or_url
    if path_or_url.startswith("/"):
        return f"{OAUTH_BASE}{path_or_url}"
    return f"{OAUTH_BASE}/{path_or_url.lstrip('/')}"


@dataclass(slots=True)
class Tokens:
    """OAuth2 tokens returned by the login flow."""

    access_token: str
    refresh_token: str | None
    expires_in: int


# Minimal headers for the login flow.
LOGIN_HEADERS = {
    "User-Agent": "Home Assistant Social Schools Connect",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
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
                    detail: str | None = None
                    try:
                        error_payload = await resp.json(content_type=None)
                    except (ContentTypeError, TypeError, ValueError):
                        error_payload = None
                    if isinstance(error_payload, dict):
                        detail = error_payload.get("error_description") or error_payload.get(
                            "error"
                        )

                    if resp.status in (400, 401):
                        raise AuthError(
                            f"Token endpoint returned {resp.status}"
                            + (f": {detail}" if detail else "")
                        )
                    raise TokenError(
                        f"Token endpoint returned {resp.status}"
                        + (f": {detail}" if detail else "")
                    )
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

    def _raise_on_home_error(self, url: str, html: str) -> None:
        """Raise LoginError if the OAuth server returned an error page."""
        if urlsplit(url).path != "/home/error":
            return
        if (error_text := _extract_error_text(html)) is not None:
            raise LoginError(error_text)
        raise LoginError("Authorization flow ended at /home/error")

    async def _async_exchange_code(self, code: str, code_verifier: str) -> Tokens:
        """Exchange authorization code for access/refresh token."""
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

    async def _async_start_authorize_flow(
        self, auth_params: dict[str, str]
    ) -> tuple[str, str]:
        """Start authorize flow and return final URL + HTML."""
        try:
            async with self._session.get(
                AUTHORIZATION_ENDPOINT,
                params=auth_params,
                headers=LOGIN_HEADERS,
                allow_redirects=True,
            ) as resp:
                if resp.status != 200:
                    raise LoginError(f"Failed to start authorize flow: {resp.status}")

                final_authorize_url = str(resp.url)
                if resp.history:
                    _LOGGER.debug(
                        "Authorize redirect chain: %s",
                        " -> ".join(_safe_url(str(h.url)) for h in resp.history),
                    )
                html = await resp.text()
        except ClientError as err:
            raise LoginError("Error starting authorize flow") from err

        _LOGGER.debug("Authorize flow ended at %s", _safe_url(final_authorize_url))
        self._raise_on_home_error(final_authorize_url, html)
        return final_authorize_url, html

    async def _async_submit_login_form(
        self, login_page_url: str, return_url: str, html: str
    ) -> tuple[str, str | None]:
        """Submit the login form and return final URL + optional HTML."""
        assert self._username is not None
        assert self._password is not None

        soup = BeautifulSoup(html, "html.parser")

        payload: dict[str, str] = {"ReturnUrl": return_url}
        action_url = f"{OAUTH_BASE}/Account/Login"
        login_params: dict[str, str] | None = {"ReturnUrl": return_url}

        form: Tag | None = None
        for candidate in soup.find_all("form"):
            if candidate.find("input", {"type": "password"}):
                form = candidate
                break

        if form is not None:
            action = form.get("action")
            if isinstance(action, str) and action:
                action_url = _absolute_oauth_url(action)

            # If the form action already contains `ReturnUrl=...`, do not add
            # another query parameter copy via aiohttp `params=...`.
            if "ReturnUrl=" in urlsplit(action_url).query:
                login_params = None

            for input_tag in form.find_all("input"):
                if not isinstance(input_tag, Tag):
                    continue
                name = input_tag.get("name")
                if not isinstance(name, str) or not name:
                    continue
                input_type = input_tag.get("type", "text")
                value = input_tag.get("value")

                if input_type == "hidden" and isinstance(value, str):
                    payload.setdefault(name, value)

                if name.lower() == "returnurl":
                    payload[name] = return_url

                if input_type in ("text", "email") and "username" in name.lower():
                    payload[name] = self._username

                if input_type == "password" and "password" in name.lower():
                    payload[name] = self._password

            button = form.find("button", {"name": True, "value": True})
            if isinstance(button, Tag):
                button_name = button.get("name")
                button_value = button.get("value")
                if isinstance(button_name, str) and isinstance(button_value, str):
                    payload.setdefault(button_name, button_value)

            submit_input = form.find(
                "input",
                {"type": "submit", "name": True, "value": True},
            )
            if isinstance(submit_input, Tag):
                submit_name = submit_input.get("name")
                submit_value = submit_input.get("value")
                if isinstance(submit_name, str) and isinstance(submit_value, str):
                    payload.setdefault(submit_name, submit_value)

        # Fallback for older markup if we did not detect field names.
        payload.setdefault("Username", self._username)
        payload.setdefault("Password", self._password)
        payload.setdefault("button", "login")

        _LOGGER.debug("Submitting login form to %s", _safe_url(action_url))

        try:
            async with self._session.post(
                action_url,
                params=login_params,
                data=payload,
                headers={
                    **LOGIN_HEADERS,
                    "Referer": login_page_url,
                },
                allow_redirects=True,
            ) as resp2:
                final_url = str(resp2.url)
                if resp2.history:
                    _LOGGER.debug(
                        "Login redirect chain: %s",
                        " -> ".join(_safe_url(str(h.url)) for h in resp2.history),
                    )
                post_html: str | None = None
                if "code=" not in final_url:
                    post_html = await resp2.text()
        except ClientError as err:
            raise LoginError("Error posting the login form") from err

        _LOGGER.debug("Login redirect ended at %s", _safe_url(final_url))
        return final_url, post_html

    async def _async_follow_authorize_callback(
        self, login_page_url: str, return_url: str
    ) -> tuple[str, str]:
        """Follow the authorize callback after login and return final URL + HTML."""
        try:
            authorize_callback_url = _absolute_oauth_url(return_url)
            async with self._session.get(
                authorize_callback_url,
                headers={**LOGIN_HEADERS, "Referer": login_page_url},
                allow_redirects=True,
            ) as resp3:
                callback_url = str(resp3.url)
                if resp3.history:
                    _LOGGER.debug(
                        "Authorize callback redirect chain: %s",
                        " -> ".join(_safe_url(str(h.url)) for h in resp3.history),
                    )
                callback_html = await resp3.text()
        except ClientError as err:
            raise LoginError("Error following authorize callback after login") from err

        _LOGGER.debug("Authorize callback ended at %s", _safe_url(callback_url))
        self._raise_on_home_error(callback_url, callback_html)
        return callback_url, callback_html

    async def _async_login_with_credentials(self) -> Tokens:
        """Perform a full OAuth2 + PKCE login with username and password."""
        if not self._username or not self._password:
            raise LoginError("Missing username/password for login")

        code_verifier = secrets.token_urlsafe(64)
        code_challenge = _pkce_challenge(code_verifier)
        state = secrets.token_urlsafe(16)

        # 1. Start the OAuth2 authorize flow (like a browser) and follow redirects
        # to the login page. This ensures any required cookies / context are set
        # by the server, instead of constructing a ReturnUrl ourselves.
        auth_params = {
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

        final_authorize_url, authorize_html = await self._async_start_authorize_flow(
            auth_params
        )

        # If the session is already authorized, the flow can land directly on the
        # redirect_uri and include the authorization code.
        code, returned_state = _parse_code_from_url(final_authorize_url)
        if code is not None:
            if returned_state != state:
                raise LoginError("State mismatch during login")
            return await self._async_exchange_code(code, code_verifier)

        # 2. Build login payload based on the discovered form fields.
        # Social Schools occasionally changes input names, so derive them from HTML.
        login_page_url = final_authorize_url
        login_qs = parse_qs(urlsplit(login_page_url).query)
        return_url = (login_qs.get("ReturnUrl") or [None])[0]
        if not return_url:
            raise LoginError("Authorize flow did not provide ReturnUrl for login")

        final_url, post_html = await self._async_submit_login_form(
            login_page_url, return_url, authorize_html
        )
        code, returned_state = _parse_code_from_url(final_url)

        if not code:
            # Some flows only redirect to the authorize callback after the login
            # POST has completed (browser navigation). Mimic that by explicitly
            # performing a GET to the ReturnUrl when needed.
            callback_url, _callback_html = await self._async_follow_authorize_callback(
                login_page_url,
                return_url,
            )
            code, returned_state = _parse_code_from_url(callback_url)

            if post_html:
                if (error_text := _extract_error_text(post_html)) is not None:
                    _LOGGER.debug("Login error page: %s", error_text)
                    raise LoginError(error_text)
            raise LoginError(
                f"No authorization code found in redirect URL (ended at {_safe_url(final_url)})"
            )

        if returned_state != state:
            raise LoginError("State mismatch during login")

        # 3. Exchange code for tokens.
        return await self._async_exchange_code(code, code_verifier)

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
