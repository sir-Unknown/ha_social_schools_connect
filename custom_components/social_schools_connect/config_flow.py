"""Config flow for the Social Schools Connect integration."""

from __future__ import annotations

import logging
from typing import Any

import aiohttp
import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult

from .auth import AuthError, LoginError, TokenError
from .client import SocialSchoolsClient
from .const import (
    CONF_PASSWORD,
    CONF_REFRESH_TOKEN,
    CONF_USERNAME,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

_LOGIN_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
    }
)


def _user_id(user: dict[str, Any], username: str) -> str:
    """Derive a stable unique identifier from the user payload."""
    return str(user.get("userProfileId") or user.get("username") or username)


class SocialSchoolsConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Social Schools Connect."""

    VERSION = 1
    MINOR_VERSION = 1

    def is_matching(self, other_flow: ConfigFlow) -> bool:
        """Return True if other_flow is matching this flow.

        Returning False here allows multiple setup flows to be in progress at
        the same time (e.g. two different accounts).  Duplicate entries are
        still prevented by async_set_unique_id + _abort_if_unique_id_configured
        once the user successfully logs in.
        """
        return False

    async def _async_try_login(
        self, user_input: dict[str, Any]
    ) -> tuple[dict[str, Any], str | None, str | None]:
        """Attempt login and return (user_data, refresh_token, error_key).

        Uses a dedicated session with an isolated cookie jar so that OAuth
        session cookies and CSRF tokens are not shared with the rest of HA.
        """
        login_session = aiohttp.ClientSession(
            cookie_jar=aiohttp.CookieJar(unsafe=True),
        )
        try:
            client = SocialSchoolsClient(login_session)
            try:
                _LOGGER.debug("Starting credential login for %s", user_input[CONF_USERNAME])
                await client.async_login(user_input[CONF_USERNAME], user_input[CONF_PASSWORD])
                user = await client.async_get_current_user()
                _LOGGER.debug("Successfully fetched current user after login")
            except (AuthError, LoginError) as err:
                _LOGGER.debug("Login failed: %s", err)
                return {}, None, "invalid_auth"
            except TokenError as err:
                _LOGGER.debug("Token error during login: %s", err)
                return {}, None, "cannot_connect"
            except Exception:  # pylint: disable=broad-except  # safety net
                _LOGGER.exception("Unexpected error during login")
                return {}, None, "unknown"
            if not client.refresh_token:
                _LOGGER.warning("Login succeeded but server returned no refresh token")
                return {}, None, "cannot_connect"
            return user, client.refresh_token, None
        finally:
            await login_session.close()

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            user, refresh_token, error_key = await self._async_try_login(user_input)
            if error_key:
                errors["base"] = error_key
            else:
                user_id = _user_id(user, user_input[CONF_USERNAME])
                roles = user.get("roles") or []
                school_name = (
                    ((roles[0].get("school") or {}).get("displayName") or "").strip()
                    if roles else ""
                )
                display_name = (
                    school_name
                    or (user.get("displayName") or "").strip()
                    or user.get("username")
                    or user_id
                )

                await self.async_set_unique_id(user_id)
                self._abort_if_unique_id_configured()

                return self.async_create_entry(
                    title=display_name,
                    data={CONF_REFRESH_TOKEN: refresh_token},
                )

        return self.async_show_form(
            step_id="user",
            data_schema=_LOGIN_SCHEMA,
            errors=errors,
        )

    async def async_step_reauth(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle a reauthentication request."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Confirm reauth to refresh stored tokens."""
        errors: dict[str, str] = {}

        if user_input is not None:
            user, refresh_token, error_key = await self._async_try_login(user_input)
            if error_key:
                errors["base"] = error_key
            else:
                user_id = _user_id(user, user_input[CONF_USERNAME])
                await self.async_set_unique_id(user_id)
                self._abort_if_unique_id_mismatch(reason="wrong_account")

                return self.async_update_reload_and_abort(
                    self._get_reauth_entry(),
                    data_updates={CONF_REFRESH_TOKEN: refresh_token},
                )

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=_LOGIN_SCHEMA,
            errors=errors,
        )
