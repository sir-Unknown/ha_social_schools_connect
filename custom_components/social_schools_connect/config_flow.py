"""Config flow for the Social Schools Connect integration."""

from __future__ import annotations

import logging
from typing import Any, Self

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry, ConfigFlow, ConfigFlowResult
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import AuthError, LoginError, SocialSchoolsClient, TokenError
from .const import CONF_PASSWORD, CONF_REFRESH_TOKEN, CONF_USERNAME, DOMAIN

_LOGGER = logging.getLogger(__name__)


class SocialSchoolsConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Social Schools Connect."""

    VERSION = 1
    MINOR_VERSION = 1

    def is_matching(self, other_flow: Self) -> bool:
        """Return True if other_flow is matching this flow."""
        return False

    def __init__(self) -> None:
        """Initialize the config flow."""
        self._reauth_entry: ConfigEntry | None = None

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            session = async_get_clientsession(self.hass)
            client = SocialSchoolsClient(
                session,
                username=user_input[CONF_USERNAME],
                password=user_input[CONF_PASSWORD],
            )

            try:
                user = await client.async_get_current_user()
            except (AuthError, LoginError) as err:
                _LOGGER.debug("Login failed: %s", err)
                errors["base"] = "invalid_auth"
            except TokenError as err:
                _LOGGER.debug("Token error during login: %s", err)
                errors["base"] = "cannot_connect"
            except Exception:  # pylint: disable=broad-except  # safety net
                _LOGGER.exception("Unexpected error during login")
                errors["base"] = "unknown"
            else:
                user_id = (
                    user.get("userProfileId")
                    or user.get("username")
                    or user_input[CONF_USERNAME]
                )
                display_name = (
                    user.get("displayName")
                    or user.get("username")
                    or user.get("email")
                    or str(user_id)
                )

                await self.async_set_unique_id(str(user_id))
                self._abort_if_unique_id_configured()

                refresh_token = client.refresh_token
                if not refresh_token:
                    _LOGGER.debug("Login succeeded but no refresh token was returned")
                    errors["base"] = "unknown"
                else:
                    entry_data: dict[str, str] = {CONF_REFRESH_TOKEN: refresh_token}

                    return self.async_create_entry(
                        title=display_name,
                        data=entry_data,
                    )

        data_schema = vol.Schema(
            {
                vol.Required(CONF_USERNAME): str,
                vol.Required(CONF_PASSWORD): str,
            }
        )

        return self.async_show_form(
            step_id="user",
            data_schema=data_schema,
            errors=errors,
        )

    async def async_step_reauth(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle a reauthentication request."""
        entry_id = self.context.get("entry_id")
        if entry_id is None:
            return self.async_abort(reason="unknown_entry")
        if not (entry := self.hass.config_entries.async_get_entry(entry_id)):
            return self.async_abort(reason="unknown_entry")

        self._reauth_entry = entry
        return await self.async_step_reauth_confirm(user_input)

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Confirm reauth to refresh stored tokens."""
        assert self._reauth_entry is not None
        errors: dict[str, str] = {}

        if user_input is not None:
            session = async_get_clientsession(self.hass)
            client = SocialSchoolsClient(
                session,
                username=user_input[CONF_USERNAME],
                password=user_input[CONF_PASSWORD],
            )

            try:
                user = await client.async_get_current_user()
            except (AuthError, LoginError) as err:
                _LOGGER.debug("Login failed: %s", err)
                errors["base"] = "invalid_auth"
            except TokenError as err:
                _LOGGER.debug("Token error during login: %s", err)
                errors["base"] = "cannot_connect"
            except Exception:  # pylint: disable=broad-except  # safety net
                _LOGGER.exception("Unexpected error during login")
                errors["base"] = "unknown"
            else:
                user_id = (
                    user.get("userProfileId")
                    or user.get("username")
                    or user_input[CONF_USERNAME]
                )
                if (
                    self._reauth_entry.unique_id
                    and str(user_id) != self._reauth_entry.unique_id
                ):
                    return self.async_abort(reason="wrong_account")

                refresh_token = client.refresh_token
                if not refresh_token:
                    _LOGGER.debug("Login succeeded but no refresh token was returned")
                    errors["base"] = "unknown"
                else:
                    return self.async_update_reload_and_abort(
                        self._reauth_entry,
                        data={CONF_REFRESH_TOKEN: refresh_token},
                    )

        data_schema = vol.Schema(
            {
                vol.Required(CONF_USERNAME): str,
                vol.Required(CONF_PASSWORD): str,
            }
        )

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=data_schema,
            errors=errors,
        )
