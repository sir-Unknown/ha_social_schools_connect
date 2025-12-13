"""Config flow for the Social Schools Connect integration."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import LoginError, SocialSchoolsClient, TokenError
from .const import (
    CONF_DISPLAY_NAME,
    CONF_PASSWORD,
    CONF_REFRESH_TOKEN,
    CONF_USER_ID,
    CONF_USERNAME,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)


class SocialSchoolsConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Social Schools Connect."""

    VERSION = 1
    MINOR_VERSION = 1

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
            except LoginError:
                _LOGGER.debug("Login failed")
                errors["base"] = "invalid_auth"
            except TokenError:
                _LOGGER.debug("Token error during login")
                errors["base"] = "cannot_connect"
            except Exception:  # safety net
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

                entry_data: dict[str, str] = {
                    CONF_USER_ID: str(user_id),
                    CONF_DISPLAY_NAME: display_name,
                }

                # Ideaal: alleen refresh_token bewaren
                if client.refresh_token:
                    entry_data[CONF_REFRESH_TOKEN] = client.refresh_token
                else:
                    # Fallback: credentials bewaren
                    entry_data[CONF_USERNAME] = user_input[CONF_USERNAME]
                    entry_data[CONF_PASSWORD] = user_input[CONF_PASSWORD]

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
