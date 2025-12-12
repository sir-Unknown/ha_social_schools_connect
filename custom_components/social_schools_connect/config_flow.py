from __future__ import annotations

import logging
import voluptuous as vol

from homeassistant import config_entries
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    CONF_DISPLAY_NAME,
    CONF_PASSWORD,
    CONF_REFRESH_TOKEN,
    CONF_USER_ID,
    CONF_USERNAME,
    DOMAIN,
)
from .api import SocialSchoolsClient, LoginError, TokenError

_LOGGER = logging.getLogger(__name__)


class SocialSchoolsConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input=None):
        errors: dict[str, str] = {}

        if user_input is not None:
            session = async_get_clientsession(self.hass)
            client = SocialSchoolsClient(
                session,
                username=user_input[CONF_USERNAME],
                password=user_input[CONF_PASSWORD],
            )

            try:
                _LOGGER.debug("Starting Social Schools login for %s", user_input[CONF_USERNAME])
                user = await client.async_get_current_user()
                _LOGGER.debug("Login OK, current user: %s", user)
            except LoginError as err:
                _LOGGER.exception("LoginError during Social Schools auth: %s", err)
                errors["base"] = "invalid_auth"
            except TokenError as err:
                _LOGGER.exception("TokenError during Social Schools auth: %s", err)
                errors["base"] = "cannot_connect"
            except Exception as err:  # safety net
                _LOGGER.exception("Unexpected error during Social Schools auth: %s", err)
                errors["base"] = "unknown"
            else:
                user_id = user.get("userProfileId") or user.get("username") or user_input[
                    CONF_USERNAME
                ]
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
