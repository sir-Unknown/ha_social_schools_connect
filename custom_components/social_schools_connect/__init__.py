"""The Social Schools Connect integration."""

from __future__ import annotations

from typing import Final

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import SocialSchoolsClient
from .const import CONF_PASSWORD, CONF_REFRESH_TOKEN, CONF_USERNAME, DOMAIN

PLATFORMS: Final[list[Platform]] = [Platform.SENSOR]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Social Schools Connect from a config entry."""

    session = async_get_clientsession(hass)
    data = entry.data

    client = SocialSchoolsClient(
        session,
        username=data.get(CONF_USERNAME),
        password=data.get(CONF_PASSWORD),
        refresh_token=data.get(CONF_REFRESH_TOKEN),
    )

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = client

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok and DOMAIN in hass.data:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unload_ok
