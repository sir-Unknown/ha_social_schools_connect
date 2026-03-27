"""The Social Schools Connect integration."""

from __future__ import annotations

from dataclasses import dataclass

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.typing import ConfigType

from .client import SocialSchoolsClient
from .const import CONF_REFRESH_TOKEN
from .coordinator import SocialSchoolsCoordinator
from .services import async_setup_services


@dataclass(slots=True)
class SocialSchoolsRuntimeData:
    """Runtime data for Social Schools Connect."""

    coordinator: SocialSchoolsCoordinator


type SocialSchoolsConfigEntry = ConfigEntry[SocialSchoolsRuntimeData]

PLATFORMS: list[Platform] = [Platform.CALENDAR, Platform.IMAGE, Platform.SENSOR]


async def async_setup(hass: HomeAssistant, _config: ConfigType) -> bool:
    """Set up Social Schools Connect."""
    async_setup_services(hass)
    return True


async def async_setup_entry(
    hass: HomeAssistant, entry: SocialSchoolsConfigEntry
) -> bool:
    """Set up Social Schools Connect from a config entry."""

    session = async_get_clientsession(hass)

    client = SocialSchoolsClient(
        session,
        refresh_token=entry.data.get(CONF_REFRESH_TOKEN),
    )

    coordinator = SocialSchoolsCoordinator(hass, client, entry)
    await coordinator.async_config_entry_first_refresh()

    entry.runtime_data = SocialSchoolsRuntimeData(coordinator=coordinator)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


async def async_unload_entry(
    hass: HomeAssistant, entry: SocialSchoolsConfigEntry
) -> bool:
    """Unload a config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
