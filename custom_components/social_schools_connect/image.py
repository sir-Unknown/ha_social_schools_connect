"""Image platform for the Social Schools Connect integration."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from aiohttp import ClientTimeout

from homeassistant.components.image import ImageEntity
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import SocialSchoolsConfigEntry
from .const import DOMAIN, REQUEST_TIMEOUT
from .coordinator import SocialSchoolsCoordinator

_IMAGE_TIMEOUT = ClientTimeout(total=REQUEST_TIMEOUT)


def _logo_url(user: dict[str, Any]) -> str | None:
    role = ((user.get("roles") or [{}])[0]) or {}
    school = role.get("school") or {}
    return (school.get("theme") or {}).get("logo")


async def async_setup_entry(
    hass: HomeAssistant,
    entry: SocialSchoolsConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up image entities from a config entry."""
    async_add_entities([SocialSchoolsLogoImage(entry)])


class SocialSchoolsLogoImage(CoordinatorEntity[SocialSchoolsCoordinator], ImageEntity):
    """Image entity for the school logo."""

    _attr_has_entity_name = True
    _attr_translation_key = "logo"

    def __init__(self, entry: SocialSchoolsConfigEntry) -> None:
        """Initialize the image entity."""
        coordinator = entry.runtime_data.coordinator
        super().__init__(coordinator)
        ImageEntity.__init__(self, coordinator.hass)
        self._attr_unique_id = f"{entry.entry_id}_school_logo"
        self._attr_device_info = DeviceInfo(identifiers={(DOMAIN, entry.entry_id)})

    @property
    def available(self) -> bool:  # type: ignore[override]
        """Return if entity is available."""
        return self.coordinator.last_update_success

    async def async_added_to_hass(self) -> None:
        """Register coordinator listener and activate image proxy endpoint."""
        await super().async_added_to_hass()
        if self._attr_image_last_updated is None:
            self._attr_image_last_updated = datetime.now(UTC)
            self.async_write_ha_state()

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        self.async_write_ha_state()

    async def async_image(self) -> bytes | None:
        """Fetch the current logo image bytes."""
        if self.coordinator.data is None:
            return None
        url = _logo_url(self.coordinator.data.user)
        if not url:
            return None
        session = async_get_clientsession(self.hass)
        async with session.get(url, timeout=_IMAGE_TIMEOUT) as resp:
            if resp.status == 200:
                self._attr_content_type = resp.content_type or "image/jpeg"
                return await resp.read()
        return None
