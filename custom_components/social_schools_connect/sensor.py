"""Sensor platform for the Social Schools Connect integration."""

from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import SensorEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceEntryType, DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import SocialSchoolsConfigEntry
from .const import DOMAIN
from .coordinator import SocialSchoolsCoordinator


async def async_setup_entry(
    hass: HomeAssistant,
    entry: SocialSchoolsConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Social Schools Connect sensors from a config entry."""
    coordinator = entry.runtime_data.coordinator

    async_add_entities(
        [
            SocialSchoolsUserSensor(coordinator, entry),
            SocialSchoolsPostsSensor(coordinator, entry),
        ]
    )


class SocialSchoolsEntity(CoordinatorEntity[SocialSchoolsCoordinator]):
    """Base entity for Social Schools Connect."""

    _attr_has_entity_name = True

    def __init__(
        self, coordinator: SocialSchoolsCoordinator, entry: SocialSchoolsConfigEntry
    ) -> None:
        """Initialize the entity."""
        super().__init__(coordinator)
        identifier = entry.unique_id or entry.entry_id
        self._attr_device_info = DeviceInfo(
            entry_type=DeviceEntryType.SERVICE,
            identifiers={(DOMAIN, identifier)},
            manufacturer="Social Schools",
            name=entry.title,
        )


class SocialSchoolsUserSensor(SocialSchoolsEntity, SensorEntity):
    """Represent the currently logged-in Social Schools user."""

    _attr_icon = "mdi:account-school"
    _attr_name = None
    _attr_translation_key = "user"

    def __init__(
        self, coordinator: SocialSchoolsCoordinator, entry: SocialSchoolsConfigEntry
    ) -> None:
        """Initialize the user sensor."""
        super().__init__(coordinator, entry)
        self._attr_unique_id = f"{entry.entry_id}_user"

    @property
    def native_value(self) -> str | None:
        """Return the current user display name."""
        data = self.coordinator.data.user if self.coordinator.data else {}
        return data.get("displayName") or data.get("username")

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional user attributes."""
        data = self.coordinator.data.user if self.coordinator.data else {}
        return {
            "email": data.get("email"),
            "roles": data.get("roles"),
        }


class SocialSchoolsPostsSensor(SocialSchoolsEntity, SensorEntity):
    """Represent the latest Social Schools community posts."""

    _attr_icon = "mdi:message-text"
    _attr_name = None
    _attr_translation_key = "community_posts"

    def __init__(
        self, coordinator: SocialSchoolsCoordinator, entry: SocialSchoolsConfigEntry
    ) -> None:
        """Initialize the posts sensor."""
        super().__init__(coordinator, entry)
        self._attr_unique_id = f"{entry.entry_id}_community_posts"

    @property
    def native_value(self) -> int | None:
        """Return the total number of posts."""
        data = self.coordinator.data.posts if self.coordinator.data else {}
        return data.get("totalCount")

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional details about the latest posts."""
        data = self.coordinator.data.posts if self.coordinator.data else {}
        values = data.get("values") or []

        attrs: dict[str, Any] = {
            "totalCount": data.get("totalCount"),
        }

        if values:
            latest = values[0]
            attrs["latest_id"] = latest.get("id")
            attrs["latest_title"] = latest.get("title")
            attrs["latest_created"] = latest.get("created")
            attrs["latest_body"] = (latest.get("body") or "")[:500]
            attrs["latest_community"] = (
                (latest.get("communities") or [{}])[0].get("name")
                if latest.get("communities")
                else None
            )
            attrs["latest_author"] = (latest.get("author") or {}).get("displayName")

        # Provide a compact list of posts for templates and automations.
        attrs["posts"] = [
            {
                "id": v.get("id"),
                "title": v.get("title"),
                "created": v.get("created"),
                "community": (v.get("communities") or [{}])[0].get("name")
                if v.get("communities")
                else None,
                "author": (v.get("author") or {}).get("displayName"),
            }
            for v in values
        ]

        return attrs
