"""Sensor platform for the Social Schools Connect integration."""

from __future__ import annotations

from datetime import timedelta
import logging
from typing import Any

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
)

from .api import SocialSchoolsClient
from .const import DEFAULT_SCAN_INTERVAL, DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Social Schools Connect sensors from a config entry."""
    client: SocialSchoolsClient = hass.data[DOMAIN][entry.entry_id]

    async def _async_update_user() -> dict[str, Any]:
        """Fetch the current user details."""
        return await client.async_get_current_user()

    async def _async_update_posts() -> dict[str, Any]:
        """Fetch the latest community posts."""
        return await client.async_get_latest_community_posts(
            offset=0,
            limit=10,
            filter_type=0,
        )

    user_coordinator = DataUpdateCoordinator(
        hass,
        _LOGGER,
        name="Social Schools user",
        update_method=_async_update_user,
        update_interval=timedelta(seconds=DEFAULT_SCAN_INTERVAL),
        config_entry=entry,
    )

    posts_coordinator = DataUpdateCoordinator(
        hass,
        _LOGGER,
        name="Social Schools community posts",
        update_method=_async_update_posts,
        update_interval=timedelta(seconds=DEFAULT_SCAN_INTERVAL),
        config_entry=entry,
    )

    await user_coordinator.async_config_entry_first_refresh()
    await posts_coordinator.async_config_entry_first_refresh()

    async_add_entities(
        [
            SocialSchoolsUserSensor(user_coordinator, entry),
            SocialSchoolsPostsSensor(posts_coordinator, entry),
        ]
    )


class SocialSchoolsUserSensor(CoordinatorEntity, SensorEntity):
    """Represent the currently logged-in Social Schools user."""

    _attr_has_entity_name = True
    _attr_icon = "mdi:account-school"

    def __init__(self, coordinator: DataUpdateCoordinator, entry: ConfigEntry) -> None:
        """Initialize the user sensor."""
        super().__init__(coordinator)
        self._attr_unique_id = f"{entry.entry_id}_user"
        self._attr_name = "Social Schools user"

    @property
    def native_value(self) -> str | None:
        """Return the current user display name."""
        data = self.coordinator.data or {}
        return data.get("displayName") or data.get("username")

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional user attributes."""
        data = self.coordinator.data or {}
        return {
            "email": data.get("email"),
            "roles": data.get("roles"),
        }


class SocialSchoolsPostsSensor(CoordinatorEntity, SensorEntity):
    """Represent the latest Social Schools community posts."""

    _attr_has_entity_name = True
    _attr_icon = "mdi:message-text"

    def __init__(self, coordinator: DataUpdateCoordinator, entry: ConfigEntry) -> None:
        """Initialize the posts sensor."""
        super().__init__(coordinator)
        self._attr_unique_id = f"{entry.entry_id}_community_posts"
        self._attr_name = "Social Schools posts"

    @property
    def native_value(self) -> int | None:
        """Return the total number of posts."""
        data = self.coordinator.data or {}
        return data.get("totalCount")

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional details about the latest posts."""
        data = self.coordinator.data or {}
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
