"""Sensor platform for the Social Schools Connect integration."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import timedelta
import logging
from typing import Any

from homeassistant.components.sensor import SensorEntity
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
    UpdateFailed,
)

from . import SocialSchoolsConfigEntry
from .api import AuthError, SocialSchoolsClient, TokenError
from .const import (
    CONF_PASSWORD,
    CONF_REFRESH_TOKEN,
    CONF_USERNAME,
    DEFAULT_SCAN_INTERVAL,
)

_LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class SocialSchoolsData:
    """Coordinator data for Social Schools Connect."""

    user: dict[str, Any]
    posts: dict[str, Any]


class SocialSchoolsCoordinator(DataUpdateCoordinator[SocialSchoolsData]):
    """Coordinator for Social Schools Connect."""

    def __init__(self, hass: HomeAssistant, entry: SocialSchoolsConfigEntry) -> None:
        """Initialize the coordinator."""
        self._entry = entry
        self._client: SocialSchoolsClient = entry.runtime_data
        super().__init__(
            hass,
            _LOGGER,
            name="Social Schools Connect",
            update_interval=timedelta(seconds=DEFAULT_SCAN_INTERVAL),
            config_entry=entry,
        )

    async def _async_update_data(self) -> SocialSchoolsData:
        """Fetch the latest data from Social Schools."""
        try:
            user, posts = await asyncio.gather(
                self._client.async_get_current_user(),
                self._client.async_get_latest_community_posts(
                    offset=0,
                    limit=10,
                    filter_type=0,
                ),
            )
        except AuthError as err:
            raise ConfigEntryAuthFailed from err
        except TokenError as err:
            raise UpdateFailed("Error communicating with Social Schools") from err

        refresh_token = self._client.refresh_token
        data = dict(self._entry.data)
        updated = False
        if refresh_token and data.get(CONF_REFRESH_TOKEN) != refresh_token:
            data[CONF_REFRESH_TOKEN] = refresh_token
            updated = True
        if refresh_token:
            if data.pop(CONF_USERNAME, None) is not None:
                updated = True
            if data.pop(CONF_PASSWORD, None) is not None:
                updated = True
        if updated:
            self.hass.config_entries.async_update_entry(self._entry, data=data)

        return SocialSchoolsData(user=user, posts=posts)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: SocialSchoolsConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Social Schools Connect sensors from a config entry."""
    coordinator = SocialSchoolsCoordinator(hass, entry)
    await coordinator.async_config_entry_first_refresh()

    async_add_entities(
        [
            SocialSchoolsUserSensor(coordinator, entry),
            SocialSchoolsPostsSensor(coordinator, entry),
        ]
    )


class SocialSchoolsUserSensor(
    CoordinatorEntity[SocialSchoolsCoordinator], SensorEntity
):
    """Represent the currently logged-in Social Schools user."""

    _attr_has_entity_name = True
    _attr_icon = "mdi:account-school"

    def __init__(
        self, coordinator: SocialSchoolsCoordinator, entry: SocialSchoolsConfigEntry
    ) -> None:
        """Initialize the user sensor."""
        super().__init__(coordinator)
        self._attr_unique_id = f"{entry.entry_id}_user"
        self._attr_name = "Social Schools user"

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


class SocialSchoolsPostsSensor(
    CoordinatorEntity[SocialSchoolsCoordinator], SensorEntity
):
    """Represent the latest Social Schools community posts."""

    _attr_has_entity_name = True
    _attr_icon = "mdi:message-text"

    def __init__(
        self, coordinator: SocialSchoolsCoordinator, entry: SocialSchoolsConfigEntry
    ) -> None:
        """Initialize the posts sensor."""
        super().__init__(coordinator)
        self._attr_unique_id = f"{entry.entry_id}_community_posts"
        self._attr_name = "Social Schools posts"

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
