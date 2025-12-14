"""Data update coordinator for the Social Schools Connect integration."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import timedelta
import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import AuthError, LoginError, SocialSchoolsClient, TokenError
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

    def __init__(
        self, hass: HomeAssistant, client: SocialSchoolsClient, entry: ConfigEntry
    ) -> None:
        """Initialize the coordinator."""
        self._entry = entry
        self._client = client

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
        except (AuthError, LoginError) as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except TokenError as err:
            raise UpdateFailed("Error communicating with API") from err

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
