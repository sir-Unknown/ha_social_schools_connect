"""Data update coordinator for the Social Schools Connect integration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import logging
from typing import Any, Awaitable, Literal, TypeVar

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, HomeAssistantError
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .auth import AuthError, TokenError
from .client import SocialSchoolsClient
from .const import (
    CONF_REFRESH_TOKEN,
    DEFAULT_SCAN_INTERVAL,
    EVENT_LOOKAHEAD_DAYS,
)

_LOGGER = logging.getLogger(__name__)
_T = TypeVar("_T")


def parse_event_datetime(value: str | None) -> datetime | None:
    """Parse a Social Schools UTC timestamp into a timezone-aware datetime."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


@dataclass(slots=True)
class SocialSchoolsData:
    """Coordinator data for Social Schools Connect."""

    user: dict[str, Any]
    next_event: dict[str, Any] | None
    next_leave_report: dict[str, Any] | None


class SocialSchoolsCoordinator(DataUpdateCoordinator[SocialSchoolsData]):
    """Coordinator for Social Schools Connect."""

    def __init__(
        self, hass: HomeAssistant, client: SocialSchoolsClient, entry: ConfigEntry
    ) -> None:
        """Initialize the coordinator."""
        self._client = client
        self._entry = entry

        super().__init__(
            hass,
            _LOGGER,
            name="Social Schools Connect",
            update_interval=timedelta(seconds=DEFAULT_SCAN_INTERVAL),
            config_entry=entry,
        )

    def _select_next_event(
        self, events: list[dict[str, Any]], *, now: datetime
    ) -> dict[str, Any] | None:
        """Return the active or next upcoming event from a normalized event list."""
        dated_events: list[tuple[datetime, dict[str, Any]]] = []
        for event in events:
            end_value = parse_event_datetime(event.get("end"))
            start_value = parse_event_datetime(event.get("start"))
            if end_value is None or start_value is None or end_value < now:
                continue
            dated_events.append((start_value, event))

        if not dated_events:
            return None

        dated_events.sort(key=lambda item: item[0])
        return dated_events[0][1]

    def _select_next_leave_report(
        self, leave_reports: list[dict[str, Any]], *, now: datetime
    ) -> dict[str, Any] | None:
        """Return the active or next upcoming leave report from a normalized list."""
        dated_reports: list[tuple[datetime, dict[str, Any]]] = []
        for report in leave_reports:
            end_value = parse_event_datetime(report.get("end"))
            start_value = parse_event_datetime(report.get("start"))
            if end_value is None or start_value is None or end_value < now:
                continue
            dated_reports.append((start_value, report))

        if not dated_reports:
            return None

        dated_reports.sort(key=lambda item: item[0])
        return dated_reports[0][1]

    async def _async_call_service_api(self, awaitable: Awaitable[_T]) -> _T:
        """Run service-facing API calls with consistent HA error conversion."""
        try:
            return await awaitable
        except TokenError as err:
            _LOGGER.debug("Service API error: %s", err)
            raise HomeAssistantError("Error communicating with Social Schools") from err

    async def _async_fetch_leave_reports(
        self, *, user: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Fetch leave reports directly from the client (raises raw TokenError/AuthError)."""
        leave_reports: list[dict[str, Any]] = []
        for connection in ((user.get("roles") or [{}])[0] or {}).get(
            "connections", []
        ):
            student_id = connection.get("id")
            if student_id is None:
                continue
            student_name = (
                (connection.get("firstName") or "").strip()
                or (connection.get("displayName") or "").strip()
                or str(student_id)
            )
            reports = await self._client.async_get_leave_reports(int(student_id))
            for report in reports:
                leave_reports.append(
                    {
                        **report,
                        "studentId": student_id,
                        "studentName": student_name,
                    }
                )

        return leave_reports

    async def _async_update_data(self) -> SocialSchoolsData:
        """Fetch the latest data from Social Schools."""
        now = datetime.now(UTC)
        try:
            user = await self._client.async_get_current_user()
            next_events = await self._client.async_get_events(
                start_date=now,
                end_date=now + timedelta(days=EVENT_LOOKAHEAD_DAYS),
            )
            leave_reports = await self._async_fetch_leave_reports(user=user)
        except AuthError as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except TokenError as err:
            raise UpdateFailed("Error communicating with API") from err

        refresh_token = self._client.refresh_token
        if refresh_token and self._entry.data.get(CONF_REFRESH_TOKEN) != refresh_token:
            self.hass.config_entries.async_update_entry(
                self._entry,
                data={**self._entry.data, CONF_REFRESH_TOKEN: refresh_token},
            )

        return SocialSchoolsData(
            user=user,
            next_event=self._select_next_event(next_events, now=now),
            next_leave_report=self._select_next_leave_report(leave_reports, now=now),
        )

    async def async_get_posts(
        self,
        *,
        mode: Literal["latest", "search", "post"],
        post_id: int | None = None,
        q: str | None = None,
        community_id: int | None = None,
        include_media: bool = False,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Get posts in latest/search/post mode."""
        return await self._async_call_service_api(
            self._client.async_get_posts(
                mode=mode,
                post_id=post_id,
                q=q,
                community_id=community_id,
                include_media=include_media,
                limit=limit,
            )
        )

    async def async_get_events(
        self, *, start_date: datetime, end_date: datetime
    ) -> list[dict[str, Any]]:
        """Get calendar events within the requested datetime range."""
        return await self._async_call_service_api(
            self._client.async_get_events(start_date=start_date, end_date=end_date)
        )

    async def async_get_leave_reports(
        self, *, user: dict[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        """Get leave reports for all known students."""
        user_data = user or self.data.user
        return await self._async_call_service_api(
            self._async_fetch_leave_reports(user=user_data)
        )
