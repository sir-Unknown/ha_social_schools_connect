"""Calendar platform for the Social Schools Connect integration."""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

from homeassistant.components.calendar import CalendarEntity, CalendarEvent
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import SocialSchoolsConfigEntry
from .const import DOMAIN
from .coordinator import SocialSchoolsCoordinator, parse_event_datetime

LEAVE_STATUS_LABELS = {
    1: "concept",
    2: "aangevraagd",
    3: "afgewezen",
    4: "goedgekeurd",
    5: "verwijderd",
    6: "ingetrokken",
}


def _normalize_optional_text(value: Any) -> str | None:
    """Return a stripped string or ``None`` for empty values."""
    if not isinstance(value, str):
        return None

    normalized = value.strip()
    return normalized or None


def _event_to_calendar_event(event: dict[str, Any] | None) -> CalendarEvent | None:
    """Convert a normalized Social Schools event to a Home Assistant event."""
    if event is None:
        return None

    start_value = parse_event_datetime(event.get("start"))
    end_value = parse_event_datetime(event.get("end"))
    if start_value is None or end_value is None:
        return None

    if event.get("all_day"):
        start: datetime | date = start_value.date()
        end: datetime | date = end_value.date()
    else:
        start = start_value
        end = end_value

    community_names = ", ".join(
        community["name"]
        for community in event.get("communities", [])
        if isinstance(community, dict) and community.get("name")
    )

    description = _normalize_optional_text(event.get("description"))
    if community_names:
        description = (
            f"{description}\n\nCommunities: {community_names}"
            if description
            else f"Communities: {community_names}"
        )

    return CalendarEvent(
        summary=_normalize_optional_text(event.get("title")) or "Untitled event",
        start=start,
        end=end,
        description=description,
        location=_normalize_optional_text(event.get("location")),
        uid=str(event["id"]) if event.get("id") is not None else None,
    )


def _leave_report_to_calendar_event(
    leave_report: dict[str, Any] | None,
) -> CalendarEvent | None:
    """Convert a normalized leave report to an all-day calendar event."""
    if leave_report is None:
        return None

    start_value = parse_event_datetime(leave_report.get("start"))
    end_value = parse_event_datetime(leave_report.get("end"))
    if start_value is None or end_value is None:
        return None

    student_name = _normalize_optional_text(leave_report.get("studentName")) or "Leerling"
    status_value = leave_report.get("status")
    status_label = (
        LEAVE_STATUS_LABELS.get(status_value, "onbekend")
        if isinstance(status_value, int)
        else "onbekend"
    )
    explanation = _normalize_optional_text(leave_report.get("explanation")) or "-"
    status_explanation = (
        _normalize_optional_text(leave_report.get("statusExplanation")) or "-"
    )

    return CalendarEvent(
        summary=f"Verlofaanvraag {student_name} ({status_label})",
        start=start_value.date(),
        end=end_value.date(),
        description=f"Aanvraag: {explanation}\nReactie: {status_explanation}",
        uid=str(leave_report["id"]) if leave_report.get("id") is not None else None,
    )


async def async_setup_entry(
    hass: HomeAssistant,
    entry: SocialSchoolsConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up calendar entities from a config entry."""
    async_add_entities(
        [
            SocialSchoolsCalendar(entry),
            SocialSchoolsLeaveRequestsCalendar(entry),
        ]
    )


class _SocialSchoolsBaseCalendar(CoordinatorEntity[SocialSchoolsCoordinator], CalendarEntity):
    """Base calendar entity with resolved available property for Pyright compatibility."""

    _attr_has_entity_name = True

    @property
    def available(self) -> bool:  # type: ignore[override]
        """Return if entity is available."""
        return self.coordinator.last_update_success


class SocialSchoolsCalendar(_SocialSchoolsBaseCalendar):
    """Calendar entity backed by the Social Schools events endpoint."""

    _attr_translation_key = "calendar"

    def __init__(self, entry: SocialSchoolsConfigEntry) -> None:
        """Initialize the calendar entity."""
        super().__init__(entry.runtime_data.coordinator)
        self._attr_unique_id = f"{entry.entry_id}_calendar"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name=entry.title,
        )
        self._update_attrs()

    @property
    def event(self) -> CalendarEvent | None:
        """Return the active or next event for the entity state."""
        coordinator_data = self.coordinator.data
        if coordinator_data is None:
            return None
        return _event_to_calendar_event(coordinator_data.next_event)

    def _update_attrs(self) -> None:
        """Refresh cached attributes from coordinator data."""
        coordinator_data = self.coordinator.data
        if coordinator_data is None or coordinator_data.next_event is None:
            self._attr_extra_state_attributes = {}
            return

        event = coordinator_data.next_event
        self._attr_extra_state_attributes = {
            "event_id": event.get("id"),
            "all_day": event.get("all_day"),
            "type": event.get("type"),
            "communities": event.get("communities", []),
        }

    async def async_get_events(
        self,
        hass: HomeAssistant,
        start_date: datetime,
        end_date: datetime,
    ) -> list[CalendarEvent]:
        """Return calendar events for the requested datetime range."""
        events = await self.coordinator.async_get_events(
            start_date=start_date,
            end_date=end_date,
        )
        return [
            calendar_event
            for event in events
            if (calendar_event := _event_to_calendar_event(event)) is not None
        ]

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        self._update_attrs()
        super()._handle_coordinator_update()


class SocialSchoolsLeaveRequestsCalendar(_SocialSchoolsBaseCalendar):
    """Calendar entity exposing leave requests as all-day events."""

    _attr_translation_key = "leave_requests"

    def __init__(self, entry: SocialSchoolsConfigEntry) -> None:
        """Initialize the leave requests calendar entity."""
        super().__init__(entry.runtime_data.coordinator)
        self._attr_unique_id = f"{entry.entry_id}_leave_requests_calendar"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name=entry.title,
        )
        self._update_attrs()

    @property
    def event(self) -> CalendarEvent | None:
        """Return the active or next leave request for the entity state."""
        coordinator_data = self.coordinator.data
        if coordinator_data is None:
            return None
        return _leave_report_to_calendar_event(coordinator_data.next_leave_report)

    def _update_attrs(self) -> None:
        """Refresh cached attributes from coordinator data."""
        coordinator_data = self.coordinator.data
        if coordinator_data is None or coordinator_data.next_leave_report is None:
            self._attr_extra_state_attributes = {}
            return

        leave_report = coordinator_data.next_leave_report
        self._attr_extra_state_attributes = {
            "report_id": leave_report.get("id"),
            "student_id": leave_report.get("studentId"),
            "student_name": leave_report.get("studentName"),
            "status": leave_report.get("status"),
            "status_date": leave_report.get("statusDate"),
        }

    async def async_get_events(
        self,
        hass: HomeAssistant,
        start_date: datetime,
        end_date: datetime,
    ) -> list[CalendarEvent]:
        """Return leave requests overlapping the requested datetime range."""
        leave_reports = await self.coordinator.async_get_leave_reports()
        calendar_events: list[CalendarEvent] = []
        range_start = start_date.astimezone(UTC)
        range_end = end_date.astimezone(UTC)

        for leave_report in leave_reports:
            report_start = parse_event_datetime(leave_report.get("start"))
            report_end = parse_event_datetime(leave_report.get("end"))
            if report_start is None or report_end is None:
                continue
            if report_end < range_start or report_start > range_end:
                continue

            if calendar_event := _leave_report_to_calendar_event(leave_report):
                calendar_events.append(calendar_event)

        return calendar_events

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        self._update_attrs()
        super()._handle_coordinator_update()
