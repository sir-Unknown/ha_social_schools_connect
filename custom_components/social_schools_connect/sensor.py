"""Sensor platform for the Social Schools Connect integration."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import SocialSchoolsConfigEntry
from .const import DOMAIN
from .coordinator import SocialSchoolsCoordinator, parse_event_datetime


def _role(user: dict[str, Any]) -> dict[str, Any]:
    return ((user.get("roles") or [{}])[0]) or {}


def _school(user: dict[str, Any]) -> dict[str, Any]:
    return _role(user).get("school") or {}


def _school_year(user: dict[str, Any]) -> dict[str, Any]:
    return _school(user).get("schoolYear") or {}


def _notif_stats(user: dict[str, Any]) -> dict[str, Any]:
    return _role(user).get("notificationStats") or {}


def _community_stats(user: dict[str, Any]) -> dict[str, Any]:
    return _role(user).get("communityPostStats") or {}


@dataclass(frozen=True, kw_only=True)
class SocialSchoolsSensorDescription(SensorEntityDescription):
    """Extends SensorEntityDescription with a value extractor callable."""

    value_fn: Callable[[dict[str, Any]], Any]


_SCHOOL_SENSORS: tuple[SocialSchoolsSensorDescription, ...] = (
    SocialSchoolsSensorDescription(
        key="school_name",
        translation_key="school_name",
        entity_category=EntityCategory.DIAGNOSTIC,
        icon="mdi:school",
        value_fn=lambda u: _school(u).get("name"),
    ),
    SocialSchoolsSensorDescription(
        key="school_city",
        translation_key="school_city",
        entity_category=EntityCategory.DIAGNOSTIC,
        icon="mdi:city",
        value_fn=lambda u: _school(u).get("city"),
    ),
    SocialSchoolsSensorDescription(
        key="school_tag_line",
        translation_key="school_tag_line",
        entity_category=EntityCategory.DIAGNOSTIC,
        icon="mdi:text",
        value_fn=lambda u: (_school(u).get("theme") or {}).get("tagLine"),
    ),
    SocialSchoolsSensorDescription(
        key="school_period",
        translation_key="school_period",
        entity_category=EntityCategory.DIAGNOSTIC,
        icon="mdi:calendar-range",
        value_fn=lambda u: _school_year(u).get("display"),
    ),
    SocialSchoolsSensorDescription(
        key="school_year_start",
        translation_key="school_year_start",
        entity_category=EntityCategory.DIAGNOSTIC,
        device_class=SensorDeviceClass.TIMESTAMP,
        value_fn=lambda u: parse_event_datetime(_school_year(u).get("schoolYearStart")),
    ),
    SocialSchoolsSensorDescription(
        key="school_year_end",
        translation_key="school_year_end",
        entity_category=EntityCategory.DIAGNOSTIC,
        device_class=SensorDeviceClass.TIMESTAMP,
        value_fn=lambda u: parse_event_datetime(_school_year(u).get("schoolYearEnd")),
    ),
)

_STATS_SENSORS: tuple[SocialSchoolsSensorDescription, ...] = (
    SocialSchoolsSensorDescription(
        key="notifications_unseen",
        translation_key="notifications_unseen",
        icon="mdi:bell-badge",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda u: _notif_stats(u).get("unseenCount"),
    ),
    SocialSchoolsSensorDescription(
        key="notifications_new_posts",
        translation_key="notifications_new_posts",
        icon="mdi:bell-ring",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda u: _notif_stats(u).get("newPostCount"),
    ),
    SocialSchoolsSensorDescription(
        key="notifications_topics_unseen",
        translation_key="notifications_topics_unseen",
        icon="mdi:forum-outline",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda u: _notif_stats(u).get("topicsUnseen"),
    ),
    SocialSchoolsSensorDescription(
        key="community_posts_pending",
        translation_key="community_posts_pending",
        icon="mdi:post-outline",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda u: _community_stats(u).get("pendingCount"),
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: SocialSchoolsConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up sensor entities from a config entry."""
    coordinator = entry.runtime_data.coordinator
    user = coordinator.data.user
    school = _school(user)

    entities: list[SensorEntity] = [
        SocialSchoolsStaticSensor(entry, description)
        for description in _SCHOOL_SENSORS
    ]

    # Only add display_name sensor when it differs from the canonical name
    if school.get("displayName") and school.get("displayName") != school.get("name"):
        entities.append(
            SocialSchoolsStaticSensor(
                entry,
                SocialSchoolsSensorDescription(
                    key="school_display_name",
                    translation_key="school_display_name",
                    entity_category=EntityCategory.DIAGNOSTIC,
                    icon="mdi:school-outline",
                    value_fn=lambda u: _school(u).get("displayName"),
                ),
            )
        )

    entities.extend(
        SocialSchoolsStaticSensor(entry, description) for description in _STATS_SENSORS
    )

    for connection in (_role(user).get("connections") or []):
        if connection.get("id") is not None:
            entities.extend(
                [
                    SocialSchoolsConnectionSensor(entry, connection["id"]),
                    SocialSchoolsConnectionNameSensor(entry, connection["id"]),
                    SocialSchoolsConnectionGroupsSensor(entry, connection["id"]),
                ]
            )

    async_add_entities(entities)


class _SocialSchoolsBaseSensor(CoordinatorEntity[SocialSchoolsCoordinator], SensorEntity):
    """Base sensor that resolves the available MRO conflict between CoordinatorEntity and Entity."""

    _attr_has_entity_name = True

    @property
    def available(self) -> bool:  # type: ignore[override]
        """Return if entity is available."""
        return self.coordinator.last_update_success


class SocialSchoolsStaticSensor(_SocialSchoolsBaseSensor):
    """Sensor entity driven by a value_fn extractor."""

    def __init__(
        self,
        entry: SocialSchoolsConfigEntry,
        description: SocialSchoolsSensorDescription,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(entry.runtime_data.coordinator)
        self._description = description
        self._attr_unique_id = f"{entry.entry_id}_{description.key}"
        self._attr_device_info = DeviceInfo(identifiers={(DOMAIN, entry.entry_id)})
        self._attr_translation_key = description.translation_key
        self._attr_entity_category = description.entity_category
        self._attr_icon = description.icon
        self._attr_device_class = description.device_class
        self._attr_state_class = description.state_class

    def _update_native_value(self) -> None:
        """Refresh native value from coordinator data."""
        if self.coordinator.data is None:
            self._attr_native_value = None
            return
        self._attr_native_value = self._description.value_fn(self.coordinator.data.user)

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        self._update_native_value()
        super()._handle_coordinator_update()


class _SocialSchoolsConnectionBaseSensor(_SocialSchoolsBaseSensor):
    """Base for sensors that track a single student connection."""

    def __init__(
        self,
        entry: SocialSchoolsConfigEntry,
        connection_id: int,
    ) -> None:
        """Initialize the connection sensor."""
        super().__init__(entry.runtime_data.coordinator)
        self._connection_id = connection_id

    def _get_connection(self) -> dict[str, Any] | None:
        if self.coordinator.data is None:
            return None
        return next(
            (
                c
                for c in (_role(self.coordinator.data.user).get("connections") or [])
                if c.get("id") == self._connection_id
            ),
            None,
        )


class SocialSchoolsConnectionSensor(_SocialSchoolsConnectionBaseSensor):
    """Sensor entity representing a single connected student."""

    _attr_icon = "mdi:account-child"
    _attr_translation_key = "student_school_year"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        entry: SocialSchoolsConfigEntry,
        connection_id: int,
    ) -> None:
        """Initialize the connection sensor."""
        super().__init__(entry, connection_id)
        self._attr_unique_id = f"{entry.entry_id}_connection_{connection_id}"
        self._attr_device_info = DeviceInfo(identifiers={(DOMAIN, entry.entry_id)})

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        conn = self._get_connection()
        self._attr_native_value = conn.get("yearClass") if conn is not None else None
        super()._handle_coordinator_update()


class SocialSchoolsConnectionNameSensor(_SocialSchoolsConnectionBaseSensor):
    """Sensor entity exposing the connected student's name."""

    _attr_icon = "mdi:account-child"
    _attr_translation_key = "student"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        entry: SocialSchoolsConfigEntry,
        connection_id: int,
    ) -> None:
        """Initialize the student name sensor."""
        super().__init__(entry, connection_id)
        self._attr_unique_id = f"{entry.entry_id}_connection_{connection_id}_student"
        self._attr_device_info = DeviceInfo(identifiers={(DOMAIN, entry.entry_id)})

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        conn = self._get_connection()
        if conn is None:
            self._attr_native_value = None
            self._attr_extra_state_attributes = {}
        else:
            display_name = (
                (conn.get("firstName") or "").strip()
                or (conn.get("displayName") or "").strip()
                or None
            )
            self._attr_native_value = display_name
            self._attr_extra_state_attributes = {
                "student_name": display_name,
                "display_name": (conn.get("displayName") or "").strip() or None,
                "first_name": conn.get("firstName") or None,
                "middle_initials": conn.get("middleInitials"),
                "last_name": conn.get("lastName") or None,
                "groups": conn.get("groups") or [],
                "alias": conn.get("alias"),
                "id": conn.get("id") or self._connection_id,
            }
        super()._handle_coordinator_update()


class SocialSchoolsConnectionGroupsSensor(_SocialSchoolsConnectionBaseSensor):
    """Sensor entity exposing the connected student's groups."""

    _attr_icon = "mdi:account-group"
    _attr_translation_key = "student_groups"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        entry: SocialSchoolsConfigEntry,
        connection_id: int,
    ) -> None:
        """Initialize the student groups sensor."""
        super().__init__(entry, connection_id)
        self._attr_unique_id = f"{entry.entry_id}_connection_{connection_id}_groups"
        self._attr_device_info = DeviceInfo(identifiers={(DOMAIN, entry.entry_id)})

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        conn = self._get_connection()
        if conn is None:
            self._attr_native_value = None
            self._attr_extra_state_attributes = {}
        else:
            groups = conn.get("groups") or []
            self._attr_native_value = ", ".join(groups) if groups else None
            self._attr_extra_state_attributes = {"groups": groups}
        super()._handle_coordinator_update()
