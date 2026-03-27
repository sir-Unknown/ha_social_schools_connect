"""Service registration and handlers for Social Schools Connect."""

from __future__ import annotations

from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant, ServiceCall, SupportsResponse
from homeassistant.exceptions import HomeAssistantError

from .const import DOMAIN

SERVICE_GET_POSTS = "get_posts"
_MODE_VALUES = ("latest", "search", "post")


def _non_empty_string(value: Any) -> str:
    """Validate and normalize non-empty search input."""
    if not isinstance(value, str):
        raise vol.Invalid("Expected a string")
    normalized = value.strip()
    if not normalized:
        raise vol.Invalid("Value cannot be empty")
    return normalized


def _validate_get_posts_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate service fields based on selected mode."""
    mode = payload["mode"]
    if mode == "post" and "post_id" not in payload:
        raise vol.Invalid("`post_id` is required when mode is `post`")
    if mode == "search" and "search_query" not in payload:
        raise vol.Invalid("`search_query` is required when mode is `search`")
    return payload


def _resolve_coordinator(hass: HomeAssistant) -> Any:
    """Resolve a coordinator from the first loaded config entry."""
    for entry in hass.config_entries.async_entries(DOMAIN):
        if entry.state is not ConfigEntryState.LOADED:
            continue
        runtime_data = getattr(entry, "runtime_data", None)
        if runtime_data is None:
            continue
        coordinator = getattr(runtime_data, "coordinator", None)
        if coordinator is not None:
            return coordinator

    raise HomeAssistantError("No loaded config entry available for service call")


def async_setup_services(hass: HomeAssistant) -> None:
    """Register integration services."""

    async def _handle_get_posts(call: ServiceCall) -> dict:
        coordinator = _resolve_coordinator(hass)
        mode = call.data["mode"]
        posts = await coordinator.async_get_posts(
            mode=mode,
            post_id=call.data.get("post_id"),
            q=call.data.get("search_query"),
            community_id=call.data.get("community_id"),
            include_media=call.data["include_media"],
            limit=call.data["limit"],
        )

        return {"mode": mode, "posts": posts, "count": len(posts)}

    hass.services.async_register(
        DOMAIN,
        SERVICE_GET_POSTS,
        _handle_get_posts,
        schema=vol.Schema(
            vol.All(
                {
                    vol.Required("mode"): vol.In(_MODE_VALUES),
                    vol.Optional("post_id"): vol.All(
                        vol.Coerce(int), vol.Range(min=1)
                    ),
                    vol.Optional("search_query"): _non_empty_string,
                    vol.Optional("community_id"): vol.All(
                        vol.Coerce(int), vol.Range(min=1)
                    ),
                    vol.Optional("limit", default=10): vol.All(
                        vol.Coerce(int), vol.Range(min=1, max=10)
                    ),
                    vol.Optional("include_media", default=False): bool,
                },
                _validate_get_posts_payload,
            )
        ),
        supports_response=SupportsResponse.ONLY,
    )
