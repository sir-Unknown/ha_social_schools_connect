"""API client for the Social Schools Connect integration."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from aiohttp import ClientError, ClientSession, ClientTimeout

from .auth import AuthError, ForbiddenError, SocialSchoolsAuth, TokenError
from .const import (
    API_BASE,
    COMMUNITY_POSTS_PATH,
    CURRENT_USER_PATH,
    EVENTS_PATH,
    LEAVE_REPORTS_PATH,
    REQUEST_TIMEOUT,
)

MEDIA_TYPE_LABELS: dict[int, str] = {
    1: "image",
    2: "video",
    3: "document",
}
_REQUEST_TIMEOUT = ClientTimeout(total=REQUEST_TIMEOUT)


def _map_post(
    raw: dict[str, Any], *, include_media: bool = False, include_body: bool = True
) -> dict[str, Any]:
    """Map a raw API post to the subset of fields used by this integration."""
    author_raw = raw.get("author")
    if isinstance(author_raw, dict):
        author_display_name = author_raw.get("displayName")
    elif isinstance(author_raw, str):
        author_display_name = author_raw
    else:
        author_display_name = None

    mapped = {
        "id": raw.get("id"),
        "title": raw.get("title"),
        "created": raw.get("created"),
        "communities": [
            {
                "id": c.get("id") if isinstance(c, dict) else None,
                "name": c.get("name") if isinstance(c, dict) else None,
                "type": c.get("type") if isinstance(c, dict) else None,
            }
            for c in raw.get("communities") or []
        ],
        "author": {
            "displayName": author_display_name,
        },
    }
    if include_body:
        mapped["body"] = raw.get("body")
    if include_media:
        mapped["media"] = [
            {
                "id": m.get("id") if isinstance(m, dict) else None,
                "typeLabel": (
                    MEDIA_TYPE_LABELS.get(media_type)
                    if isinstance(m, dict) and isinstance((media_type := m.get("type")), int)
                    else None
                ),
                "fileName": m.get("fileName") if isinstance(m, dict) else None,
                "fullPath": m.get("fullPath") if isinstance(m, dict) else None,
                "order": m.get("order") if isinstance(m, dict) else None,
            }
            for m in raw.get("media") or []
        ]
    return mapped


def _map_posts_collection(
    raw: Any, *, include_media: bool = False, include_body: bool = True
) -> list[dict[str, Any]]:
    """Map list-like post payloads to normalized post dictionaries."""
    values = raw.get("values") if isinstance(raw, dict) else raw
    if not isinstance(values, list):
        raise TokenError(
            f"Unexpected response from posts endpoint: {type(raw).__name__}"
        )

    mapped_posts: list[dict[str, Any]] = []
    for item in values:
        if not isinstance(item, dict):
            raise TokenError(
                f"Unexpected post item type from posts endpoint: {type(item).__name__}"
            )
        mapped_posts.append(
            _map_post(item, include_media=include_media, include_body=include_body)
        )
    return mapped_posts


def _map_event(raw: dict[str, Any]) -> dict[str, Any]:
    """Map a raw API event to the subset of fields used by this integration."""
    return {
        "id": raw.get("id"),
        "title": raw.get("title"),
        "description": raw.get("description"),
        "start": raw.get("start"),
        "end": raw.get("end"),
        "all_day": bool(raw.get("allDay")),
        "location": raw.get("location"),
        "type": raw.get("type"),
        "communities": [
            {
                "id": community.get("id") if isinstance(community, dict) else None,
                "name": community.get("name") if isinstance(community, dict) else None,
                "type": community.get("type") if isinstance(community, dict) else None,
            }
            for community in raw.get("communities") or []
        ],
    }


def _map_events_collection(raw: Any) -> list[dict[str, Any]]:
    """Map list-like event payloads to normalized event dictionaries."""
    if not isinstance(raw, list):
        raise TokenError(
            f"Unexpected response from events endpoint: {type(raw).__name__}"
        )

    mapped_events: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            raise TokenError(
                f"Unexpected event item type from events endpoint: {type(item).__name__}"
            )
        mapped_events.append(_map_event(item))
    return mapped_events


def _map_leave_report(raw: dict[str, Any]) -> dict[str, Any]:
    """Map a raw leave report to the subset of fields used by this integration."""
    status_by = raw.get("statusBy")
    return {
        "id": raw.get("id"),
        "created": raw.get("created"),
        "start": raw.get("start"),
        "end": raw.get("end"),
        "explanation": raw.get("explanation"),
        "status": raw.get("status"),
        "statusDate": raw.get("statusDate"),
        "statusExplanation": raw.get("statusExplanation"),
        "studentIds": raw.get("studentIds") or [],
        "reportType": raw.get("reportType"),
        "companyInfo": raw.get("companyInfo"),
        "lateExplanation": raw.get("lateExplanation"),
        "employmentType": raw.get("employmentType"),
        "document": raw.get("document"),
        "statusBy": {
            "id": status_by.get("id") if isinstance(status_by, dict) else None,
            "displayName": (
                status_by.get("displayName") if isinstance(status_by, dict) else None
            ),
        },
    }


def _map_leave_reports_collection(raw: Any) -> list[dict[str, Any]]:
    """Map list-like leave report payloads to normalized dictionaries."""
    if not isinstance(raw, list):
        raise TokenError(
            f"Unexpected response from leave reports endpoint: {type(raw).__name__}"
        )

    mapped_reports: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            raise TokenError(
                f"Unexpected leave report item type: {type(item).__name__}"
            )
        mapped_reports.append(_map_leave_report(item))
    return mapped_reports


class SocialSchoolsClient:
    """Client that handles authenticated Social Schools API calls."""

    def __init__(
        self,
        session: ClientSession,
        *,
        refresh_token: str | None = None,
    ) -> None:
        """Initialize the client."""
        self._auth = SocialSchoolsAuth(
            session,
            refresh_token=refresh_token,
        )
        self._session = session
        self._role_type_id: int | None = None
        self._school_id: int | None = None

    @property
    def refresh_token(self) -> str | None:
        """Return the refresh token, if available."""
        return self._auth.refresh_token

    async def async_login(self, username: str, password: str) -> None:
        """Perform a full OAuth2 PKCE login with the provided credentials."""
        await self._auth.async_login_with_credentials(username, password)

    async def _async_get_json(
        self,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
    ) -> Any:
        """Perform an authenticated GET request against the Social Schools API."""
        access_token = await self._auth.async_ensure_token()

        request_headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }
        if headers:
            request_headers.update(headers)

        url = f"{API_BASE}{path}"
        try:
            async with self._session.get(
                url,
                headers=request_headers,
                params=params,
                timeout=_REQUEST_TIMEOUT,
            ) as resp:
                if resp.status == 403:
                    raise ForbiddenError("API returned 403")
                if resp.status == 401:
                    raise AuthError("API returned 401")
                if resp.status != 200:
                    raise TokenError(f"API returned {resp.status}")
                return await resp.json()
        except ClientError as err:
            raise TokenError("Error communicating with the Social Schools API") from err
        except TimeoutError as err:
            raise TokenError("Social Schools API timed out") from err

    async def _async_get_json_with_context_retry(
        self,
        path: str,
        *,
        params: dict[str, str] | None = None,
    ) -> Any:
        """GET JSON and retry once with role and school headers when API returns 403."""
        try:
            return await self._async_get_json(path, params=params)
        except ForbiddenError:
            pass

        if self._role_type_id is None or self._school_id is None:
            await self.async_get_current_user()

        if self._role_type_id is None or self._school_id is None:
            raise ForbiddenError("API returned 403 and no role/school context available")

        return await self._async_get_json(
            path,
            params=params,
            headers={
                "roletypeid": str(self._role_type_id),
                "schoolid": str(self._school_id),
            },
        )

    async def async_get(self, path: str) -> Any:
        """Perform an authenticated GET request."""
        return await self._async_get_json(path)

    async def async_get_current_user(self) -> dict[str, Any]:
        """Fetch the current user and cache the main role and school identifiers."""
        data = await self.async_get(CURRENT_USER_PATH)
        if not isinstance(data, dict):
            raise TokenError(
                f"Unexpected response from user endpoint: {type(data).__name__}"
            )

        roles = data.get("roles") or []
        if roles:
            main_role = roles[0]
            role_type = main_role.get("type")
            try:
                self._role_type_id = int(role_type) if role_type is not None else None
            except (TypeError, ValueError):
                self._role_type_id = None

            school_id = (main_role.get("school") or {}).get("id")
            try:
                self._school_id = int(school_id) if school_id is not None else None
            except (TypeError, ValueError):
                self._school_id = None

        return data

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
        """Fetch posts in latest, search, or post mode."""
        if mode == "post":
            if post_id is None:
                raise ValueError("post_id is required for mode=post")
            raw = await self._async_get_json_with_context_retry(
                f"{COMMUNITY_POSTS_PATH}/{post_id}"
            )
            if not isinstance(raw, dict):
                raise TokenError(
                    f"Unexpected response from post endpoint: {type(raw).__name__}"
                )
            return [_map_post(raw, include_media=include_media, include_body=True)]

        if mode == "search":
            if q is None or not q.strip():
                raise ValueError("q is required for mode=search")
            params = {
                "offset": "0",
                "limit": "20",
                "q": q,
            }
            if community_id is not None:
                params["communityId"] = str(community_id)
            raw = await self._async_get_json_with_context_retry(
                f"{COMMUNITY_POSTS_PATH}/search", params=params
            )
            return _map_posts_collection(
                raw, include_media=include_media, include_body=True
            )

        params = {
            "offset": "0",
            "limit": str(limit),
            "filterType": "0",
        }
        if community_id is not None:
            raw = await self._async_get_json_with_context_retry(
                f"/api/v1/communities/{community_id}/posts", params=params
            )
        else:
            raw = await self._async_get_json_with_context_retry(
                COMMUNITY_POSTS_PATH, params=params
            )
        # Keep service responses consistent across all modes by always including
        # the post body in mapped results.
        return _map_posts_collection(raw, include_media=include_media, include_body=True)

    async def async_get_events(
        self, *, start_date: datetime, end_date: datetime
    ) -> list[dict[str, Any]]:
        """Fetch calendar events within the provided UTC datetime range."""
        raw = await self._async_get_json_with_context_retry(
            EVENTS_PATH,
            params={
                "from": start_date.isoformat().replace("+00:00", "Z"),
                "until": end_date.isoformat().replace("+00:00", "Z"),
            },
        )
        return _map_events_collection(raw)

    async def async_get_leave_reports(self, student_id: int) -> list[dict[str, Any]]:
        """Fetch leave reports for a specific student."""
        raw = await self._async_get_json_with_context_retry(
            f"{LEAVE_REPORTS_PATH}/{student_id}"
        )
        return _map_leave_reports_collection(raw)
