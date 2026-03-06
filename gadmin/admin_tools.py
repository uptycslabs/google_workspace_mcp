"""
Google Admin MCP Tools

This module provides MCP tools for interacting with Google Admin APIs like Reports API, etc.
"""

from googleapiclient.errors import HttpError
import json
import logging
import asyncio

from core.server import server
from core.utils import handle_http_errors
from auth.service_decorator import require_google_service

# Configure module logger
logger = logging.getLogger(__name__)


async def _list_activities_impl(
    service,
    application_name: str,
    user_google_email: str = "@",
    user_key: str = "all",
    max_results: int = 1000,
    next_page_token: str = None,
    start_time: str = None,
    end_time: str = None,
    event_name: str = None,
    actor_ip_address: str = None,
    filters: str = None,
) -> str:
    """Internal implementation for listing activities."""
    logger.info(f"[list_activities] Invoked. Email: '{user_google_email}', User Key: '{user_key}', Application: '{application_name}'")

    try:
        activities_response = await asyncio.to_thread(
            lambda: service.activities().list(
                userKey=user_key,
                applicationName=application_name,
                maxResults=max_results,
                pageToken=next_page_token,
                startTime=start_time,
                endTime=end_time,
                eventName=event_name,
                actorIpAddress=actor_ip_address,
                filters=filters,
            ).execute()
        )
    except HttpError as get_error:
        if get_error.status_code == 401:
            message = f"API error [list_activities]: {get_error}."
            logger.error(message)
            raise Exception(message)
        else:
            raise 

    items = activities_response.get("items", [])

    logger.info(f"Successfully listed {len(items)} activities for user {user_google_email}, User Key: '{user_key}', Application: '{application_name}'.")
    return json.dumps(activities_response)


@server.tool(
    annotations={
        "title": "Access Transparency Audit Log Retriever",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    }
)
@handle_http_errors("list_activities_access_transparency", is_read_only=True, service_type='admin')
@require_google_service("admin", "admin_reports_read")
async def list_activities_access_transparency(
    service,
    user_google_email: str = "@",
    user_key: str = "all",
    max_results: int = 1000,
    next_page_token: str = None,
    start_time: str = None,
    end_time: str = None,
    event_name: str = None,
    actor_ip_address: str = None,
    filters: str = None,
) -> str:
    """
    Retrieves Access Transparency audit activity logs (up to 180 days).
    Use for tracking Google staff access to your organization's data.

    Args:
        user_google_email (str): The user's Google email address. Defaults to '@' (applies to all users).
        user_key (str): User profile ID or email to filter by, or 'all' for all users. Defaults to 'all'.
        max_results (int): Results per page (max 1000). Defaults to 1000.
        next_page_token (Optional[str]): Token for pagination from previous response.
        start_time (Optional[str]): Start of time range (RFC 3339, e.g., '2024-01-15T10:00:00Z').
        end_time (Optional[str]): End of time range (RFC 3339). Defaults to current time.
        event_name (Optional[str]): Specific event name to filter by.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Event parameter filters (e.g., 'doc_id==12345').

    Returns:
        str: JSON with activity records (items), pagination token (nextPageToken), and metadata.
    """
    return await _list_activities_impl(
        service=service,
        application_name="access_transparency",
        user_google_email=user_google_email,
        user_key=user_key,
        max_results=max_results,
        next_page_token=next_page_token,
        start_time=start_time,
        end_time=end_time,
        event_name=event_name,
        actor_ip_address=actor_ip_address,
        filters=filters,
    )


@server.tool(
    annotations={
        "title": "Admin Audit Log Retriever",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    }
)
@handle_http_errors("list_activities_admin", is_read_only=True, service_type='admin')
@require_google_service("admin", "admin_reports_read")
async def list_activities_admin(
    service,
    user_google_email: str = "@",
    user_key: str = "all",
    max_results: int = 1000,
    next_page_token: str = None,
    start_time: str = None,
    end_time: str = None,
    event_name: str = None,
    actor_ip_address: str = None,
    filters: str = None,
) -> str:
    """
    Retrieves Admin Console audit activity logs (up to 180 days).
    Use for tracking admin actions like user management, security settings, and organizational changes.

    Args:
        user_google_email (str): The user's Google email address. Defaults to '@' (applies to all users).
        user_key (str): User profile ID or email to filter by, or 'all' for all users. Defaults to 'all'.
        max_results (int): Results per page (max 1000). Defaults to 1000.
        next_page_token (Optional[str]): Token for pagination from previous response.
        start_time (Optional[str]): Start of time range (RFC 3339, e.g., '2024-01-15T10:00:00Z').
        end_time (Optional[str]): End of time range (RFC 3339). Defaults to current time.
        event_name (Optional[str]): Specific event name to filter by.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Event parameter filters (e.g., 'doc_id==12345').

    Returns:
        str: JSON with activity records (items), pagination token (nextPageToken), and metadata.
    """
    return await _list_activities_impl(
        service=service,
        application_name="admin",
        user_google_email=user_google_email,
        user_key=user_key,
        max_results=max_results,
        next_page_token=next_page_token,
        start_time=start_time,
        end_time=end_time,
        event_name=event_name,
        actor_ip_address=actor_ip_address,
        filters=filters,
    )


@server.tool(
    annotations={
        "title": "Calendar Audit Log Retriever",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    }
)
@handle_http_errors("list_activities_calendar", is_read_only=True, service_type='admin')
@require_google_service("admin", "admin_reports_read")
async def list_activities_calendar(
    service,
    user_google_email: str = "@",
    user_key: str = "all",
    max_results: int = 1000,
    next_page_token: str = None,
    start_time: str = None,
    end_time: str = None,
    event_name: str = None,
    actor_ip_address: str = None,
    filters: str = None,
) -> str:
    """
    Retrieves Google Calendar audit activity logs (up to 180 days).
    Use for tracking calendar events, sharing changes, and meeting activities.

    Args:
        user_google_email (str): The user's Google email address. Defaults to '@' (applies to all users).
        user_key (str): User profile ID or email to filter by, or 'all' for all users. Defaults to 'all'.
        max_results (int): Results per page (max 1000). Defaults to 1000.
        next_page_token (Optional[str]): Token for pagination from previous response.
        start_time (Optional[str]): Start of time range (RFC 3339, e.g., '2024-01-15T10:00:00Z').
        end_time (Optional[str]): End of time range (RFC 3339). Defaults to current time.
        event_name (Optional[str]): Specific event name to filter by.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Event parameter filters (e.g., 'doc_id==12345').

    Returns:
        str: JSON with activity records (items), pagination token (nextPageToken), and metadata.
    """
    return await _list_activities_impl(
        service=service,
        application_name="calendar",
        user_google_email=user_google_email,
        user_key=user_key,
        max_results=max_results,
        next_page_token=next_page_token,
        start_time=start_time,
        end_time=end_time,
        event_name=event_name,
        actor_ip_address=actor_ip_address,
        filters=filters,
    )


@server.tool(
    annotations={
        "title": "Chat Audit Log Retriever",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    }
)
@handle_http_errors("list_activities_chat", is_read_only=True, service_type='admin')
@require_google_service("admin", "admin_reports_read")
async def list_activities_chat(
    service,
    user_google_email: str = "@",
    user_key: str = "all",
    max_results: int = 1000,
    next_page_token: str = None,
    start_time: str = None,
    end_time: str = None,
    event_name: str = None,
    actor_ip_address: str = None,
    filters: str = None,
) -> str:
    """
    Retrieves Google Chat audit activity logs (up to 180 days).
    Use for tracking chat messages, spaces, and collaboration activities.

    Args:
        user_google_email (str): The user's Google email address. Defaults to '@' (applies to all users).
        user_key (str): User profile ID or email to filter by, or 'all' for all users. Defaults to 'all'.
        max_results (int): Results per page (max 1000). Defaults to 1000.
        next_page_token (Optional[str]): Token for pagination from previous response.
        start_time (Optional[str]): Start of time range (RFC 3339, e.g., '2024-01-15T10:00:00Z').
        end_time (Optional[str]): End of time range (RFC 3339). Defaults to current time.
        event_name (Optional[str]): Specific event name to filter by.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Event parameter filters (e.g., 'doc_id==12345').

    Returns:
        str: JSON with activity records (items), pagination token (nextPageToken), and metadata.
    """
    return await _list_activities_impl(
        service=service,
        application_name="chat",
        user_google_email=user_google_email,
        user_key=user_key,
        max_results=max_results,
        next_page_token=next_page_token,
        start_time=start_time,
        end_time=end_time,
        event_name=event_name,
        actor_ip_address=actor_ip_address,
        filters=filters,
    )


@server.tool(
    annotations={
        "title": "Chrome Audit Log Retriever",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    }
)
@handle_http_errors("list_activities_chrome", is_read_only=True, service_type='admin')
@require_google_service("admin", "admin_reports_read")
async def list_activities_chrome(
    service,
    user_google_email: str = "@",
    user_key: str = "all",
    max_results: int = 1000,
    next_page_token: str = None,
    start_time: str = None,
    end_time: str = None,
    event_name: str = None,
    actor_ip_address: str = None,
    filters: str = None,
) -> str:
    """
    Retrieves Chrome Browser/OS audit activity logs (up to 180 days).
    Use for tracking Chrome device management, extensions, and browser policies.

    Args:
        user_google_email (str): The user's Google email address. Defaults to '@' (applies to all users).
        user_key (str): User profile ID or email to filter by, or 'all' for all users. Defaults to 'all'.
        max_results (int): Results per page (max 1000). Defaults to 1000.
        next_page_token (Optional[str]): Token for pagination from previous response.
        start_time (Optional[str]): Start of time range (RFC 3339, e.g., '2024-01-15T10:00:00Z').
        end_time (Optional[str]): End of time range (RFC 3339). Defaults to current time.
        event_name (Optional[str]): Specific event name to filter by.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Event parameter filters (e.g., 'doc_id==12345').

    Returns:
        str: JSON with activity records (items), pagination token (nextPageToken), and metadata.
    """
    return await _list_activities_impl(
        service=service,
        application_name="chrome",
        user_google_email=user_google_email,
        user_key=user_key,
        max_results=max_results,
        next_page_token=next_page_token,
        start_time=start_time,
        end_time=end_time,
        event_name=event_name,
        actor_ip_address=actor_ip_address,
        filters=filters,
    )


@server.tool(
    annotations={
        "title": "Classroom Audit Log Retriever",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    }
)
@handle_http_errors("list_activities_classroom", is_read_only=True, service_type='admin')
@require_google_service("admin", "admin_reports_read")
async def list_activities_classroom(
    service,
    user_google_email: str = "@",
    user_key: str = "all",
    max_results: int = 1000,
    next_page_token: str = None,
    start_time: str = None,
    end_time: str = None,
    event_name: str = None,
    actor_ip_address: str = None,
    filters: str = None,
) -> str:
    """
    Retrieves Google Classroom audit activity logs (up to 180 days).
    Use for tracking classroom activities, assignments, and educational interactions.

    Args:
        user_google_email (str): The user's Google email address. Defaults to '@' (applies to all users).
        user_key (str): User profile ID or email to filter by, or 'all' for all users. Defaults to 'all'.
        max_results (int): Results per page (max 1000). Defaults to 1000.
        next_page_token (Optional[str]): Token for pagination from previous response.
        start_time (Optional[str]): Start of time range (RFC 3339, e.g., '2024-01-15T10:00:00Z').
        end_time (Optional[str]): End of time range (RFC 3339). Defaults to current time.
        event_name (Optional[str]): Specific event name to filter by.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Event parameter filters (e.g., 'doc_id==12345').

    Returns:
        str: JSON with activity records (items), pagination token (nextPageToken), and metadata.
    """
    return await _list_activities_impl(
        service=service,
        application_name="classroom",
        user_google_email=user_google_email,
        user_key=user_key,
        max_results=max_results,
        next_page_token=next_page_token,
        start_time=start_time,
        end_time=end_time,
        event_name=event_name,
        actor_ip_address=actor_ip_address,
        filters=filters,
    )


@server.tool(
    annotations={
        "title": "Context Aware Access Audit Log Retriever",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    }
)
@handle_http_errors("list_activities_context_aware_access", is_read_only=True, service_type='admin')
@require_google_service("admin", "admin_reports_read")
async def list_activities_context_aware_access(
    service,
    user_google_email: str = "@",
    user_key: str = "all",
    max_results: int = 1000,
    next_page_token: str = None,
    start_time: str = None,
    end_time: str = None,
    event_name: str = None,
    actor_ip_address: str = None,
    filters: str = None,
) -> str:
    """
    Retrieves Context-Aware Access audit activity logs (up to 180 days).
    Use for tracking access level evaluations and policy enforcement.

    Args:
        user_google_email (str): The user's Google email address. Defaults to '@' (applies to all users).
        user_key (str): User profile ID or email to filter by, or 'all' for all users. Defaults to 'all'.
        max_results (int): Results per page (max 1000). Defaults to 1000.
        next_page_token (Optional[str]): Token for pagination from previous response.
        start_time (Optional[str]): Start of time range (RFC 3339, e.g., '2024-01-15T10:00:00Z').
        end_time (Optional[str]): End of time range (RFC 3339). Defaults to current time.
        event_name (Optional[str]): Specific event name to filter by.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Event parameter filters (e.g., 'doc_id==12345').

    Returns:
        str: JSON with activity records (items), pagination token (nextPageToken), and metadata.
    """
    return await _list_activities_impl(
        service=service,
        application_name="context_aware_access",
        user_google_email=user_google_email,
        user_key=user_key,
        max_results=max_results,
        next_page_token=next_page_token,
        start_time=start_time,
        end_time=end_time,
        event_name=event_name,
        actor_ip_address=actor_ip_address,
        filters=filters,
    )


@server.tool(
    annotations={
        "title": "Data Studio Audit Log Retriever",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    }
)
@handle_http_errors("list_activities_data_studio", is_read_only=True, service_type='admin')
@require_google_service("admin", "admin_reports_read")
async def list_activities_data_studio(
    service,
    user_google_email: str = "@",
    user_key: str = "all",
    max_results: int = 1000,
    next_page_token: str = None,
    start_time: str = None,
    end_time: str = None,
    event_name: str = None,
    actor_ip_address: str = None,
    filters: str = None,
) -> str:
    """
    Retrieves Looker Studio (Data Studio) audit activity logs (up to 180 days).
    Use for tracking report creation, sharing, and data source activities.

    Args:
        user_google_email (str): The user's Google email address. Defaults to '@' (applies to all users).
        user_key (str): User profile ID or email to filter by, or 'all' for all users. Defaults to 'all'.
        max_results (int): Results per page (max 1000). Defaults to 1000.
        next_page_token (Optional[str]): Token for pagination from previous response.
        start_time (Optional[str]): Start of time range (RFC 3339, e.g., '2024-01-15T10:00:00Z').
        end_time (Optional[str]): End of time range (RFC 3339). Defaults to current time.
        event_name (Optional[str]): Specific event name to filter by.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Event parameter filters (e.g., 'doc_id==12345').

    Returns:
        str: JSON with activity records (items), pagination token (nextPageToken), and metadata.
    """
    return await _list_activities_impl(
        service=service,
        application_name="data_studio",
        user_google_email=user_google_email,
        user_key=user_key,
        max_results=max_results,
        next_page_token=next_page_token,
        start_time=start_time,
        end_time=end_time,
        event_name=event_name,
        actor_ip_address=actor_ip_address,
        filters=filters,
    )


@server.tool(
    annotations={
        "title": "Drive Audit Log Retriever",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    }
)
@handle_http_errors("list_activities_drive", is_read_only=True, service_type='admin')
@require_google_service("admin", "admin_reports_read")
async def list_activities_drive(
    service,
    user_google_email: str = "@",
    user_key: str = "all",
    max_results: int = 1000,
    next_page_token: str = None,
    start_time: str = None,
    end_time: str = None,
    event_name: str = None,
    actor_ip_address: str = None,
    filters: str = None,
) -> str:
    """
    Retrieves Google Drive audit activity logs (up to 180 days).
    Use for tracking file operations, sharing changes, and collaboration activities.

    Args:
        user_google_email (str): The user's Google email address. Defaults to '@' (applies to all users).
        user_key (str): User profile ID or email to filter by, or 'all' for all users. Defaults to 'all'.
        max_results (int): Results per page (max 1000). Defaults to 1000.
        next_page_token (Optional[str]): Token for pagination from previous response.
        start_time (Optional[str]): Start of time range (RFC 3339, e.g., '2024-01-15T10:00:00Z').
        end_time (Optional[str]): End of time range (RFC 3339). Defaults to current time.
        event_name (Optional[str]): Specific event name to filter by.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Event parameter filters (e.g., 'doc_id==12345').

    Returns:
        str: JSON with activity records (items), pagination token (nextPageToken), and metadata.
    """
    return await _list_activities_impl(
        service=service,
        application_name="drive",
        user_google_email=user_google_email,
        user_key=user_key,
        max_results=max_results,
        next_page_token=next_page_token,
        start_time=start_time,
        end_time=end_time,
        event_name=event_name,
        actor_ip_address=actor_ip_address,
        filters=filters,
    )


@server.tool(
    annotations={
        "title": "GCP Audit Log Retriever",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    }
)
@handle_http_errors("list_activities_gcp", is_read_only=True, service_type='admin')
@require_google_service("admin", "admin_reports_read")
async def list_activities_gcp(
    service,
    user_google_email: str = "@",
    user_key: str = "all",
    max_results: int = 1000,
    next_page_token: str = None,
    start_time: str = None,
    end_time: str = None,
    event_name: str = None,
    actor_ip_address: str = None,
    filters: str = None,
) -> str:
    """
    Retrieves Google Cloud Platform audit activity logs (up to 180 days).
    Use for tracking GCP resource access and management activities.

    Args:
        user_google_email (str): The user's Google email address. Defaults to '@' (applies to all users).
        user_key (str): User profile ID or email to filter by, or 'all' for all users. Defaults to 'all'.
        max_results (int): Results per page (max 1000). Defaults to 1000.
        next_page_token (Optional[str]): Token for pagination from previous response.
        start_time (Optional[str]): Start of time range (RFC 3339, e.g., '2024-01-15T10:00:00Z').
        end_time (Optional[str]): End of time range (RFC 3339). Defaults to current time.
        event_name (Optional[str]): Specific event name to filter by.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Event parameter filters (e.g., 'doc_id==12345').

    Returns:
        str: JSON with activity records (items), pagination token (nextPageToken), and metadata.
    """
    return await _list_activities_impl(
        service=service,
        application_name="gcp",
        user_google_email=user_google_email,
        user_key=user_key,
        max_results=max_results,
        next_page_token=next_page_token,
        start_time=start_time,
        end_time=end_time,
        event_name=event_name,
        actor_ip_address=actor_ip_address,
        filters=filters,
    )


@server.tool(
    annotations={
        "title": "Gemini in Workspace Apps Audit Log Retriever",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    }
)
@handle_http_errors("list_activities_gemini_in_workspace_apps", is_read_only=True, service_type='admin')
@require_google_service("admin", "admin_reports_read")
async def list_activities_gemini_in_workspace_apps(
    service,
    user_google_email: str = "@",
    user_key: str = "all",
    max_results: int = 1000,
    next_page_token: str = None,
    start_time: str = None,
    end_time: str = None,
    event_name: str = None,
    actor_ip_address: str = None,
    filters: str = None,
) -> str:
    """
    Retrieves Gemini in Workspace Apps audit activity logs (up to 180 days).
    Use for tracking Gemini AI usage across Workspace applications.

    Args:
        user_google_email (str): The user's Google email address. Defaults to '@' (applies to all users).
        user_key (str): User profile ID or email to filter by, or 'all' for all users. Defaults to 'all'.
        max_results (int): Results per page (max 1000). Defaults to 1000.
        next_page_token (Optional[str]): Token for pagination from previous response.
        start_time (Optional[str]): Start of time range (RFC 3339, e.g., '2024-01-15T10:00:00Z').
        end_time (Optional[str]): End of time range (RFC 3339). Defaults to current time.
        event_name (Optional[str]): Specific event name to filter by.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Event parameter filters (e.g., 'doc_id==12345').

    Returns:
        str: JSON with activity records (items), pagination token (nextPageToken), and metadata.
    """
    return await _list_activities_impl(
        service=service,
        application_name="gemini_in_workspace_apps",
        user_google_email=user_google_email,
        user_key=user_key,
        max_results=max_results,
        next_page_token=next_page_token,
        start_time=start_time,
        end_time=end_time,
        event_name=event_name,
        actor_ip_address=actor_ip_address,
        filters=filters,
    )


@server.tool(
    annotations={
        "title": "Gmail Audit Log Retriever",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    }
)
@handle_http_errors("list_activities_gmail", is_read_only=True, service_type='admin')
@require_google_service("admin", "admin_reports_read")
async def list_activities_gmail(
    service,
    user_google_email: str = "@",
    user_key: str = "all",
    max_results: int = 1000,
    next_page_token: str = None,
    start_time: str = None,
    end_time: str = None,
    event_name: str = None,
    actor_ip_address: str = None,
    filters: str = None,
) -> str:
    """
    Retrieves Gmail audit activity logs (up to 180 days).
    Use for tracking email activities. Note: start_time and end_time are required (max 30 days range).

    Args:
        user_google_email (str): The user's Google email address. Defaults to '@' (applies to all users).
        user_key (str): User profile ID or email to filter by, or 'all' for all users. Defaults to 'all'.
        max_results (int): Results per page (max 1000). Defaults to 1000.
        next_page_token (Optional[str]): Token for pagination from previous response.
        start_time (str): Start of time range (RFC 3339, e.g., '2024-01-15T10:00:00Z'). Required for Gmail (max 30 days range).
        end_time (str): End of time range (RFC 3339). Required for Gmail.
        event_name (Optional[str]): Specific event name to filter by.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Event parameter filters (e.g., 'doc_id==12345').

    Returns:
        str: JSON with activity records (items), pagination token (nextPageToken), and metadata.
    """
    return await _list_activities_impl(
        service=service,
        application_name="gmail",
        user_google_email=user_google_email,
        user_key=user_key,
        max_results=max_results,
        next_page_token=next_page_token,
        start_time=start_time,
        end_time=end_time,
        event_name=event_name,
        actor_ip_address=actor_ip_address,
        filters=filters,
    )


@server.tool(
    annotations={
        "title": "Google+ Audit Log Retriever",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    }
)
@handle_http_errors("list_activities_gplus", is_read_only=True, service_type='admin')
@require_google_service("admin", "admin_reports_read")
async def list_activities_gplus(
    service,
    user_google_email: str = "@",
    user_key: str = "all",
    max_results: int = 1000,
    next_page_token: str = None,
    start_time: str = None,
    end_time: str = None,
    event_name: str = None,
    actor_ip_address: str = None,
    filters: str = None,
) -> str:
    """
    Retrieves Google+ audit activity logs (up to 180 days).
    Use for tracking legacy Google+ activities.

    Args:
        user_google_email (str): The user's Google email address. Defaults to '@' (applies to all users).
        user_key (str): User profile ID or email to filter by, or 'all' for all users. Defaults to 'all'.
        max_results (int): Results per page (max 1000). Defaults to 1000.
        next_page_token (Optional[str]): Token for pagination from previous response.
        start_time (Optional[str]): Start of time range (RFC 3339, e.g., '2024-01-15T10:00:00Z').
        end_time (Optional[str]): End of time range (RFC 3339). Defaults to current time.
        event_name (Optional[str]): Specific event name to filter by.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Event parameter filters (e.g., 'doc_id==12345').

    Returns:
        str: JSON with activity records (items), pagination token (nextPageToken), and metadata.
    """
    return await _list_activities_impl(
        service=service,
        application_name="gplus",
        user_google_email=user_google_email,
        user_key=user_key,
        max_results=max_results,
        next_page_token=next_page_token,
        start_time=start_time,
        end_time=end_time,
        event_name=event_name,
        actor_ip_address=actor_ip_address,
        filters=filters,
    )


@server.tool(
    annotations={
        "title": "Groups Audit Log Retriever",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    }
)
@handle_http_errors("list_activities_groups", is_read_only=True, service_type='admin')
@require_google_service("admin", "admin_reports_read")
async def list_activities_groups(
    service,
    user_google_email: str = "@",
    user_key: str = "all",
    max_results: int = 1000,
    next_page_token: str = None,
    start_time: str = None,
    end_time: str = None,
    event_name: str = None,
    actor_ip_address: str = None,
    filters: str = None,
) -> str:
    """
    Retrieves Google Groups audit activity logs (up to 180 days).
    Use for tracking group membership changes, settings, and message activities.

    Args:
        user_google_email (str): The user's Google email address. Defaults to '@' (applies to all users).
        user_key (str): User profile ID or email to filter by, or 'all' for all users. Defaults to 'all'.
        max_results (int): Results per page (max 1000). Defaults to 1000.
        next_page_token (Optional[str]): Token for pagination from previous response.
        start_time (Optional[str]): Start of time range (RFC 3339, e.g., '2024-01-15T10:00:00Z').
        end_time (Optional[str]): End of time range (RFC 3339). Defaults to current time.
        event_name (Optional[str]): Specific event name to filter by.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Event parameter filters (e.g., 'doc_id==12345').

    Returns:
        str: JSON with activity records (items), pagination token (nextPageToken), and metadata.
    """
    return await _list_activities_impl(
        service=service,
        application_name="groups",
        user_google_email=user_google_email,
        user_key=user_key,
        max_results=max_results,
        next_page_token=next_page_token,
        start_time=start_time,
        end_time=end_time,
        event_name=event_name,
        actor_ip_address=actor_ip_address,
        filters=filters,
    )


@server.tool(
    annotations={
        "title": "Groups Enterprise Audit Log Retriever",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    }
)
@handle_http_errors("list_activities_groups_enterprise", is_read_only=True, service_type='admin')
@require_google_service("admin", "admin_reports_read")
async def list_activities_groups_enterprise(
    service,
    user_google_email: str = "@",
    user_key: str = "all",
    max_results: int = 1000,
    next_page_token: str = None,
    start_time: str = None,
    end_time: str = None,
    event_name: str = None,
    actor_ip_address: str = None,
    filters: str = None,
) -> str:
    """
    Retrieves Groups Enterprise audit activity logs (up to 180 days).
    Use for tracking enterprise group management and security activities.

    Args:
        user_google_email (str): The user's Google email address. Defaults to '@' (applies to all users).
        user_key (str): User profile ID or email to filter by, or 'all' for all users. Defaults to 'all'.
        max_results (int): Results per page (max 1000). Defaults to 1000.
        next_page_token (Optional[str]): Token for pagination from previous response.
        start_time (Optional[str]): Start of time range (RFC 3339, e.g., '2024-01-15T10:00:00Z').
        end_time (Optional[str]): End of time range (RFC 3339). Defaults to current time.
        event_name (Optional[str]): Specific event name to filter by.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Event parameter filters (e.g., 'doc_id==12345').

    Returns:
        str: JSON with activity records (items), pagination token (nextPageToken), and metadata.
    """
    return await _list_activities_impl(
        service=service,
        application_name="groups_enterprise",
        user_google_email=user_google_email,
        user_key=user_key,
        max_results=max_results,
        next_page_token=next_page_token,
        start_time=start_time,
        end_time=end_time,
        event_name=event_name,
        actor_ip_address=actor_ip_address,
        filters=filters,
    )


@server.tool(
    annotations={
        "title": "Jamboard Audit Log Retriever",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    }
)
@handle_http_errors("list_activities_jamboard", is_read_only=True, service_type='admin')
@require_google_service("admin", "admin_reports_read")
async def list_activities_jamboard(
    service,
    user_google_email: str = "@",
    user_key: str = "all",
    max_results: int = 1000,
    next_page_token: str = None,
    start_time: str = None,
    end_time: str = None,
    event_name: str = None,
    actor_ip_address: str = None,
    filters: str = None,
) -> str:
    """
    Retrieves Jamboard audit activity logs (up to 180 days).
    Use for tracking Jamboard collaboration and device activities.

    Args:
        user_google_email (str): The user's Google email address. Defaults to '@' (applies to all users).
        user_key (str): User profile ID or email to filter by, or 'all' for all users. Defaults to 'all'.
        max_results (int): Results per page (max 1000). Defaults to 1000.
        next_page_token (Optional[str]): Token for pagination from previous response.
        start_time (Optional[str]): Start of time range (RFC 3339, e.g., '2024-01-15T10:00:00Z').
        end_time (Optional[str]): End of time range (RFC 3339). Defaults to current time.
        event_name (Optional[str]): Specific event name to filter by.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Event parameter filters (e.g., 'doc_id==12345').

    Returns:
        str: JSON with activity records (items), pagination token (nextPageToken), and metadata.
    """
    return await _list_activities_impl(
        service=service,
        application_name="jamboard",
        user_google_email=user_google_email,
        user_key=user_key,
        max_results=max_results,
        next_page_token=next_page_token,
        start_time=start_time,
        end_time=end_time,
        event_name=event_name,
        actor_ip_address=actor_ip_address,
        filters=filters,
    )


@server.tool(
    annotations={
        "title": "Keep Audit Log Retriever",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    }
)
@handle_http_errors("list_activities_keep", is_read_only=True, service_type='admin')
@require_google_service("admin", "admin_reports_read")
async def list_activities_keep(
    service,
    user_google_email: str = "@",
    user_key: str = "all",
    max_results: int = 1000,
    next_page_token: str = None,
    start_time: str = None,
    end_time: str = None,
    event_name: str = None,
    actor_ip_address: str = None,
    filters: str = None,
) -> str:
    """
    Retrieves Google Keep audit activity logs (up to 180 days).
    Use for tracking note creation, sharing, and collaboration activities.

    Args:
        user_google_email (str): The user's Google email address. Defaults to '@' (applies to all users).
        user_key (str): User profile ID or email to filter by, or 'all' for all users. Defaults to 'all'.
        max_results (int): Results per page (max 1000). Defaults to 1000.
        next_page_token (Optional[str]): Token for pagination from previous response.
        start_time (Optional[str]): Start of time range (RFC 3339, e.g., '2024-01-15T10:00:00Z').
        end_time (Optional[str]): End of time range (RFC 3339). Defaults to current time.
        event_name (Optional[str]): Specific event name to filter by.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Event parameter filters (e.g., 'doc_id==12345').

    Returns:
        str: JSON with activity records (items), pagination token (nextPageToken), and metadata.
    """
    return await _list_activities_impl(
        service=service,
        application_name="keep",
        user_google_email=user_google_email,
        user_key=user_key,
        max_results=max_results,
        next_page_token=next_page_token,
        start_time=start_time,
        end_time=end_time,
        event_name=event_name,
        actor_ip_address=actor_ip_address,
        filters=filters,
    )


@server.tool(
    annotations={
        "title": "Login Audit Log Retriever",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    }
)
@handle_http_errors("list_activities_login", is_read_only=True, service_type='admin')
@require_google_service("admin", "admin_reports_read")
async def list_activities_login(
    service,
    user_google_email: str = "@",
    user_key: str = "all",
    max_results: int = 1000,
    next_page_token: str = None,
    start_time: str = None,
    end_time: str = None,
    event_name: str = None,
    actor_ip_address: str = None,
    filters: str = None,
) -> str:
    """
    Retrieves Login audit activity logs (up to 180 days).
    Use for tracking user login attempts, successes, failures, and authentication events.

    Args:
        user_google_email (str): The user's Google email address. Defaults to '@' (applies to all users).
        user_key (str): User profile ID or email to filter by, or 'all' for all users. Defaults to 'all'.
        max_results (int): Results per page (max 1000). Defaults to 1000.
        next_page_token (Optional[str]): Token for pagination from previous response.
        start_time (Optional[str]): Start of time range (RFC 3339, e.g., '2024-01-15T10:00:00Z').
        end_time (Optional[str]): End of time range (RFC 3339). Defaults to current time.
        event_name (Optional[str]): Specific event name to filter by.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Event parameter filters (e.g., 'doc_id==12345').

    Returns:
        str: JSON with activity records (items), pagination token (nextPageToken), and metadata.
    """
    return await _list_activities_impl(
        service=service,
        application_name="login",
        user_google_email=user_google_email,
        user_key=user_key,
        max_results=max_results,
        next_page_token=next_page_token,
        start_time=start_time,
        end_time=end_time,
        event_name=event_name,
        actor_ip_address=actor_ip_address,
        filters=filters,
    )


@server.tool(
    annotations={
        "title": "Meet Audit Log Retriever",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    }
)
@handle_http_errors("list_activities_meet", is_read_only=True, service_type='admin')
@require_google_service("admin", "admin_reports_read")
async def list_activities_meet(
    service,
    user_google_email: str = "@",
    user_key: str = "all",
    max_results: int = 1000,
    next_page_token: str = None,
    start_time: str = None,
    end_time: str = None,
    event_name: str = None,
    actor_ip_address: str = None,
    filters: str = None,
) -> str:
    """
    Retrieves Google Meet audit activity logs (up to 180 days).
    Use for tracking video meeting activities, participants, and call quality.

    Args:
        user_google_email (str): The user's Google email address. Defaults to '@' (applies to all users).
        user_key (str): User profile ID or email to filter by, or 'all' for all users. Defaults to 'all'.
        max_results (int): Results per page (max 1000). Defaults to 1000.
        next_page_token (Optional[str]): Token for pagination from previous response.
        start_time (Optional[str]): Start of time range (RFC 3339, e.g., '2024-01-15T10:00:00Z').
        end_time (Optional[str]): End of time range (RFC 3339). Defaults to current time.
        event_name (Optional[str]): Specific event name to filter by.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Event parameter filters (e.g., 'doc_id==12345').

    Returns:
        str: JSON with activity records (items), pagination token (nextPageToken), and metadata.
    """
    return await _list_activities_impl(
        service=service,
        application_name="meet",
        user_google_email=user_google_email,
        user_key=user_key,
        max_results=max_results,
        next_page_token=next_page_token,
        start_time=start_time,
        end_time=end_time,
        event_name=event_name,
        actor_ip_address=actor_ip_address,
        filters=filters,
    )


@server.tool(
    annotations={
        "title": "Mobile Audit Log Retriever",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    }
)
@handle_http_errors("list_activities_mobile", is_read_only=True, service_type='admin')
@require_google_service("admin", "admin_reports_read")
async def list_activities_mobile(
    service,
    user_google_email: str = "@",
    user_key: str = "all",
    max_results: int = 1000,
    next_page_token: str = None,
    start_time: str = None,
    end_time: str = None,
    event_name: str = None,
    actor_ip_address: str = None,
    filters: str = None,
) -> str:
    """
    Retrieves Mobile device audit activity logs (up to 180 days).
    Use for tracking mobile device management activities and compliance.

    Args:
        user_google_email (str): The user's Google email address. Defaults to '@' (applies to all users).
        user_key (str): User profile ID or email to filter by, or 'all' for all users. Defaults to 'all'.
        max_results (int): Results per page (max 1000). Defaults to 1000.
        next_page_token (Optional[str]): Token for pagination from previous response.
        start_time (Optional[str]): Start of time range (RFC 3339, e.g., '2024-01-15T10:00:00Z').
        end_time (Optional[str]): End of time range (RFC 3339). Defaults to current time.
        event_name (Optional[str]): Specific event name to filter by.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Event parameter filters (e.g., 'doc_id==12345').

    Returns:
        str: JSON with activity records (items), pagination token (nextPageToken), and metadata.
    """
    return await _list_activities_impl(
        service=service,
        application_name="mobile",
        user_google_email=user_google_email,
        user_key=user_key,
        max_results=max_results,
        next_page_token=next_page_token,
        start_time=start_time,
        end_time=end_time,
        event_name=event_name,
        actor_ip_address=actor_ip_address,
        filters=filters,
    )


@server.tool(
    annotations={
        "title": "Rules Audit Log Retriever",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    }
)
@handle_http_errors("list_activities_rules", is_read_only=True, service_type='admin')
@require_google_service("admin", "admin_reports_read")
async def list_activities_rules(
    service,
    user_google_email: str = "@",
    user_key: str = "all",
    max_results: int = 1000,
    next_page_token: str = None,
    start_time: str = None,
    end_time: str = None,
    event_name: str = None,
    actor_ip_address: str = None,
    filters: str = None,
) -> str:
    """
    Retrieves Rules audit activity logs (up to 180 days).
    Use for tracking DLP rules, security rules, and automated policy actions.

    Args:
        user_google_email (str): The user's Google email address. Defaults to '@' (applies to all users).
        user_key (str): User profile ID or email to filter by, or 'all' for all users. Defaults to 'all'.
        max_results (int): Results per page (max 1000). Defaults to 1000.
        next_page_token (Optional[str]): Token for pagination from previous response.
        start_time (Optional[str]): Start of time range (RFC 3339, e.g., '2024-01-15T10:00:00Z').
        end_time (Optional[str]): End of time range (RFC 3339). Defaults to current time.
        event_name (Optional[str]): Specific event name to filter by.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Event parameter filters (e.g., 'doc_id==12345').

    Returns:
        str: JSON with activity records (items), pagination token (nextPageToken), and metadata.
    """
    return await _list_activities_impl(
        service=service,
        application_name="rules",
        user_google_email=user_google_email,
        user_key=user_key,
        max_results=max_results,
        next_page_token=next_page_token,
        start_time=start_time,
        end_time=end_time,
        event_name=event_name,
        actor_ip_address=actor_ip_address,
        filters=filters,
    )


@server.tool(
    annotations={
        "title": "SAML Audit Log Retriever",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    }
)
@handle_http_errors("list_activities_saml", is_read_only=True, service_type='admin')
@require_google_service("admin", "admin_reports_read")
async def list_activities_saml(
    service,
    user_google_email: str = "@",
    user_key: str = "all",
    max_results: int = 1000,
    next_page_token: str = None,
    start_time: str = None,
    end_time: str = None,
    event_name: str = None,
    actor_ip_address: str = None,
    filters: str = None,
) -> str:
    """
    Retrieves SAML audit activity logs (up to 180 days).
    Use for tracking SAML-based single sign-on activities and authentication.

    Args:
        user_google_email (str): The user's Google email address. Defaults to '@' (applies to all users).
        user_key (str): User profile ID or email to filter by, or 'all' for all users. Defaults to 'all'.
        max_results (int): Results per page (max 1000). Defaults to 1000.
        next_page_token (Optional[str]): Token for pagination from previous response.
        start_time (Optional[str]): Start of time range (RFC 3339, e.g., '2024-01-15T10:00:00Z').
        end_time (Optional[str]): End of time range (RFC 3339). Defaults to current time.
        event_name (Optional[str]): Specific event name to filter by.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Event parameter filters (e.g., 'doc_id==12345').

    Returns:
        str: JSON with activity records (items), pagination token (nextPageToken), and metadata.
    """
    return await _list_activities_impl(
        service=service,
        application_name="saml",
        user_google_email=user_google_email,
        user_key=user_key,
        max_results=max_results,
        next_page_token=next_page_token,
        start_time=start_time,
        end_time=end_time,
        event_name=event_name,
        actor_ip_address=actor_ip_address,
        filters=filters,
    )


@server.tool(
    annotations={
        "title": "Token Audit Log Retriever",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    }
)
@handle_http_errors("list_activities_token", is_read_only=True, service_type='admin')
@require_google_service("admin", "admin_reports_read")
async def list_activities_token(
    service,
    user_google_email: str = "@",
    user_key: str = "all",
    max_results: int = 1000,
    next_page_token: str = None,
    start_time: str = None,
    end_time: str = None,
    event_name: str = None,
    actor_ip_address: str = None,
    filters: str = None,
) -> str:
    """
    Retrieves Token audit activity logs (up to 180 days).
    Use for tracking OAuth token authorizations and third-party app access.

    Args:
        user_google_email (str): The user's Google email address. Defaults to '@' (applies to all users).
        user_key (str): User profile ID or email to filter by, or 'all' for all users. Defaults to 'all'.
        max_results (int): Results per page (max 1000). Defaults to 1000.
        next_page_token (Optional[str]): Token for pagination from previous response.
        start_time (Optional[str]): Start of time range (RFC 3339, e.g., '2024-01-15T10:00:00Z').
        end_time (Optional[str]): End of time range (RFC 3339). Defaults to current time.
        event_name (Optional[str]): Specific event name to filter by.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Event parameter filters (e.g., 'doc_id==12345').

    Returns:
        str: JSON with activity records (items), pagination token (nextPageToken), and metadata.
    """
    return await _list_activities_impl(
        service=service,
        application_name="token",
        user_google_email=user_google_email,
        user_key=user_key,
        max_results=max_results,
        next_page_token=next_page_token,
        start_time=start_time,
        end_time=end_time,
        event_name=event_name,
        actor_ip_address=actor_ip_address,
        filters=filters,
    )


@server.tool(
    annotations={
        "title": "User Accounts Audit Log Retriever",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    }
)
@handle_http_errors("list_activities_user_accounts", is_read_only=True, service_type='admin')
@require_google_service("admin", "admin_reports_read")
async def list_activities_user_accounts(
    service,
    user_google_email: str = "@",
    user_key: str = "all",
    max_results: int = 1000,
    next_page_token: str = None,
    start_time: str = None,
    end_time: str = None,
    event_name: str = None,
    actor_ip_address: str = None,
    filters: str = None,
) -> str:
    """
    Retrieves User Accounts audit activity logs (up to 180 days).
    Use for tracking user account changes, password resets, and profile updates.

    Args:
        user_google_email (str): The user's Google email address. Defaults to '@' (applies to all users).
        user_key (str): User profile ID or email to filter by, or 'all' for all users. Defaults to 'all'.
        max_results (int): Results per page (max 1000). Defaults to 1000.
        next_page_token (Optional[str]): Token for pagination from previous response.
        start_time (Optional[str]): Start of time range (RFC 3339, e.g., '2024-01-15T10:00:00Z').
        end_time (Optional[str]): End of time range (RFC 3339). Defaults to current time.
        event_name (Optional[str]): Specific event name to filter by.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Event parameter filters (e.g., 'doc_id==12345').

    Returns:
        str: JSON with activity records (items), pagination token (nextPageToken), and metadata.
    """
    return await _list_activities_impl(
        service=service,
        application_name="user_accounts",
        user_google_email=user_google_email,
        user_key=user_key,
        max_results=max_results,
        next_page_token=next_page_token,
        start_time=start_time,
        end_time=end_time,
        event_name=event_name,
        actor_ip_address=actor_ip_address,
        filters=filters,
    )


@server.tool(
    annotations={
        "title": "Vault Audit Log Retriever",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    }
)
@handle_http_errors("list_activities_vault", is_read_only=True, service_type='admin')
@require_google_service("admin", "admin_reports_read")
async def list_activities_vault(
    service,
    user_google_email: str = "@",
    user_key: str = "all",
    max_results: int = 1000,
    next_page_token: str = None,
    start_time: str = None,
    end_time: str = None,
    event_name: str = None,
    actor_ip_address: str = None,
    filters: str = None,
) -> str:
    """
    Retrieves Google Vault audit activity logs (up to 180 days).
    Use for tracking eDiscovery, legal holds, and data retention activities.

    Args:
        user_google_email (str): The user's Google email address. Defaults to '@' (applies to all users).
        user_key (str): User profile ID or email to filter by, or 'all' for all users. Defaults to 'all'.
        max_results (int): Results per page (max 1000). Defaults to 1000.
        next_page_token (Optional[str]): Token for pagination from previous response.
        start_time (Optional[str]): Start of time range (RFC 3339, e.g., '2024-01-15T10:00:00Z').
        end_time (Optional[str]): End of time range (RFC 3339). Defaults to current time.
        event_name (Optional[str]): Specific event name to filter by.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Event parameter filters (e.g., 'doc_id==12345').

    Returns:
        str: JSON with activity records (items), pagination token (nextPageToken), and metadata.
    """
    return await _list_activities_impl(
        service=service,
        application_name="vault",
        user_google_email=user_google_email,
        user_key=user_key,
        max_results=max_results,
        next_page_token=next_page_token,
        start_time=start_time,
        end_time=end_time,
        event_name=event_name,
        actor_ip_address=actor_ip_address,
        filters=filters,
    )
