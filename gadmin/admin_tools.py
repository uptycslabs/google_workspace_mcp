"""
Google Admin MCP Tools

This module provides MCP tools for interacting with Google Admin APIs like Reports API, etc.
"""

import json
import logging
import asyncio
from typing import Literal

from core.server import server
from core.utils import handle_http_errors
from auth.service_decorator import require_google_service

# Configure module logger
logger = logging.getLogger(__name__)

@server.tool()
@handle_http_errors("list_activities", is_read_only=True, service_type='admin')
@require_google_service("admin", "admin_reports_read")
async def list_activities(
    service, 
    user_google_email: str, 
    application_name: Literal['access_transparency', 'admin', 'calendar', 'chat', 'chrome', 'classroom', 'context_aware_access', 'data_studio', 'drive', 'gcp', 'gemini_in_workspace_apps', 'gmail', 'gplus', 'groups', 'groups_enterprise', 'jamboard', 'keep', 'login', 'meet', 'mobile', 'rules', 'saml', 'token', 'user_accounts', 'vault'], 
    user_key: str = "all", 
    max_results: int = 1000, 
    next_page_token: str = None,
    start_time: str = None,
    end_time: str = None,
    customer_id: str = None,
    event_name: str = None,
    actor_ip_address: str = None,
    filters: str = None,
    org_unit_id: str = None,
    group_id_filter: str = None,
) -> str:
    """
        Retrieves audit activity logs for a Google Workspace application (up to 180 days). 
        Use for tracking admin actions, user logins, Drive activity, and other workspace events.

        Args:
            user_google_email (str): The user's Google email address. Required.
            application_name (str): Application to retrieve events for (e.g., 'admin', 'drive', 'login', 'gmail').
            user_key (str): User profile ID or email to filter by, or 'all' for all users. Defaults to 'all'.
            max_results (int): Results per page (max 1000). Defaults to 1000.
            next_page_token (Optional[str]): Token for pagination from previous response.
            start_time (Optional[str]): Start of time range (RFC 3339, e.g., '2024-01-15T10:00:00Z'). Required for Gmail (max 30 days range).
            end_time (Optional[str]): End of time range (RFC 3339). Defaults to current time. Required for Gmail.
            customer_id (Optional[str]): Customer ID to retrieve data for.
            event_name (Optional[str]): Specific event name to filter by.
            actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
            filters (Optional[str]): Event parameter filters (e.g., 'doc_id==12345').
            org_unit_id (Optional[str]): Filter by organizational unit ID. Data before Dec 17, 2018 excluded.
            group_id_filter (Optional[str]): Filter by group IDs (format: 'id:abc123,id:xyz456'). Requires allowlist setup.

        Returns:
            str: JSON with activity records (items), pagination token (nextPageToken), and metadata.
    """
    logger.info(f"[list_activities] Invoked. Email: '{user_google_email}', User Key: '{user_key}', Application: '{application_name}'")

    activities_response = await asyncio.to_thread(
        lambda: service.activities().list(
            userKey=user_key, 
            applicationName=application_name, 
            maxResults=max_results, 
            pageToken=next_page_token,
            startTime=start_time,
            endTime=end_time,
            customerId=customer_id,
            eventName=event_name,
            actorIpAddress=actor_ip_address,
            filters=filters,
            orgUnitID=org_unit_id,
            groupIdFilter=group_id_filter,
        ).execute()
    )

    items = activities_response.get("items", [])

    logger.info(f"Successfully listed {len(items)} activities for user {user_google_email}, User Key: '{user_key}', Application: '{application_name}'.")
    return json.dumps(activities_response)    
