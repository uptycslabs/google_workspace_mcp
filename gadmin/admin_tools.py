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
        event_name (Optional[str]): Specific event name to filter by. Possible values: 'ACCESS'.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Comma-separated event parameter filters.
            Format: '{param}{operator}{value},{param}{operator}{value},...'
            Operators: ==, <> (%3C%3E), < (%3C), <= (%3C=), >, >=.
            Parameters must match event_name; mismatched parameters return empty results.
            Example: 'GSUITE_PRODUCT_NAME==Gmail'.

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
        event_name (Optional[str]): Specific event name to filter by. Possible values:
            'ACCEPT_USER_INVITATION', 'ACTION_CANCELLED', 'ACTION_REQUESTED', 'ADD_APPLICATION',
            'ADD_APPLICATION_TO_WHITELIST', 'ADD_DISPLAY_NAME', 'ADD_DOMAIN_ALIAS',
            'ADD_GROUP_MEMBER', 'ADD_MOBILE_APPLICATION_TO_WHITELIST', 'ADD_MOBILE_CERTIFICATE',
            'ADD_MOBILE_WIRELESS_NETWORK', 'ADD_NICKNAME', 'ADD_PRIVILEGE', 'ADD_RECOVERY_EMAIL',
            'ADD_RECOVERY_PHONE', 'ADD_SECONDARY_DOMAIN', 'ADD_TO_BLOCKED_OAUTH2_APPS',
            'ADD_TO_CAA_EXEMPT_OAUTH2_APPS', 'ADD_TO_LIMITED_OAUTH2_APPS',
            'ADD_TO_TRUSTED_BY_OAUTH_SCOPE_OAUTH2_APPS', 'ADD_TO_TRUSTED_OAUTH2_APPS',
            'ADD_TRUSTED_DOMAINS', 'ADD_WEB_ADDRESS', 'ALERT_RECEIVERS_CHANGED',
            'ALERT_STATUS_CHANGED', 'ALLOW_SERVICE_FOR_OAUTH2_ACCESS',
            'ALLOW_STRONG_AUTHENTICATION', 'APPLE_DEP_SYNC_TRIGGERED',
            'APPLE_DEP_TOKEN_SETUP_COMPLETE', 'APPLE_VPP_TOKEN_OPERATION', 'ARCHIVE_USER',
            'ASSIGN_CUSTOM_LOGO', 'ASSIGN_ROLE', 'AUTHORIZE_API_CLIENT_ACCESS',
            'BLOCK_ALL_THIRD_PARTY_API_ACCESS', 'BLOCK_ON_DEVICE_ACCESS', 'BULK_UPLOAD',
            'BULK_UPLOAD_NOTIFICATION_SENT', 'CANCEL_CALENDAR_EVENTS', 'CANCEL_USER_INVITE',
            'CHANGE_ACCOUNT_AUTO_RENEWAL', 'CHANGE_ADVERTISEMENT_OPTION',
            'CHANGE_ADMIN_RESTRICTIONS_PIN', 'CHANGE_ALERT_CRITERIA',
            'CHANGE_ALLOWED_TWO_STEP_VERIFICATION_METHODS',
            'CHANGE_APP_ACCESS_SETTINGS_COLLECTION_ID', 'CHANGE_APPLICATION_SETTING',
            'CHANGE_CALENDAR_SETTING', 'CHANGE_CAA_APP_ASSIGNMENTS', 'CHANGE_CAA_ERROR_MESSAGE',
            'CHANGE_CHAT_SETTING', 'CHANGE_CHROME_OS_ANDROID_APPLICATION_SETTING',
            'CHANGE_CHROME_OS_APPLICATION_SETTING',
            'CHANGE_CHROME_OS_CUSTOM_CONFIGURATIONS_JSON_SETTING',
            'CHANGE_CHROME_OS_DEVICE_ANNOTATION', 'CHANGE_CHROME_OS_DEVICE_SETTING',
            'CHANGE_CHROME_OS_DEVICE_STATE', 'CHANGE_CHROME_OS_ISOLATED_WEB_APPLICATION_SETTING',
            'CHANGE_CHROME_OS_PUBLIC_SESSION_SETTING', 'CHANGE_CHROME_OS_SETTING',
            'CHANGE_CHROME_OS_USER_SETTING', 'CHANGE_CHROME_OS_WEB_APPLICATION_SETTING',
            'CHANGE_CHROME_OS_WEB_PERMISSION_SETTING', 'CHANGE_CONFLICT_ACCOUNT_ACTION',
            'CHANGE_CONFLICT_ACCOUNTS_MANAGEMENT_SETTINGS', 'CHANGE_CONTACTS_SETTING',
            'CHANGE_CUSTOM_LOGO', 'CHANGE_DATA_LOCALIZATION_FOR_RUSSIA',
            'CHANGE_DATA_LOCALIZATION_SETTING', 'CHANGE_DATA_PROTECTION_OFFICER_CONTACT_INFO',
            'CHANGE_DEVICE_STATE', 'CHANGE_DEVICE_UPGRADE', 'CHANGE_DISPLAY_NAME',
            'CHANGE_DOCS_SETTING', 'CHANGE_DOMAIN_DEFAULT_LOCALE',
            'CHANGE_DOMAIN_DEFAULT_TIMEZONE', 'CHANGE_DOMAIN_NAME',
            'CHANGE_DOMAIN_SUPPORT_MESSAGE', 'CHANGE_EDU_TYPE', 'CHANGE_EMAIL_SETTING',
            'CHANGE_EU_REPRESENTATIVE_CONTACT_INFO', 'CHANGE_FIRST_NAME', 'CHANGE_GMAIL_SETTING',
            'CHANGE_GROUP_DESCRIPTION', 'CHANGE_GROUP_EMAIL', 'CHANGE_GROUP_NAME',
            'CHANGE_GROUP_SETTING', 'CHANGE_LAST_NAME', 'CHANGE_LICENSE_AUTO_ASSIGN',
            'CHANGE_LOGIN_ACTIVITY_TRACE', 'CHANGE_LOGIN_BACKGROUND_COLOR',
            'CHANGE_LOGIN_BORDER_COLOR', 'CHANGE_MOBILE_APPLICATION_PERMISSION_GRANT',
            'CHANGE_MOBILE_APPLICATION_PRIORITY_ORDER', 'CHANGE_MOBILE_APPLICATION_SETTINGS',
            'CHANGE_MOBILE_SETTING', 'CHANGE_MOBILE_WIRELESS_NETWORK',
            'CHANGE_MOBILE_WIRELESS_NETWORK_PASSWORD', 'CHANGE_ORGANIZATION_NAME',
            'CHANGE_PASSWORD', 'CHANGE_PASSWORD_MAX_LENGTH', 'CHANGE_PASSWORD_MIN_LENGTH',
            'CHANGE_PASSWORD_ON_NEXT_LOGIN', 'CHANGE_PRIMARY_DOMAIN', 'CHANGE_RECOVERY_EMAIL',
            'CHANGE_RECOVERY_PHONE', 'CHANGE_RENEW_DOMAIN_REGISTRATION', 'CHANGE_RESELLER_ACCESS',
            'CHANGE_RESELLER_ACCESS_FOR_SKU', 'CHANGE_RULE_CRITERIA', 'CHANGE_SESSION_LENGTH',
            'CHANGE_SITES_SETTING', 'CHANGE_SITES_WEB_ADDRESS_MAPPING_UPDATES',
            'CHANGE_SSO_SETTINGS', 'CHANGE_TWO_STEP_VERIFICATION_ENROLLMENT_PERIOD_DURATION',
            'CHANGE_TWO_STEP_VERIFICATION_FREQUENCY',
            'CHANGE_TWO_STEP_VERIFICATION_GRACE_PERIOD_DURATION',
            'CHANGE_TWO_STEP_VERIFICATION_START_DATE', 'CHANGE_USER_ADDRESS',
            'CHANGE_USER_CUSTOM_FIELD', 'CHANGE_USER_EXTERNAL_ID', 'CHANGE_USER_GENDER',
            'CHANGE_USER_IM', 'CHANGE_USER_KEYWORD', 'CHANGE_USER_LANGUAGE',
            'CHANGE_USER_LOCATION', 'CHANGE_USER_ORGANIZATION', 'CHANGE_USER_PHONE_NUMBER',
            'CHANGE_USER_RELATION', 'CHANGE_WHITELIST_SETTING', 'CHROME_APP_LICENSES_ENABLED',
            'CHROME_APP_USER_LICENSE_ASSIGNED', 'CHROME_APP_USER_LICENSE_REVOKED',
            'CHROME_APPLICATION_LICENSE_RESERVATION_CREATED',
            'CHROME_APPLICATION_LICENSE_RESERVATION_DELETED',
            'CHROME_APPLICATION_LICENSE_RESERVATION_UPDATED', 'CHROME_LICENSES_ALLOWED',
            'CHROME_LICENSES_ENABLED', 'CHROME_LICENSES_REDEEMED',
            'COMMUNICATION_PREFERENCES_SETTING_CHANGE', 'COMPANY_DEVICE_DELETION',
            'COMPANY_DEVICES_BULK_CREATION', 'COMPANY_OWNED_DEVICE_BLOCKED',
            'COMPANY_OWNED_DEVICE_UNBLOCKED', 'COMPANY_OWNED_DEVICE_WIPED', 'CREATE_ALERT',
            'CREATE_APPLICATION_SETTING', 'CREATE_BUILDING', 'CREATE_CALENDAR_RESOURCE',
            'CREATE_CALENDAR_RESOURCE_FEATURE', 'CREATE_CHROME_OS_ENROLLMENT_TOKEN',
            'CREATE_DATA_TRANSFER_REQUEST', 'CREATE_DEVICE_ENROLLMENT_TOKEN',
            'CREATE_EMAIL_MONITOR', 'CREATE_ENROLLMENT_TOKEN', 'CREATE_GMAIL_SETTING',
            'CREATE_GROUP', 'CREATE_MANAGED_CONFIGURATION', 'CREATE_ORG_UNIT',
            'CREATE_PLAY_FOR_WORK_TOKEN', 'CREATE_ROLE', 'CREATE_RULE', 'CREATE_USER',
            'CUSTOMER_USER_DEVICE_DELETION_EVENT', 'DELETE_2SV_SCRATCH_CODES',
            'DELETE_ACCOUNT_INFO_DUMP', 'DELETE_ALERT', 'DELETE_APPLICATION_SETTING',
            'DELETE_BUILDING', 'DELETE_CALENDAR_RESOURCE', 'DELETE_CALENDAR_RESOURCE_FEATURE',
            'DELETE_CHROME_OS_DEVICE', 'DELETE_CHROME_OS_PRINT_SERVER', 'DELETE_CHROME_OS_PRINTER',
            'DELETE_DUPLICATE_CHROME_OS_DEVICE', 'DELETE_EMAIL_MONITOR', 'DELETE_GMAIL_SETTING',
            'DELETE_GROUP', 'DELETE_MAILBOX_DUMP', 'DELETE_MANAGED_CONFIGURATION',
            'DELETE_PLAY_FOR_WORK_TOKEN', 'DELETE_PROFILE_PHOTO', 'DELETE_ROLE', 'DELETE_RULE',
            'DELETE_USER', 'DELETE_WEB_ADDRESS', 'DISALLOW_SERVICE_FOR_OAUTH2_ACCESS',
            'DOCS_ORG_BRANDING_PROVISIONING', 'DOCS_ORG_BRANDING_UPLOAD',
            'DOWNLOAD_PENDING_APP_USER_REQUESTS', 'DOWNLOAD_PENDING_INVITES_LIST',
            'DOWNLOAD_UNMANAGED_USERS_LIST', 'DOWNLOAD_USERLIST', 'DOWNLOAD_USERLIST_CSV',
            'DOWNGRADE_USER_FROM_GPLUS', 'DRIVE_DATA_RESTORE', 'DROP_FROM_QUARANTINE',
            'EDIT_ORG_UNIT_DESCRIPTION', 'EDIT_ORG_UNIT_NAME',
            'EDU_DELEGATED_USER_APPROVAL_WORKFLOW_DISABLED',
            'EDU_DELEGATED_USER_APPROVAL_WORKFLOW_ENABLED',
            'EDU_OVER_18_APPROVAL_WORKFLOW_DISABLED', 'EDU_OVER_18_APPROVAL_WORKFLOW_ENABLED',
            'EMAIL_LIFE_OF_A_MESSAGE', 'EMAIL_LOG_SEARCH', 'EMAIL_UNDELETE', 'ENABLE_API_ACCESS',
            'ENABLE_FEEDBACK_SOLICITATION', 'ENABLE_NON_ADMIN_USER_PASSWORD_RECOVERY',
            'ENABLE_SERVICE_OR_FEATURE_NOTIFICATIONS', 'ENABLE_USER_IP_WHITELIST',
            'ENROLL_FOR_GOOGLE_DEVICE_MANAGEMENT', 'ENFORCE_STRONG_AUTHENTICATION',
            'EWS_IN_NEW_CREDENTIALS_GENERATED', 'EWS_OUT_ENDPOINT_CONFIGURATION_CHANGED',
            'EWS_OUT_ENDPOINT_CONFIGURATION_RESET',
            'FIRST_TEMPORARY_OR_SUPPRESSED_LICENSE_NOTIFICATION',
            'FLASHLIGHT_EDU_NON_FEATURED_SERVICES_SELECTED', 'GENERATE_2SV_SCRATCH_CODES',
            'GENERATE_PIN', 'GENERATE_TRANSFER_TOKEN', 'GMAIL_RESET_USER',
            'GPLUS_PREMIUM_FEATURES', 'GRANT_ADMIN_PRIVILEGE', 'GRANT_DELEGATED_ADMIN_PRIVILEGES',
            'GROUP_LIST_DOWNLOAD', 'GROUP_MEMBER_BULK_UPLOAD', 'GROUP_MEMBERS_DOWNLOAD',
            'INSERT_CHROME_OS_PRINT_SERVER', 'INSERT_CHROME_OS_PRINTER', 'ISSUE_DEVICE_COMMAND',
            'MAIL_ROUTING_DESTINATION_ADDED', 'MAIL_ROUTING_DESTINATION_REMOVED',
            'MEET_INTEROP_CREATE_GATEWAY', 'MEET_INTEROP_DELETE_GATEWAY',
            'MEET_INTEROP_MODIFY_GATEWAY', 'MOBILE_ACCOUNT_WIPE', 'MOBILE_DEVICE_APPROVE',
            'MOBILE_DEVICE_BLOCK', 'MOBILE_DEVICE_CANCEL_WIPE_THEN_APPROVE',
            'MOBILE_DEVICE_CANCEL_WIPE_THEN_BLOCK', 'MOBILE_DEVICE_DELETE', 'MOBILE_DEVICE_WIPE',
            'MOVE_DEVICE_TO_ORG_UNIT_DETAILED', 'MOVE_ORG_UNIT', 'MOVE_SHARED_DRIVE_TO_ORG_UNIT',
            'MOVE_USER_TO_ORG_UNIT', 'MULTIPLE_ADD_TO_BLOCKED_OAUTH2_APPS',
            'MULTIPLE_ADD_TO_LIMITED_OAUTH2_APPS',
            'MULTIPLE_ADD_TO_TRUSTED_BY_OAUTH_SCOPE_OAUTH2_APPS',
            'MULTIPLE_ADD_TO_TRUSTED_OAUTH2_APPS', 'MX_RECORD_VERIFICATION_CLAIM',
            'OAUTH_APPS_BULK_UPLOAD', 'OAUTH_APPS_BULK_UPLOAD_NOTIFICATION_SENT',
            'ORG_ALL_USERS_LICENSE_ASSIGNMENT', 'ORG_LICENSE_REVOKE',
            'ORG_USERS_LICENSE_ASSIGNMENT', 'PASSKEY_REVOKED', 'PLAY_FOR_WORK_ENROLL',
            'PLAY_FOR_WORK_UNENROLL', 'PRE_PROVISION_CHROME_OS_DEVICE',
            'REGENERATE_OAUTH_CONSUMER_SECRET', 'REJECT_FROM_QUARANTINE',
            'RELEASE_CALENDAR_RESOURCES', 'RELEASE_FROM_QUARANTINE', 'REMOVE_APPLICATION',
            'REMOVE_APPLICATION_FROM_WHITELIST', 'REMOVE_CHROME_OS_APPLICATION_SETTING',
            'REMOVE_CHROME_OS_APPLICATION_SETTINGS', 'REMOVE_CHROME_OS_WEB_ORIGIN_SETTINGS',
            'REMOVE_DISPLAY_NAME', 'REMOVE_DOMAIN_ALIAS', 'REMOVE_FROM_BLOCKED_OAUTH2_APPS',
            'REMOVE_FROM_CAA_EXEMPT_OAUTH2_APPS', 'REMOVE_FROM_LIMITED_OAUTH2_APPS',
            'REMOVE_FROM_TRUSTED_BY_OAUTH_SCOPE_OAUTH2_APPS', 'REMOVE_FROM_TRUSTED_OAUTH2_APPS',
            'REMOVE_GROUP_MEMBER', 'REMOVE_MOBILE_APPLICATION_FROM_WHITELIST',
            'REMOVE_MOBILE_CERTIFICATE', 'REMOVE_MOBILE_WIRELESS_NETWORK', 'REMOVE_NICKNAME',
            'REMOVE_ORG_UNIT', 'REMOVE_PRIVILEGE', 'REMOVE_RECOVERY_EMAIL',
            'REMOVE_RECOVERY_PHONE', 'REMOVE_SECONDARY_DOMAIN', 'REMOVE_TRUSTED_DOMAINS',
            'RENAME_ALERT', 'RENAME_CALENDAR_RESOURCE', 'RENAME_ROLE', 'RENAME_RULE',
            'RENAME_USER', 'REORDER_GROUP_BASED_POLICIES_EVENT', 'REPAIR_CENTER_DEPROVISION',
            'REQUEST_ACCOUNT_INFO', 'REQUEST_MAILBOX_DUMP',
            'RESELLER_FIRST_TEMPORARY_OR_SUPPRESSED_LICENSE_NOTIFICATION',
            'RESELLER_TEMPORARY_LICENSES_EXPIRED_NOTIFICATION', 'RESEND_USER_INVITE',
            'RESET_SIGNIN_COOKIES', 'REVOKE_3LO_DEVICE_TOKENS', 'REVOKE_3LO_TOKEN',
            'REVOKE_ADMIN_PRIVILEGE', 'REVOKE_ASP', 'REVOKE_CHROME_OS_ENROLLMENT_TOKEN',
            'REVOKE_DEVICE_ENROLLMENT_TOKEN', 'REVOKE_ENROLLMENT_TOKEN', 'REVOKE_SECURITY_KEY',
            'RULE_ACTIONS_CHANGED', 'RULE_STATUS_CHANGED', 'SECURITY_KEY_REGISTERED_FOR_USER',
            'SEND_CHROME_OS_DEVICE_COMMAND', 'SESSION_CONTROL_SETTINGS_CHANGE',
            'SIGN_IN_ONLY_THIRD_PARTY_API_ACCESS', 'SKIP_DOMAIN_ALIAS_MX',
            'SKIP_SECONDARY_DOMAIN_MX', 'SUPPRESSED_LICENSE_ASSIGNMENT',
            'SUPPRESSED_LICENSE_REVOKE', 'SUPPRESSED_TO_ASSIGNED_LICENSE_CONVERSION',
            'SUSPEND_USER', 'TEMPORARY_LICENSE_ASSIGNMENT', 'TEMPORARY_LICENSE_REVOKE',
            'TEMPORARY_LICENSES_EXPIRED_NOTIFICATION', 'TEMPORARY_TO_ASSIGNED_LICENSE_CONVERSION',
            'TEMPORARY_TO_SUPPRESSED_LICENSE_CONVERSION', 'TOGGLE_ALLOW_ADMIN_PASSWORD_RESET',
            'TOGGLE_AUTO_ADD_NEW_SERVICE', 'TOGGLE_AUTOMATIC_CONTACT_SHARING',
            'TOGGLE_CAA_ENABLEMENT', 'TOGGLE_CAA_REMEDIATION_ENABLEMENT', 'TOGGLE_CONTACT_SHARING',
            'TOGGLE_ENABLE_OAUTH_CONSUMER_KEY', 'TOGGLE_ENABLE_PRE_RELEASE_FEATURES',
            'TOGGLE_NEW_APP_FEATURES', 'TOGGLE_OAUTH_ACCESS_TO_ALL_APIS', 'TOGGLE_OPEN_ID_ENABLED',
            'TOGGLE_OUTBOUND_RELAY', 'TOGGLE_SERVICE_ENABLED', 'TOGGLE_SSO_ENABLED', 'TOGGLE_SSL',
            'TOGGLE_USE_CUSTOM_LOGO', 'TOGGLE_USE_NEXT_GEN_CONTROL_PANEL',
            'TRANSFER_DOCUMENT_OWNERSHIP', 'TRUST_DOMAIN_OWNED_OAUTH2_APPS',
            'TURN_OFF_2_STEP_VERIFICATION', 'UNARCHIVE_USER', 'UNASSIGN_CUSTOM_LOGO',
            'UNASSIGN_ROLE', 'UNBLOCK_ALL_THIRD_PARTY_API_ACCESS', 'UNBLOCK_ON_DEVICE_ACCESS',
            'UNBLOCK_USER_SESSION', 'UNDERAGE_BLOCK_ALL_THIRD_PARTY_API_ACCESS',
            'UNDERAGE_SIGN_IN_ONLY_THIRD_PARTY_API_ACCESS',
            'UNDERAGE_USER_APPROVAL_WORKFLOW_DISABLED', 'UNDERAGE_USER_APPROVAL_WORKFLOW_ENABLED',
            'UNDELETE_USER', 'UNENROLL_USER_FROM_STRONG_AUTH', 'UNENROLL_USER_FROM_TITANIUM',
            'UNMANAGED_USERS_BULK_UPLOAD', 'UNSUSPEND_USER', 'UNTRUST_DOMAIN_OWNED_OAUTH2_APPS',
            'UPDATE_BIRTHDATE', 'UPDATE_BUILDING', 'UPDATE_CALENDAR_RESOURCE',
            'UPDATE_CALENDAR_RESOURCE_FEATURE', 'UPDATE_CHROME_OS_PRINT_SERVER',
            'UPDATE_CHROME_OS_PRINTER', 'UPDATE_DEVICE', 'UPDATE_DOMAIN_PRIMARY_ADMIN_EMAIL',
            'UPDATE_DOMAIN_SECONDARY_EMAIL', 'UPDATE_DYNAMIC_LICENSE',
            'UPDATE_ERROR_MSG_FOR_RESTRICTED_OAUTH2_APPS', 'UPDATE_GROUP_MEMBER',
            'UPDATE_GROUP_MEMBER_DELIVERY_SETTINGS',
            'UPDATE_GROUP_MEMBER_DELIVERY_SETTINGS_CAN_EMAIL_OVERRIDE',
            'UPDATE_MANAGED_CONFIGURATION', 'UPDATE_PROFILE_PHOTO',
            'UPDATE_PUBLIC_KEY_CERTIFICATE', 'UPDATE_PUBLIC_KEY_CERTIFICATE_STATUS', 'UPDATE_ROLE',
            'UPDATE_RULE', 'UPDATE_SMART_FEATURES', 'UPGRADE_USER_TO_GPLUS',
            'USE_GOOGLE_MOBILE_MANAGEMENT', 'USE_GOOGLE_MOBILE_MANAGEMENT_FOR_IOS',
            'USE_GOOGLE_MOBILE_MANAGEMENT_FOR_NON_IOS', 'USER_APPROVAL_WORKFLOW_DISABLED',
            'USER_APPROVAL_WORKFLOW_ENABLED', 'USER_CREATED_PASSKEY_REVOKE',
            'USER_ENROLLED_IN_TWO_STEP_VERIFICATION', 'USER_INVITE', 'USER_LICENSE_ASSIGNMENT',
            'USER_LICENSE_REASSIGNMENT', 'USER_LICENSE_REVOKE',
            'USER_PUT_IN_TWO_STEP_VERIFICATION_GRACE_PERIOD', 'USERS_BULK_UPLOAD',
            'USERS_BULK_UPLOAD_NOTIFICATION_SENT', 'VERIFY_DOMAIN_ALIAS', 'VERIFY_DOMAIN_ALIAS_MX',
            'VERIFY_SECONDARY_DOMAIN', 'VERIFY_SECONDARY_DOMAIN_MX', 'VIEW_DNS_LOGIN_DETAILS',
            'VIEW_SITE_DETAILS', 'VIEW_TEMP_PASSWORD', 'WEAK_PROGRAMMATIC_LOGIN_SETTINGS_CHANGED',
            'WHITELISTED_GROUPS_UPDATED'.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Comma-separated event parameter filters.
            Format: '{param}{operator}{value},{param}{operator}{value},...'
            Operators: ==, <> (%3C%3E), < (%3C), <= (%3C=), >, >=.
            Parameters must match event_name; mismatched parameters return empty results.
            Example: 'USER_EMAIL==admin@example.com'.

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
        event_name (Optional[str]): Specific event name to filter by. Possible values:
            'change_calendar_acls', 'change_calendar_country', 'create_calendar',
            'delete_calendar', 'change_calendar_description', 'export_calendar',
            'change_calendar_location', 'print_preview_calendar', 'change_calendar_timezone',
            'change_calendar_title', 'notification_triggered', 'add_subscription',
            'delete_subscription', 'change_appointment_schedule', 'create_appointment_schedule',
            'delete_appointment_schedule', 'create_event', 'delete_event', 'add_event_guest',
            'change_event_guest_response_auto', 'remove_event_guest', 'change_event_guest_response'.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Comma-separated event parameter filters.
            Format: '{param}{operator}{value},{param}{operator}{value},...'
            Operators: ==, <> (%3C%3E), < (%3C), <= (%3C=), >, >=.
            Parameters must match event_name; mismatched parameters return empty results.
            Example: 'calendar_id==user@example.com'.

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
        event_name (Optional[str]): Specific event name to filter by. Possible values:
            'add_room_member', 'app_added', 'app_invoked', 'app_removed', 'attachment_download',
            'attachment_upload', 'block_room', 'block_user', 'conversation_read',
            'custom_status_updated', 'direct_message_started', 'emoji_created', 'emoji_deleted',
            'history_turned_off', 'history_turned_on', 'invite_accept', 'invite_decline',
            'invite_send', 'message_deleted', 'message_edited', 'message_posted',
            'message_report_resolved', 'message_reported', 'reaction_added', 'reaction_removed',
            'remove_room_member', 'role_updated', 'room_created', 'room_deleted',
            'room_details_updated', 'room_left', 'room_name_updated', 'room_unblocked',
            'unread_timestamp_updated', 'user_unblocked'.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Comma-separated event parameter filters.
            Format: '{param}{operator}{value},{param}{operator}{value},...'
            Operators: ==, <> (%3C%3E), < (%3C), <= (%3C=), >, >=.
            Parameters must match event_name; mismatched parameters return empty results.
            Example: 'room_id==spaces/ABCDEF'.

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
        event_name (Optional[str]): Specific event name to filter by. Possible values:
            'CHROME_OS_ADD_USER', 'CHROME_OS_REMOVE_USER', 'DEVICE_BOOT_STATE_CHANGE',
            'CHROME_OS_LOGIN_FAILURE_EVENT', 'CHROME_OS_LOGIN_LOGOUT_EVENT',
            'CHROME_OS_LOGIN_EVENT', 'CHROME_OS_LOGOUT_EVENT', 'CHROME_OS_REPORTING_DATA_LOST',
            'PASSWORD_CHANGED', 'PASSWORD_REUSE', 'DLP_EVENT'.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Comma-separated event parameter filters.
            Format: '{param}{operator}{value},{param}{operator}{value},...'
            Operators: ==, <> (%3C%3E), < (%3C), <= (%3C=), >, >=.
            Parameters must match event_name; mismatched parameters return empty results.
            Example: 'DEVICE_ID==ABC123'.

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
        event_name (Optional[str]): Specific event name to filter by. Possible values:
            'created_add_on_attachment', 'deleted_add_on_attachment',
            'updated_add_on_attachment_submission_grade', 'updated_add_on_attachment',
            'published_announcement', 'updated_announcement', 'commented_announcement',
            'commented_course_work', 'commented_submission_private', 'commented_submission_public',
            'published_course_work', 'updated_course_work', 'set_draft_grade', 'unset_draft_grade',
            'set_grade', 'unset_grade', 'created_rubric_for_course_work', 'scored_rubric',
            'changed_submission_state', 'user_added_to_course',
            'user_gained_preview_access_to_course', 'user_invited_to_course', 'user_joined_course',
            'user_removed_from_course', 'archived_course', 'created_course', 'deleted_course',
            'created_course_quick_link', 'deleted_course_quick_link', 'edited_course_quick_link',
            'restored_course', 'created_grade_category', 'deleted_grade_category',
            'edited_grade_category', 'new_user_owns_course',
            'share_classwork_settings_updated_for_course', 'transferred_ownership_of_course',
            'user_invited_to_own_course', 'grade_export_for_course_work',
            'grade_export_for_submission', 'guardian_summaries_settings_updated_for_teacher',
            'default_guardian_summaries_settings_updated_for_teacher',
            'guardian_invited_for_student', 'guardian_removed_for_student',
            'guardian_responded_to_invite', 'guardian_summaries_settings_updated_for_course',
            'guardian_updated_email', 'originality_report_created'.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Comma-separated event parameter filters.
            Format: '{param}{operator}{value},{param}{operator}{value},...'
            Operators: ==, <> (%3C%3E), < (%3C), <= (%3C=), >, >=.
            Parameters must match event_name; mismatched parameters return empty results.
            Example: 'course_id==123456789'.

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
        event_name (Optional[str]): Specific event name to filter by. Possible values:
            'ACCESS_DENY_EVENT', 'ACCESS_DENY_INTERNAL_ERROR_EVENT'.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Comma-separated event parameter filters.
            Format: '{param}{operator}{value},{param}{operator}{value},...'
            Operators: ==, <> (%3C%3E), < (%3C), <= (%3C=), >, >=.
            Parameters must match event_name; mismatched parameters return empty results.
            Example: 'CAA_APPLICATION==Gmail'.

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
        event_name (Optional[str]): Specific event name to filter by. Possible values:
            'ADD_REPORT_EMAIL_DELIVERY', 'CREATE', 'DATA_EXPORT', 'DELETE', 'DOWNLOAD_REPORT',
            'EDIT', 'PARENT_WORKSPACE_CHANGE', 'RESTORE', 'STOP_REPORT_EMAIL_DELIVERY', 'TRASH',
            'UPDATE_REPORT_EMAIL_DELIVERY', 'VIEW', 'CHANGE_DATA_SOURCE_ACCESS_TYPE',
            'CHANGE_ASSET_LINK_SHARING_ACCESS_TYPE', 'CHANGE_ASSET_LINK_SHARING_VISIBILITY',
            'CHANGE_USER_ACCESS', 'CHANGE_USER_ACCESS_TO_ASSET_VIA_WORKSPACE'.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Comma-separated event parameter filters.
            Format: '{param}{operator}{value},{param}{operator}{value},...'
            Operators: ==, <> (%3C%3E), < (%3C), <= (%3C=), >, >=.
            Parameters must match event_name; mismatched parameters return empty results.
            Example: 'ASSET_ID==abc123'.

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
        event_name (Optional[str]): Specific event name to filter by. Possible values:
            'deny_access_request', 'expire_access_request', 'request_access', 'add_to_folder',
            'appeal_abuse_violation', 'approval_canceled', 'approval_comment_added',
            'approval_completed', 'approval_decisions_reset', 'approval_due_time_change',
            'approval_requested', 'approval_reviewer_change', 'approval_reviewer_responded',
            'create_comment', 'delete_comment', 'edit_comment', 'reassign_comment',
            'reopen_comment', 'resolve_comment', 'connected_sheets_query', 'copy', 'create',
            'delete', 'download', 'email_as_attachment', 'edit', 'email_collaborators', 'encrypt',
            'cancel_esignature', 'complete_esignature', 'request_esignature', 'review_esignature',
            'download_forms_response', 'access_item_content', 'prefetch_item_content',
            'sync_item_content', 'search', 'label_added', 'label_added_by_item_create',
            'label_field_changed', 'label_removed', 'add_lock', 'move', 'preview', 'print',
            'remove_from_folder', 'rename', 'report_abuse', 'untrash', 'delete_revision',
            'pin_revision', 'unpin_revision', 'create_script_trigger', 'delete_script_trigger',
            'sheets_import_url', 'sheets_import_range', 'source_copy', 'accept_suggestion',
            'create_suggestion', 'delete_suggestion', 'reject_suggestion', 'pause_sync_client',
            'resume_sync_client', 'trash', 'remove_lock', 'unmovable_item_reparented', 'upload',
            'access_url', 'delete_video_caption', 'download_video_caption', 'upload_video_caption',
            'view', 'apply_security_update', 'shared_drive_apply_security_update',
            'shared_drive_remove_security_update', 'change_owner_hierarchy_reconciled',
            'change_owner', 'publish_change', 'change_acl_editors',
            'disable_inherited_permissions', 'enable_inherited_permissions',
            'change_document_access_scope', 'change_document_access_scope_hierarchy_reconciled',
            'change_document_visibility', 'change_document_visibility_hierarchy_reconciled',
            'publish_new_version', 'remove_security_update', 'shared_drive_membership_change',
            'shared_drive_settings_change', 'sheets_import_range_access_change',
            'change_user_access', 'change_user_access_hierarchy_reconciled', 'storage_usage_update'.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Comma-separated event parameter filters.
            Format: '{param}{operator}{value},{param}{operator}{value},...'
            Operators: ==, <> (%3C%3E), < (%3C), <= (%3C=), >, >=.
            Parameters must match event_name; mismatched parameters return empty results.
            Example: 'doc_id==12345' or 'doc_id%3C%3E98765'.

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
        event_name (Optional[str]): Specific event name to filter by. Possible values:
            'IMPORT_SSH_PUBLIC_KEY', 'DELETE_POSIX_ACCOUNT', 'DELETE_SSH_PUBLIC_KEY',
            'GET_SSH_PUBLIC_KEY', 'GET_LOGIN_PROFILE', 'UPDATE_SSH_PUBLIC_KEY'.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Comma-separated event parameter filters.
            Format: '{param}{operator}{value},{param}{operator}{value},...'
            Operators: ==, <> (%3C%3E), < (%3C), <= (%3C=), >, >=.
            Parameters must match event_name; mismatched parameters return empty results.
            Example: 'USER_EMAIL==user@example.com'.

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
        event_name (Optional[str]): Specific event name to filter by. Possible values: 'feature_utilization'.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Comma-separated event parameter filters.
            Format: '{param}{operator}{value},{param}{operator}{value},...'
            Operators: ==, <> (%3C%3E), < (%3C), <= (%3C=), >, >=.
            Parameters must match event_name; mismatched parameters return empty results.
            Example: 'app_name==docs'.

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
        event_name (Optional[str]): Specific event name to filter by. Possible values: 'delivery'.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Comma-separated event parameter filters.
            Format: '{param}{operator}{value},{param}{operator}{value},...'
            Operators: ==, <> (%3C%3E), < (%3C), <= (%3C=), >, >=.
            Parameters must match event_name; mismatched parameters return empty results.
            Example: 'event_info.mail_event_type==1'.

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
        event_name (Optional[str]): Specific event name to filter by. Possible values:
            'create_comment', 'delete_comment', 'edit_comment', 'add_plusone', 'remove_plusone',
            'add_poll_vote', 'remove_poll_vote', 'create_post', 'delete_post',
            'content_manager_delete_post', 'edit_post'.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Comma-separated event parameter filters.
            Format: '{param}{operator}{value},{param}{operator}{value},...'
            Operators: ==, <> (%3C%3E), < (%3C), <= (%3C=), >, >=.
            Parameters must match event_name; mismatched parameters return empty results.
            Example: 'post_resource_name==posts/abc123'.

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
        event_name (Optional[str]): Specific event name to filter by. Possible values:
            'change_acl_permission', 'accept_invitation', 'approve_join_request', 'join',
            'join_via_mail', 'request_to_join', 'request_to_join_via_mail', 'change_basic_setting',
            'create_group', 'delete_group', 'change_email_subscription_type',
            'change_identity_setting', 'add_info_setting', 'change_info_setting',
            'remove_info_setting', 'change_new_members_restrictions_setting',
            'change_post_replies_setting', 'change_spam_moderation_setting',
            'change_topic_setting', 'moderate_message', 'always_post_from_user', 'add_user',
            'ban_user_with_moderation', 'revoke_invitation', 'invite_user', 'reject_join_request',
            'reinvite_user', 'remove_user', 'unsubscribe_via_mail'.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Comma-separated event parameter filters.
            Format: '{param}{operator}{value},{param}{operator}{value},...'
            Operators: ==, <> (%3C%3E), < (%3C), <= (%3C=), >, >=.
            Parameters must match event_name; mismatched parameters return empty results.
            Example: 'group_email==mygroup@example.com'.

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
        event_name (Optional[str]): Specific event name to filter by. Possible values:
            'accept_invitation', 'add_info_setting', 'add_member', 'add_member_role',
            'add_security_setting', 'add_service_account_permission', 'approve_join_request',
            'ban_member_with_moderation', 'change_info_setting', 'change_security_setting',
            'change_security_setting_state', 'create_group', 'create_namespace', 'delete_group',
            'delete_namespace', 'add_dynamic_group_query', 'change_dynamic_group_query',
            'invite_member', 'join', 'add_membership_expiry', 'remove_membership_expiry',
            'update_membership_expiry', 'reject_invitation', 'reject_join_request',
            'remove_info_setting', 'remove_member', 'remove_member_role',
            'remove_security_setting', 'remove_service_account_permission', 'request_to_join',
            'revoke_invitation', 'unban_member'.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Comma-separated event parameter filters.
            Format: '{param}{operator}{value},{param}{operator}{value},...'
            Operators: ==, <> (%3C%3E), < (%3C), <= (%3C=), >, >=.
            Parameters must match event_name; mismatched parameters return empty results.
            Example: 'member_role==MEMBER'.

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
        filters (Optional[str]): Comma-separated event parameter filters.
            Format: '{param}{operator}{value},{param}{operator}{value},...'
            Operators: ==, <> (%3C%3E), < (%3C), <= (%3C=), >, >=.
            Parameters must match event_name; mismatched parameters return empty results.
            Example: 'device_id==ABC123456'.

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
        event_name (Optional[str]): Specific event name to filter by. Possible values:
            'deleted_attachment', 'uploaded_attachment', 'edited_note_content', 'created_note',
            'deleted_note', 'modified_acl'.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Comma-separated event parameter filters.
            Format: '{param}{operator}{value},{param}{operator}{value},...'
            Operators: ==, <> (%3C%3E), < (%3C), <= (%3C=), >, >=.
            Valid parameters: 'owner_email' (all events), 'note_name' (all events),
            'attachment_name' (deleted_attachment, uploaded_attachment events only).
            Parameters must match event_name; mismatched parameters return empty results.
            Example: 'owner_email==user@example.com' or 'note_name==My Note'.

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
        event_name (Optional[str]): Specific event name to filter by. Possible values:
            '2sv_disable', '2sv_enroll', 'password_edit', 'recovery_email_edit',
            'recovery_phone_edit', 'recovery_secret_qa_edit', 'account_disabled_password_leak',
            'passkey_enrolled', 'passkey_removed', 'suspicious_login',
            'suspicious_login_less_secure_app', 'suspicious_programmatic_login',
            'user_signed_out_due_to_suspicious_session_cookie', 'account_disabled_generic',
            'account_disabled_spamming_through_relay', 'account_disabled_spamming',
            'account_disabled_hijacked', 'titanium_enroll', 'titanium_unenroll',
            'gov_attack_warning', 'blocked_sender', 'email_forwarding_out_of_domain',
            'login_failure', 'login_challenge', 'login_verification', 'logout',
            'risky_sensitive_action_allowed', 'risky_sensitive_action_blocked', 'login_success'.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Comma-separated event parameter filters.
            Format: '{param}{operator}{value},{param}{operator}{value},...'
            Operators: ==, <> (%3C%3E), < (%3C), <= (%3C=), >, >=.
            Parameters must match event_name; mismatched parameters return empty results.
            Example: 'login_type==google_password'.

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
        event_name (Optional[str]): Specific event name to filter by. Possible values:
            'abuse_report_submitted', 'broadcast_activity', 'call_ended', 'livestream_watched',
            'dialed_out', 'send_chat_everyone', 'in_meet_broadcast_activity', 'see_chat_everyone',
            'see_chat_participants', 'invitation_sent', 'knocking_accepted', 'knocking_denied',
            'send_chat_contributors', 'send_chat_hosts', 'poll_answered', 'poll_created',
            'presentation_started', 'presentation_stopped', 'question_created',
            'question_responded', 'recording_activity', 'ring_answered', 'ring_missed',
            'ring_sent', 'transcription_activity', 'watermarking_active', 'watermarking_starting',
            'watermarking_stopped'.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Comma-separated event parameter filters.
            Format: '{param}{operator}{value},{param}{operator}{value},...'
            Operators: ==, <> (%3C%3E), < (%3C), <= (%3C=), >, >=.
            Parameters must match event_name; mismatched parameters return empty results.
            Example: 'conference_id==abc-defg-hij'.

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
        event_name (Optional[str]): Specific event name to filter by. Possible values:
            'APPLICATION_EVENT', 'APPLICATION_REPORT_EVENT', 'DEVICE_REGISTER_UNREGISTER_EVENT',
            'ADVANCED_POLICY_SYNC_EVENT', 'DEVICE_ACTION_EVENT', 'DEVICE_COMPLIANCE_CHANGED_EVENT',
            'OS_UPDATED_EVENT', 'DEVICE_OWNERSHIP_CHANGE_EVENT', 'DEVICE_SETTINGS_UPDATED_EVENT',
            'APPLE_DEP_DEVICE_UPDATE_ON_APPLE_PORTAL_EVENT', 'DEVICE_SYNC_EVENT',
            'RISK_SIGNAL_UPDATED_EVENT', 'ANDROID_WORK_PROFILE_SUPPORT_ENABLED_EVENT',
            'DEVICE_COMPROMISED_EVENT', 'FAILED_PASSWORD_ATTEMPTS_EVENT',
            'SUSPICIOUS_ACTIVITY_EVENT'.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Comma-separated event parameter filters.
            Format: '{param}{operator}{value},{param}{operator}{value},...'
            Operators: ==, <> (%3C%3E), < (%3C), <= (%3C=), >, >=.
            Parameters must match event_name; mismatched parameters return empty results.
            Example: 'DEVICE_TYPE==ANDROID'.

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
        event_name (Optional[str]): Specific event name to filter by. Possible values:
            'action_complete', 'label_applied', 'label_field_value_changed', 'label_removed',
            'rule_match', 'rule_trigger'.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Comma-separated event parameter filters.
            Format: '{param}{operator}{value},{param}{operator}{value},...'
            Operators: ==, <> (%3C%3E), < (%3C), <= (%3C=), >, >=.
            Parameters must match event_name; mismatched parameters return empty results.
            Example: 'rule_name==my-dlp-rule'.

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
        event_name (Optional[str]): Specific event name to filter by. Possible values:
            'login_failure', 'login_success'.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Comma-separated event parameter filters.
            Format: '{param}{operator}{value},{param}{operator}{value},...'
            Operators: ==, <> (%3C%3E), < (%3C), <= (%3C=), >, >=.
            Parameters must match event_name; mismatched parameters return empty results.
            Example: 'application_name==MyApp'.

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
        event_name (Optional[str]): Specific event name to filter by. Possible values:
            'activity', 'authorize', 'request', 'revoke'.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Comma-separated event parameter filters.
            Format: '{param}{operator}{value},{param}{operator}{value},...'
            Operators: ==, <> (%3C%3E), < (%3C), <= (%3C=), >, >=.
            Valid parameters (all events): 'app_name', 'client_id', 'client_type'.
            Additional parameters for authorize/request/revoke: 'scope', 'scope_data'.
            Additional parameters for activity only: 'api_name', 'method_name'.
            'client_type' values: 'WEB', 'NATIVE_ANDROID', 'NATIVE_DESKTOP',
            'CONNECTED_DEVICE', 'NATIVE_APPLICATION'.
            Parameters must match event_name; mismatched parameters return empty results.
            Example: 'app_name==MyOAuthApp' or 'client_type==WEB'.

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
        event_name (Optional[str]): Specific event name to filter by. Possible values:
            '2sv_disable', '2sv_enroll', 'password_edit', 'recovery_email_edit',
            'recovery_phone_edit', 'recovery_secret_qa_edit', 'titanium_enroll',
            'titanium_unenroll', 'email_forwarding_out_of_domain'.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Not applicable for user_accounts — no filterable event
            parameters are documented for this application. Use 'user_key' to scope by
            user and 'event_name' to scope by event type instead. Note: 'is_suspicious'
            is a login application parameter, not user_accounts.

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
        event_name (Optional[str]): Specific event name to filter by. Possible values:
            'add_collaborator_begin', 'add_collaborator_end', 'add_litigation_hold_begin',
            'add_litigation_hold_end', 'add_preservation_rule_begin', 'add_preservation_rule_end',
            'add_retention_rule_begin', 'add_retention_rule_end',
            'cancel_accelerated_deletion_begin', 'cancel_accelerated_deletion_end',
            'close_investigation_begin', 'close_investigation_end',
            'convert_saved_query_to_collection_begin', 'convert_saved_query_to_collection_end',
            'create_accelerated_deletion_begin', 'create_accelerated_deletion_end',
            'create_export_begin', 'create_export_end', 'create_investigation_begin',
            'create_investigation_end', 'create_saved_query_begin', 'create_saved_query_end',
            'delete_export_begin', 'delete_export_end', 'delete_export_fail',
            'delete_investigation_begin', 'delete_investigation_end',
            'delete_preservation_rule_begin', 'delete_preservation_rule_end',
            'delete_retention_rule_begin', 'delete_retention_rule_end', 'delete_saved_query_begin',
            'delete_saved_query_end', 'deletion_search', 'download_count_per_account_csv',
            'download_cross_matter_litigation_hold_report',
            'download_per_matter_litigation_hold_report', 'export', 'export_file_download',
            'get_count_operation', 'legacy_export_download',
            'modify_default_retention_period_begin', 'modify_default_retention_period_end',
            'obsolete_api_exports_list', 'obsolete_api_holds_insert', 'obsolete_api_holds_list',
            'obsolete_api_matters_delete', 'obsolete_api_matters_get',
            'obsolete_api_matters_insert', 'obsolete_api_matters_list',
            'obsolete_api_matters_update', 'obsolete_preview_retention_rule_count',
            'preview_retention_rule', 'remove_collaborator_begin', 'remove_collaborator_end',
            'remove_litigation_hold_begin', 'remove_litigation_hold_end',
            'reopen_investigation_begin', 'reopen_investigation_end',
            'restore_investigation_begin', 'restore_investigation_end', 'search', 'search_count',
            'update_investigation_details_begin', 'update_investigation_details_end',
            'update_preservation_rule_add_holds_begin', 'update_preservation_rule_add_holds_end',
            'update_preservation_rule_query_begin', 'update_preservation_rule_query_end',
            'update_preservation_rule_remove_holds_begin',
            'update_preservation_rule_remove_holds_end', 'update_retention_rule_begin',
            'update_retention_rule_end', 'update_retention_settings',
            'update_saved_query_details_begin', 'update_saved_query_details_end',
            'view_cross_matter_litigation_hold_report', 'view_custodian_litigation_hold_report',
            'view_document', 'view_document_information', 'view_external_document',
            'view_investigation', 'view_matter_audit_log',
            'view_per_matter_litigation_hold_report', 'view_retention_policy',
            'view_retention_settings', 'view_system_audit_log'.
        actor_ip_address (Optional[str]): Filter by IP address where event occurred (IPv4/IPv6).
        filters (Optional[str]): Comma-separated event parameter filters.
            Format: '{param}{operator}{value},{param}{operator}{value},...'
            Operators: ==, <> (%3C%3E), < (%3C), <= (%3C=), >, >=.
            Parameters must match event_name; mismatched parameters return empty results.
            Example: 'matter_id==abc123'.

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
