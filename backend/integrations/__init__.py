"""
SOAR Integration Module

Interfaces to external systems for automated response:
- Identity providers (account control)
- Network/Cloud (blocking, firewalls)
- Messaging (alerting, notifications)
"""

from integrations.identity import disable_user, revoke_sessions, force_password_reset
from integrations.network import block_ip, unblock_ip, block_domain
from integrations.messaging import send_alert, send_to_siem

__all__ = [
    "disable_user",
    "revoke_sessions",
    "force_password_reset",
    "block_ip",
    "unblock_ip",
    "block_domain",
    "send_alert",
    "send_to_siem",
]
