"""
Incident Management Module

Handles incident lifecycle, response tracking, and aggregation.
"""

from incidents.service import (
    IncidentService,
    IncidentResponseTracker,
    IncidentAggregator,
    create_incident_from_alerts,
    update_incident_status,
    add_timeline_event,
    add_analyst_note,
    close_incident,
    get_response_summary,
    log_response_action,
)

__all__ = [
    "IncidentService",
    "IncidentResponseTracker",
    "IncidentAggregator",
    "create_incident_from_alerts",
    "update_incident_status",
    "add_timeline_event",
    "add_analyst_note",
    "close_incident",
    "get_response_summary",
    "log_response_action",
]
