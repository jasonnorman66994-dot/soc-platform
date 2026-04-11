"""
Incident Management Service

Handles incident lifecycle:
- Creation and aggregation
- Status transitions (open → investigating → responded → closed)
- Response tracking and timeline
- Timeline event management
"""

from datetime import datetime, timezone
from typing import Optional
import json


class IncidentService:
    """Service for managing incidents."""
    
    @staticmethod
    def create_incident_from_alerts(alerts: list, event: dict, db_conn=None) -> dict:
        """
        Create a new incident from alerts.
        
        Args:
            alerts: List of alert dicts
            event: Event dict that triggered alerts
            db_conn: Database connection
        
        Returns:
            Incident dict
        """
        if not alerts:
            return None
        
        incident_type = alerts[0].get("type", "detection")
        severity = max(
            ["critical", "high", "medium", "low"].index(a.get("severity", "low")) 
            for a in alerts
        )
        severity_map = {3: "critical", 2: "high", 1: "medium", 0: "low"}
        
        incident = {
            "title": f"{incident_type} - {event.get('user', 'unknown')}",
            "description": f"{len(alerts)} alerts detected for {event.get('event_type', 'unknown')} event",
            "severity": severity_map.get(severity, "medium"),
            "status": "open",
            "event_id": event.get("id"),
            "user": event.get("user"),
            "ip": event.get("ip"),
            "event_type": event.get("event_type"),
            "alerts": alerts,
            "timeline": [
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "action": "incident_created",
                    "description": "Incident created from alerts",
                }
            ],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        
        return incident
    
    @staticmethod
    def update_incident_status(incident_id: int, new_status: str, reason: str = "", db_conn=None):
        """
        Transition incident to new status.
        
        Valid transitions:
        - open → investigating
        - open/investigating → responded
        - responded → closed
        """
        valid_statuses = ["open", "investigating", "responded", "closed"]
        if new_status not in valid_statuses:
            raise ValueError(f"Invalid status: {new_status}")
        
        return {
            "incident_id": incident_id,
            "new_status": new_status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
        }
    
    @staticmethod
    def add_timeline_event(
        incident_id: int,
        action: str,
        description: str,
        actor: str = None,
        details: dict = None,
        db_conn=None,
    ) -> dict:
        """Add event to incident timeline."""
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "description": description,
            "actor": actor,
            "details": details or {},
        }
        
        return event
    
    @staticmethod
    def add_analyst_note(
        incident_id: int,
        note: str,
        analyst_id: str = None,
        tags: list = None,
        db_conn=None,
    ) -> dict:
        """Add analyst note to incident."""
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "note": note,
            "analyst_id": analyst_id,
            "tags": tags or [],
            "type": "note",
        }
    
    @staticmethod
    def link_incidents(parent_id: int, child_id: int, reason: str = "related", db_conn=None) -> dict:
        """Link related incidents."""
        return {
            "parent_id": parent_id,
            "child_id": child_id,
            "reason": reason,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    
    @staticmethod
    def close_incident(
        incident_id: int,
        resolution: str,
        analyst_id: str = None,
        db_conn=None,
    ) -> dict:
        """Close incident with resolution."""
        return {
            "incident_id": incident_id,
            "status": "closed",
            "resolution": resolution,
            "analyst_id": analyst_id,
            "closed_at": datetime.now(timezone.utc).isoformat(),
        }
    
    @staticmethod
    def get_incident_timeline(incident_id: int, db_conn=None) -> list:
        """Get incident timeline events."""
        return [
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": "sample_event",
                "description": "This is a sample timeline event",
            }
        ]
    
    @staticmethod
    def get_incident_related(incident_id: int, db_conn=None) -> dict:
        """Get related incidents."""
        return {
            "incident_id": incident_id,
            "parent": None,
            "children": [],
            "siblings": [],
        }
    
    @staticmethod
    def get_incident_metrics(incident_id: int, db_conn=None) -> dict:
        """Get incident metrics (MTTD, MTTR, etc.)."""
        return {
            "incident_id": incident_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "first_response_at": None,
            "closed_at": None,
            "mttd": None,  # Mean Time To Detect
            "mttr": None,  # Mean Time To Respond
            "alert_count": 0,
            "event_count": 0,
        }


class IncidentResponseTracker:
    """Track incident response actions and automation."""
    
    def __init__(self):
        self.response_log = {}
    
    def log_response_action(
        self,
        incident_id: int,
        action_type: str,
        status: str,
        result: dict = None,
    ) -> dict:
        """Log a response action."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action_type": action_type,
            "status": status,
            "result": result or {},
        }
        
        if incident_id not in self.response_log:
            self.response_log[incident_id] = []
        
        self.response_log[incident_id].append(entry)
        return entry
    
    def get_response_log(self, incident_id: int) -> list:
        """Get response log for incident."""
        return self.response_log.get(incident_id, [])
    
    def get_response_summary(self, incident_id: int) -> dict:
        """Get summary of response actions."""
        log = self.get_response_log(incident_id)
        
        if not log:
            return {
                "incident_id": incident_id,
                "total_actions": 0,
                "successful_actions": 0,
                "failed_actions": 0,
                "actions": [],
            }
        
        successful = len([a for a in log if a["status"] == "success"])
        failed = len([a for a in log if a["status"] == "error"])
        
        return {
            "incident_id": incident_id,
            "total_actions": len(log),
            "successful_actions": successful,
            "failed_actions": failed,
            "first_action": log[0]["timestamp"],
            "last_action": log[-1]["timestamp"],
            "actions": log,
        }


class IncidentAggregator:
    """Aggregate related incidents into larger incidents."""
    
    @staticmethod
    def should_aggregate(incident1: dict, incident2: dict) -> bool:
        """Determine if two incidents should be aggregated."""
        # Same user in different contexts
        if (incident1.get("user") == incident2.get("user") and 
            incident1.get("user") is not None):
            return True
        
        # Same IP doing different things
        if (incident1.get("ip") == incident2.get("ip") and 
            incident1.get("ip") is not None):
            return True
        
        # Same domain/sender in phishing
        if (incident1.get("domain") == incident2.get("domain") and 
            incident1.get("domain") is not None):
            return True
        
        return False
    
    @staticmethod
    def aggregate_incidents(incidents: list) -> list:
        """Group related incidents."""
        if len(incidents) <= 1:
            return incidents
        
        aggregated = []
        used = set()
        
        for i, inc1 in enumerate(incidents):
            if i in used:
                continue
            
            group = [inc1]
            for j, inc2 in enumerate(incidents[i+1:], start=i+1):
                if j not in used and IncidentAggregator.should_aggregate(inc1, inc2):
                    group.append(inc2)
                    used.add(j)
            
            aggregated.append({
                "type": "group" if len(group) > 1 else "incident",
                "incidents": group,
                "count": len(group),
            })
        
        return aggregated


# Global instances
_incident_service = IncidentService()
_response_tracker = IncidentResponseTracker()
_aggregator = IncidentAggregator()


def create_incident_from_alerts(alerts: list, event: dict, db_conn=None) -> dict:
    """Service entry point."""
    return _incident_service.create_incident_from_alerts(alerts, event, db_conn)


def update_incident_status(incident_id: int, new_status: str, reason: str = "", db_conn=None):
    """Service entry point."""
    return _incident_service.update_incident_status(incident_id, new_status, reason, db_conn)


def add_timeline_event(incident_id: int, action: str, description: str, actor: str = None, details: dict = None, db_conn=None) -> dict:
    """Service entry point."""
    return _incident_service.add_timeline_event(incident_id, action, description, actor, details, db_conn)


def add_analyst_note(incident_id: int, note: str, analyst_id: str = None, tags: list = None, db_conn=None) -> dict:
    """Service entry point."""
    return _incident_service.add_analyst_note(incident_id, note, analyst_id, tags, db_conn)


def close_incident(incident_id: int, resolution: str, analyst_id: str = None, db_conn=None) -> dict:
    """Service entry point."""
    return _incident_service.close_incident(incident_id, resolution, analyst_id, db_conn)


def get_response_summary(incident_id: int) -> dict:
    """Service entry point."""
    return _response_tracker.get_response_summary(incident_id)


def log_response_action(incident_id: int, action_type: str, status: str, result: dict = None) -> dict:
    """Service entry point."""
    return _response_tracker.log_response_action(incident_id, action_type, status, result)
