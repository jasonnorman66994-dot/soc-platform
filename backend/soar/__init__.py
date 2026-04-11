"""
SOAR (Security Orchestration, Automation, and Response) Module

Provides intelligent automation of security response workflows.
Orchestrates integrations with identity, network, and messaging systems.
"""

from soar.playbooks import (
    PlaybookExecutor,
    execute_playbook_for_incident,
    get_execution_history,
)

__all__ = [
    "PlaybookExecutor",
    "execute_playbook_for_incident",
    "get_execution_history",
]
