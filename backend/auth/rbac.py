PERMISSIONS = {
    "view_incidents": {"owner", "admin", "analyst", "viewer"},
    "respond": {"owner", "admin", "analyst"},
    "manage_users": {"owner", "admin"},
}


def authorize(user: dict, action: str):
    allowed = PERMISSIONS.get(action)
    if not allowed:
        raise PermissionError("Unknown action")
    if user.get("role") not in allowed:
        raise PermissionError("Forbidden")
