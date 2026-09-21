import re

_PROJECT_ID_RE = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")


def validate_project_id(project_id: str) -> str:
    """Return project_id if it looks like a GCP project ID, else raise ValueError.

    Also keeps the value safe to interpolate into Cloud Logging filters and
    service account emails.
    """
    if not isinstance(project_id, str) or not _PROJECT_ID_RE.match(project_id):
        raise ValueError(f"Invalid GCP project ID: {project_id!r}")
    return project_id
