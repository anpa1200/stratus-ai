"""
GCP session wrapper — thin holder for credentials + project ID.
"""
from dataclasses import dataclass
from typing import Any


@dataclass
class GCPSession:
    """Encapsulates GCP credentials and project context, analogous to boto3.Session."""
    credentials: Any   # google.oauth2.credentials.Credentials or google.auth.credentials.Credentials
    project_id: str

    def build(self, service: str, version: str, **kwargs):
        """Build a Google API Discovery client for the given service."""
        from googleapiclient import discovery
        return discovery.build(
            service,
            version,
            credentials=self.credentials,
            cache_discovery=False,
            **kwargs,
        )
