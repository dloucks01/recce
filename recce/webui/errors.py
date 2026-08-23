"""Error handling and exceptions for webui."""
from __future__ import annotations

from fastapi import HTTPException, status


class RecceAPIError(HTTPException):
    """Base exception for recce API errors."""
    def __init__(self, detail: str, status_code: int = status.HTTP_400_BAD_REQUEST):
        super().__init__(status_code=status_code, detail=detail)


class EngagementNotFound(RecceAPIError):
    """Engagement directory not found."""
    def __init__(self):
        super().__init__("Engagement not found", status.HTTP_404_NOT_FOUND)


class InvalidCommand(RecceAPIError):
    """Invalid command or parameters."""
    def __init__(self, cmd: str = ""):
        detail = f"Invalid command: {cmd}" if cmd else "Invalid command"
        super().__init__(detail, status.HTTP_400_BAD_REQUEST)


class ScanNotFound(RecceAPIError):
    """Scan/job not found."""
    def __init__(self, scan_id: str = ""):
        detail = f"Scan not found: {scan_id}" if scan_id else "Scan not found"
        super().__init__(detail, status.HTTP_404_NOT_FOUND)


class ImportError(RecceAPIError):
    """Import failed."""
    def __init__(self, reason: str = ""):
        detail = f"Import failed: {reason}" if reason else "Import failed"
        super().__init__(detail, status.HTTP_400_BAD_REQUEST)


class UnauthorizedAction(RecceAPIError):
    """Action not authorized."""
    def __init__(self, reason: str = ""):
        detail = f"Unauthorized: {reason}" if reason else "Unauthorized"
        super().__init__(detail, status.HTTP_403_FORBIDDEN)
