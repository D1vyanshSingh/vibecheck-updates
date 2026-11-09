"""Third-party integrations. Each one reports \"unconfigured\" instead of failing silently."""

from app.integrations.github import GitHubApp, GitHubError, verify_webhook_signature

__all__ = ["GitHubApp", "GitHubError", "verify_webhook_signature"]
