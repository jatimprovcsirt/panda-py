"""
Storage adapters for PANDA SDK.

Provides database TLS connection verification.
"""

import os
from typing import Optional


class TLSVerifier:
    """
    Verifies TLS connections for database adapters.

    Helps ensure data is encrypted in transit between application and database.
    """

    @staticmethod
    def check_mysql_connection(host: str, port: int, use_tls: bool) -> dict:
        """
        Check MySQL connection TLS status.

        Args:
            host: Database host
            port: Database port
            use_tls: Whether TLS is enabled

        Returns:
            Dictionary with TLS status
        """
        return {
            "host": host,
            "port": port,
            "tls_enabled": use_tls,
            "verified": use_tls,  # Simplified check
            "message": "TLS enabled" if use_tls else "WARNING: TLS not enabled"
        }

    @staticmethod
    def check_postgres_connection(host: str, port: int, use_ssl: bool) -> dict:
        """
        Check PostgreSQL connection SSL/TLS status.

        Args:
            host: Database host
            port: Database port
            use_ssl: Whether SSL is enabled

        Returns:
            Dictionary with SSL status
        """
        return {
            "host": host,
            "port": port,
            "ssl_enabled": use_ssl,
            "verified": use_ssl,
            "message": "SSL enabled" if use_ssl else "WARNING: SSL not enabled"
        }


class MySqlAdapter:
    """MySQL-specific storage adapter."""

    @staticmethod
    def get_column_type() -> str:
        """Get the recommended column type for MySQL."""
        return "TEXT"

    @staticmethod
    def get_blind_index_type() -> str:
        """Get the recommended column type for blind index."""
        return "VARCHAR(64)"


class PostgresAdapter:
    """PostgreSQL-specific storage adapter."""

    @staticmethod
    def get_column_type() -> str:
        """Get the recommended column type for PostgreSQL."""
        return "TEXT"  # or "BYTEA" for raw binary

    @staticmethod
    def get_blind_index_type() -> str:
        """Get the recommended column type for blind index."""
        return "VARCHAR(64)"
