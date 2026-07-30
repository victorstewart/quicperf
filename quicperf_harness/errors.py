"""Coordinator errors with stable command exit status."""

from __future__ import annotations


class HarnessError(Exception):
    """Base error rendered without a traceback by the command entry point."""

    exit_code = 5


class InvalidConfigurationError(HarnessError):
    """The requested configuration is malformed or internally inconsistent."""

    exit_code = 4


class CanonicalizationError(InvalidConfigurationError):
    """Input cannot be represented as strict canonical JSON."""


class SpecValidationError(InvalidConfigurationError):
    """An experiment specification violates the v2 contract."""


class ManifestValidationError(InvalidConfigurationError):
    """An immutable identity manifest violates the v2 contract."""


class IdentityMismatchError(InvalidConfigurationError):
    """A persisted campaign identity differs from the requested identity."""


class PreflightError(HarnessError):
    """The host or build cannot honor the requested frozen treatment."""

    exit_code = 4


class NonpublishableError(HarnessError):
    """Execution completed, but the result cannot support publication."""

    exit_code = 2


class IncompleteCampaignError(HarnessError):
    """A campaign remains incomplete and may be resumed."""

    exit_code = 3
