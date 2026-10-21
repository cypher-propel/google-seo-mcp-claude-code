"""Explicit identity/deadline interfaces. No SDK imports or ambient identity."""

from __future__ import annotations

from typing import Protocol, TypeVar

from .models import (
    GoogleAccountId,
    GoogleCredentialGeneration,
    GoogleDiscoverySnapshot,
    GoogleOAuthCredential,
    GoogleProvider,
    GoogleRequestDeadline,
    GoogleSdkClients,
)

T = TypeVar("T")
T_co = TypeVar("T_co", covariant=True)


class GoogleSdkOperation(Protocol[T_co]):
    def __call__(self, clients: GoogleSdkClients) -> T_co: ...


class IGoogleCredentialLoader(Protocol):
    def load_accounts(self) -> tuple[GoogleOAuthCredential, GoogleOAuthCredential]: ...
    def generation(self) -> GoogleCredentialGeneration: ...


class IGoogleAccountClients(Protocol):
    def execute(
        self,
        account_id: GoogleAccountId,
        operation: GoogleSdkOperation[T],
        deadline: GoogleRequestDeadline,
    ) -> T: ...


class IGooglePropertyDiscovery(Protocol):
    def discover(
        self, provider: GoogleProvider, deadline: GoogleRequestDeadline
    ) -> GoogleDiscoverySnapshot: ...


class GooglePropertyExecutor(Protocol):
    def execute(self, operation: GoogleSdkOperation[T]) -> T: ...


class IGooglePropertyRouter(Protocol):
    def for_gsc(self, site_url: str, deadline: GoogleRequestDeadline) -> GooglePropertyExecutor: ...
    def for_ga4(
        self, property_id: int | str, deadline: GoogleRequestDeadline
    ) -> GooglePropertyExecutor: ...
