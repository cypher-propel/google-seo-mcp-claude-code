"""Strict local Bing contracts. Validation performs no file or network I/O."""

import re
from datetime import date, datetime
from enum import StrEnum
from ipaddress import ip_address
from typing import Annotated, Literal, Protocol, runtime_checkable
from urllib.parse import unquote, urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)

from .wire_models import (
    Count,
    RawBingCrawlIssue,
    RawBingCrawlStats,
    RawBingFeed,
    RawBingQueryStats,
    RawBingSite,
    RawBingTrafficStats,
    RawBingUrlInfo,
)


class BingOperation(StrEnum):
    GET_USER_SITES = "GetUserSites"
    GET_RANK_AND_TRAFFIC_STATS = "GetRankAndTrafficStats"
    GET_QUERY_STATS = "GetQueryStats"
    GET_PAGE_STATS = "GetPageStats"
    GET_PAGE_QUERY_STATS = "GetPageQueryStats"
    GET_QUERY_PAGE_STATS = "GetQueryPageStats"
    GET_CRAWL_STATS = "GetCrawlStats"
    GET_CRAWL_ISSUES = "GetCrawlIssues"
    GET_URL_INFO = "GetUrlInfo"
    GET_FEEDS = "GetFeeds"
    GET_FEED_DETAILS = "GetFeedDetails"


ANALYTICS_OPERATIONS = frozenset(
    {
        BingOperation.GET_RANK_AND_TRAFFIC_STATS,
        BingOperation.GET_QUERY_STATS,
        BingOperation.GET_PAGE_STATS,
        BingOperation.GET_PAGE_QUERY_STATS,
        BingOperation.GET_QUERY_PAGE_STATS,
        BingOperation.GET_CRAWL_STATS,
    }
)


class BingModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True, hide_input_in_errors=True)


def validate_public_url(value: str) -> str:
    """Return the exact literal; syntactic public DNS URL checks, never DNS."""
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        raise ValueError("invalid_url")
    try:
        value.encode("utf-8", errors="strict")
        if any(ord(c) < 33 or ord(c) == 127 for c in value) or "\\" in value:
            raise ValueError
        parts = urlsplit(value)
        host = parts.hostname or ""
        if (
            parts.scheme not in {"https", "http"}
            or not host
            or parts.username is not None
            or parts.password is not None
            or "#" in value
            or parts.port not in {None, 80, 443}
            or host.endswith(".")
            or ":" in host
        ):
            raise ValueError
        try:
            ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError
        labels = host.split(".")
        if (
            len(labels) < 2
            or len(host) > 253
            or labels[-1].isdigit()
            or labels[-1].lower()
            in {"localhost", "local", "internal", "test", "invalid", "example"}
            or not all(
                re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", x) for x in labels
            )
        ):
            raise ValueError
        if re.search(r"%(?![0-9A-Fa-f]{2})", value):
            raise ValueError
        decoded = parts.path
        for _ in range(8):
            new = unquote(decoded, errors="strict")
            if new == decoded:
                break
            decoded = new
        else:
            raise ValueError
        if (
            "\\" in decoded
            or any(x in {".", ".."} for x in decoded.split("/"))
            or any(ord(c) < 32 or ord(c) == 127 for c in decoded)
        ):
            raise ValueError
    except (ValueError, UnicodeError):
        raise ValueError("invalid_url") from None
    return value


def validate_site_selector(site_url: str, selector: str) -> str:
    """Require exact origin and property path boundary, without fetching either."""
    validate_public_url(site_url)
    validate_public_url(selector)
    site, target = urlsplit(site_url), urlsplit(selector)
    prefix = site.path or "/"
    path = target.path or "/"
    if (
        site.scheme != target.scheme
        or site.netloc != target.netloc
        or not (path == prefix or path.startswith(prefix if prefix.endswith("/") else prefix + "/"))
    ):
        raise ValueError("selector_outside_property")
    return selector


class BingToolRequest(BingModel):
    operation: BingOperation
    site_url: str | None = Field(default=None, repr=False)
    page_url: str | None = Field(default=None, repr=False)
    query: str | None = Field(default=None, repr=False)
    url: str | None = Field(default=None, repr=False)
    sitemap_url: str | None = Field(default=None, repr=False)
    start_date: str | None = None
    end_date: str | None = None
    limit: Annotated[int, Field(strict=True, ge=1, le=1000)] = 100

    @field_validator("operation", mode="before")
    @classmethod
    def operation_value(cls, value):
        if isinstance(value, BingOperation):
            return value
        if type(value) is str:
            try:
                return BingOperation(value)
            except ValueError:
                pass
        raise ValueError("invalid_operation")

    @model_validator(mode="after")
    def valid_request(self):
        op = self.operation
        if op == BingOperation.GET_USER_SITES:
            if (
                any(
                    v is not None
                    for v in (
                        self.site_url,
                        self.page_url,
                        self.query,
                        self.url,
                        self.sitemap_url,
                        self.start_date,
                        self.end_date,
                    )
                )
                or self.limit != 100
            ):
                raise ValueError("unsupported_arguments")
            return self
        if self.site_url is None:
            raise ValueError("site_required")
        validate_public_url(self.site_url)
        if urlsplit(self.site_url).query:
            raise ValueError("invalid_property")
        selectors = {
            "page_url": BingOperation.GET_PAGE_QUERY_STATS,
            "query": BingOperation.GET_QUERY_PAGE_STATS,
            "url": BingOperation.GET_URL_INFO,
            "sitemap_url": BingOperation.GET_FEED_DETAILS,
        }
        for name, required_op in selectors.items():
            value = getattr(self, name)
            if op == required_op:
                if value is None:
                    raise ValueError("selector_required")
                if name == "query":
                    if not 1 <= len(value) <= 512:
                        raise ValueError("invalid_query")
                    try:
                        value.encode("utf-8", errors="strict")
                    except UnicodeError:
                        raise ValueError("invalid_query") from None
                    if any(ord(c) < 32 or ord(c) == 127 for c in value):
                        raise ValueError("invalid_query")
                else:
                    validate_site_selector(self.site_url, value)
            elif value is not None:
                raise ValueError("unsupported_selector")
        if (self.start_date is None) != (self.end_date is None):
            raise ValueError("date_pair_required")
        if self.start_date is not None:
            if op not in ANALYTICS_OPERATIONS:
                raise ValueError("unsupported_period")
            try:
                if not all(
                    re.fullmatch(r"\d{4}-\d{2}-\d{2}", x) for x in (self.start_date, self.end_date)
                ):
                    raise ValueError
                start, end = date.fromisoformat(self.start_date), date.fromisoformat(self.end_date)
                if not 0 <= (end - start).days <= 366:
                    raise ValueError
            except ValueError:
                raise ValueError("invalid_period") from None
        if op == BingOperation.GET_URL_INFO and self.limit != 100:
            raise ValueError("unsupported_limit")
        return self


class BingCredentialDocument(BingModel):
    version: Literal[1]
    api_key: SecretStr = Field(repr=False, exclude=True)

    @field_validator("version", mode="before")
    @classmethod
    def strict_version(cls, value):
        if type(value) is not int or value != 1:
            raise ValueError("invalid_version")
        return value

    @field_validator("api_key", mode="before")
    @classmethod
    def strict_key(cls, value):
        if not isinstance(value, (str, SecretStr)):
            raise ValueError("invalid_credential")
        raw = value.get_secret_value() if isinstance(value, SecretStr) else value
        try:
            valid = 1 <= len(raw.encode("utf-8", errors="strict")) <= 16384
        except UnicodeError:
            valid = False
        if not valid or not raw.strip() or any(ord(c) < 32 or ord(c) == 127 for c in raw):
            raise ValueError("invalid_credential")
        return value


@runtime_checkable
class BingBudget(Protocol):
    """View of ONE caller's combined real/injected deadline, never a new timer.

    remaining is nonnegative, zero on expiry/cancellation. cancel is idempotent
    and must prevent later dispatch through the concrete client's gates.
    """

    def remaining(self) -> float: ...

    def cancel(self) -> None: ...


class BingRawResponse(BingModel):
    """Private, bounded transfer AFTER key-aware reflection checks by the client.

    Not an outward result: every field is excluded from repr and serialization.
    No key, headers, request object or foreign exception crosses this seam.
    This record does not itself certify provider JSON or grant authority.
    """

    status_code: int = Field(repr=False, exclude=True)
    retry_after: Annotated[str, Field(max_length=2048)] | None = Field(repr=False, exclude=True)
    body: Annotated[bytes, Field(max_length=2 * 1024 * 1024)] = Field(repr=False, exclude=True)
    credential_generation: Annotated[str, Field(min_length=1, max_length=128)] = Field(
        repr=False, exclude=True)


class BingRawAttempt(Protocol):
    """Nonrecursive raw primitive; uses the caller's existing budget instance."""

    def __call__(self, request: BingToolRequest, budget: BingBudget) -> BingRawResponse: ...


SafeCode = Literal[
    "provider_not_configured",
    "credentials_missing",
    "credentials_invalid",
    "invalid_request",
    "site_denied",
    "access_denied",
    "invalid_api_key",
    "rate_limited",
    "timeout",
    "transport_error",
    "invalid_response",
    "response_too_large",
    "credential_reflection",
    "provider_error",
]


class BingProviderFault(BingModel):
    code: SafeCode
    retryable: bool = False


class BingPeriod(BingModel):
    start_date: date
    end_date: date

    @model_validator(mode="after")
    def ordered(self):
        if self.start_date > self.end_date:
            raise ValueError("invalid_period")
        return self


class BingSiteRecord(RawBingSite):
    kind: Literal["site"] = "site"


class BingDiscoverySnapshot(BingModel):
    """Private request-local admission, NOT provider inventory completeness.

    A partial local parse never authorizes, even an otherwise valid true row.
    Wire completeness remains unknown; no cache or I/O occurs in validation.
    Explicit projection into BingReadResult belongs to the consumer, not dump().
    """

    credential_generation: Annotated[str, Field(min_length=1, max_length=128)] = Field(
        repr=False, exclude=True)
    listed_sites: tuple[BingSiteRecord, ...] = Field(repr=False, exclude=True)
    eligible_sites: frozenset[str] = Field(repr=False, exclude=True)
    invalid_rows: Count = Field(repr=False, exclude=True)
    complete: bool = Field(repr=False, exclude=True)

    @model_validator(mode="after")
    def local_admission(self):
        seen, eligible = set(), set()
        for row in self.listed_sites:
            # Revalidate unchecked nested model instances without warning output.
            checked = BingSiteRecord.model_validate(row.model_dump(warnings=False))
            validate_public_url(checked.url)
            if urlsplit(checked.url).query or checked.url in seen:
                raise ValueError("invalid_discovery_snapshot")
            seen.add(checked.url)
            if checked.is_verified is True:
                eligible.add(checked.url)
        if (self.complete and self.invalid_rows
                or self.eligible_sites != (frozenset(eligible) if self.complete else frozenset())):
            raise ValueError("invalid_discovery_snapshot")
        return self


class IBingSiteDiscovery(Protocol):
    def discover(self, deadline: BingBudget) -> BingDiscoverySnapshot: ...


class BingTrafficRecord(RawBingTrafficStats):
    kind: Literal["traffic"] = "traffic"
    date_utc: datetime
    ctr: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)] | None


class BingQueryRecord(RawBingQueryStats):
    kind: Literal["query"] = "query"
    date_utc: datetime
    ctr: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)] | None
    average_position: None = None
    position_scale: Literal["undocumented"] = "undocumented"
    page_url: str | None = Field(default=None, max_length=2048)
    selector_query: str | None = Field(default=None, max_length=512)


class BingCrawlRecord(RawBingCrawlStats):
    kind: Literal["crawl"] = "crawl"
    date_utc: datetime


CrawlIssueName = Literal[
    "None",
    "Code301",
    "Code302",
    "Code4xx",
    "Code5xx",
    "BlockedByRobotsTxt",
    "ContainsMalware",
    "ImportantUrlBlockedByRobotsTxt",
    "DnsErrors",
    "TimeOutErrors",
]


class BingCrawlIssueRecord(RawBingCrawlIssue):
    kind: Literal["crawl_issue"] = "crawl_issue"
    known_issues: list[CrawlIssueName]
    unknown_bits: Count


class BingUrlInfoRecord(RawBingUrlInfo):
    kind: Literal["url_info"] = "url_info"
    discovery_date_utc: datetime
    last_crawled_date_utc: datetime


class BingFeedRecord(RawBingFeed):
    kind: Literal["feed"] = "feed"
    last_crawled_utc: datetime
    submitted_utc: datetime


BingRecord = Annotated[
    BingSiteRecord
    | BingTrafficRecord
    | BingQueryRecord
    | BingCrawlRecord
    | BingCrawlIssueRecord
    | BingUrlInfoRecord
    | BingFeedRecord,
    Field(discriminator="kind"),
]
BingWarning = Literal[
    "local_date_filter",
    "utc_date_filter",
    "local_limit",
    "weekly_buckets",
    "provider_completeness_unknown",
    "invalid_rows_dropped",
    "invalid_dates_dropped",
    "invalid_metrics_dropped",
    "position_scale_undocumented",
    "raw_query_identity",
    "selector_context",
    "all_verticals",
    "crawl_issue_lag",
    "url_info_limited",
    "sitemap_metadata_only",
    "unknown_issue_bits",
    "window_not_exact",
]


class BingReadResult(BingModel):
    status: Literal[
        "ok", "empty", "partial", "unavailable", "denied", "invalid_request", "provider_error"
    ]
    source: Literal["bing_webmaster"] = "bing_webmaster"
    operation: BingOperation
    site_url: str | None = None
    extracted_at: datetime
    records: list[BingRecord] = Field(default_factory=list)
    requested_period: BingPeriod | None = None
    observed_period: BingPeriod | None = None
    provider_cadence: Literal["daily", "weekly", "unknown"] = "unknown"
    source_rows: Count = 0
    returned_rows: Count = 0
    dropped_rows: Count = 0
    local_truncated: bool = False
    provider_completeness: Literal["unknown"] = "unknown"
    position_scale: Literal["undocumented"] | None = None
    warnings: list[BingWarning] = Field(default_factory=list)
    error: BingProviderFault | None = None

    _operation_value = field_validator("operation", mode="before")(
        BingToolRequest.operation_value.__func__
    )

    @model_validator(mode="after")
    def coherent_result(self):
        if self.extracted_at.utcoffset() is None:
            raise ValueError("timezone_required")
        if self.operation != BingOperation.GET_USER_SITES and self.site_url is None:
            raise ValueError("site_required")
        if (
            self.returned_rows != len(self.records)
            or self.source_rows < self.returned_rows + self.dropped_rows
        ):
            raise ValueError("invalid_row_counts")
        if self.status == "empty" and (self.records or self.dropped_rows):
            raise ValueError("invalid_empty")
        if self.status == "ok" and (not self.records or self.dropped_rows):
            raise ValueError("invalid_success")
        if self.status == "partial" and not self.records:
            raise ValueError("invalid_partial")
        failure = self.status in {"unavailable", "denied", "invalid_request", "provider_error"}
        if failure != (self.error is not None) or (failure and self.records):
            raise ValueError("invalid_fault_result")
        expected = {
            BingOperation.GET_USER_SITES: "site",
            BingOperation.GET_RANK_AND_TRAFFIC_STATS: "traffic",
            BingOperation.GET_CRAWL_STATS: "crawl",
            BingOperation.GET_CRAWL_ISSUES: "crawl_issue",
            BingOperation.GET_URL_INFO: "url_info",
            BingOperation.GET_FEEDS: "feed",
            BingOperation.GET_FEED_DETAILS: "feed",
        }.get(self.operation, "query")
        if any(record.kind != expected for record in self.records):
            raise ValueError("invalid_record_family")
        return self
