"""Documentation-derived Bing wire schemas; unknown metadata is discarded."""

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

Count = Annotated[int, Field(strict=True, ge=0)]
RawPosition = Annotated[int, Field(strict=True, ge=-2147483648, le=2147483647)]
WireText = Annotated[str, StringConstraints(strict=True, max_length=2048)]
RawDate = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=128)]


class BingWireModel(BaseModel):
    """Validate known members only. Never log validation errors from foreign payloads."""

    model_config = ConfigDict(
        strict=True, extra="ignore", frozen=True, hide_input_in_errors=True, populate_by_name=True
    )

    @field_validator("*", check_fields=False)
    @classmethod
    def safe_text_and_timestamp(cls, value):
        if isinstance(value, str):
            try:
                value.encode("utf-8", errors="strict")
            except UnicodeError:
                raise ValueError("invalid_unicode") from None
        if isinstance(value, datetime) and value.utcoffset() is None:
            raise ValueError("timezone_required")
        return value


class RawBingSite(BingWireModel):
    url: WireText = Field(alias="Url")
    is_verified: bool = Field(alias="IsVerified")
    # Verification codes deliberately have no fields, so cannot be serialized.


class RawBingTrafficStats(BingWireModel):
    clicks: Count = Field(alias="Clicks")
    date: RawDate = Field(alias="Date")
    impressions: Count = Field(alias="Impressions")


class RawBingQueryStats(RawBingTrafficStats):
    query: WireText = Field(alias="Query")
    avg_click_position: RawPosition = Field(alias="AvgClickPosition")
    avg_impression_position: RawPosition = Field(alias="AvgImpressionPosition")


class RawBingCrawlStats(BingWireModel):
    all_other_codes: Count = Field(alias="AllOtherCodes")
    blocked_by_robots_txt: Count = Field(alias="BlockedByRobotsTxt")
    code_2xx: Count = Field(alias="Code2xx")
    code_301: Count = Field(alias="Code301")
    code_302: Count = Field(alias="Code302")
    code_4xx: Count = Field(alias="Code4xx")
    code_5xx: Count = Field(alias="Code5xx")
    connection_timeout: Count = Field(alias="ConnectionTimeout")
    contains_malware: Count = Field(alias="ContainsMalware")
    crawled_pages: Count = Field(alias="CrawledPages")
    crawl_errors: Count = Field(alias="CrawlErrors")
    date: RawDate = Field(alias="Date")
    dns_failures: Count = Field(alias="DnsFailures")
    in_index: Count = Field(alias="InIndex")
    in_links: Count = Field(alias="InLinks")


class RawBingCrawlIssue(BingWireModel):
    http_code: Count = Field(alias="HttpCode")
    in_links: Count = Field(alias="InLinks")
    issues: Count = Field(alias="Issues")
    url: WireText = Field(alias="Url")


class RawBingUrlInfo(BingWireModel):
    anchor_count: Count = Field(alias="AnchorCount")
    discovery_date: RawDate = Field(alias="DiscoveryDate")
    document_size: Count = Field(alias="DocumentSize")
    http_status: Count = Field(alias="HttpStatus")
    is_page: bool = Field(alias="IsPage")
    last_crawled_date: RawDate = Field(alias="LastCrawledDate")
    total_child_url_count: Count = Field(alias="TotalChildUrlCount")
    url: WireText = Field(alias="Url")


class RawBingFeed(BingWireModel):
    compressed: bool = Field(alias="Compressed")
    file_size: Count = Field(alias="FileSize")
    last_crawled: RawDate = Field(alias="LastCrawled")
    status: WireText = Field(alias="Status")
    submitted: RawDate = Field(alias="Submitted")
    type: WireText = Field(alias="Type")
    url: WireText = Field(alias="Url")
    url_count: Count = Field(alias="UrlCount")
