# Restricted hosted production service

This runbook describes the release and operator acceptance procedure. It does not
assert that an image, deployment, public route, credential enrollment or canary
has completed. The parent release operator uses an authorized release builder;
build and deployment follow a reviewed, protected merge to `main`. Keep
qualification evidence and operator configuration outside
the public repository. Never copy secret values into a command line, transcript,
record, expanded Compose output or image.

## Runtime contract

`google-seo-mcp` defaults to legacy stdio, with the 113-tool catalog
and protocol-only stdout. `--transport streamable-http` selects the restricted
production profile: SDK 1 FastMCP, stateless JSON HTTP, one worker/replica,
`/mcp` and `/mcp/`. There are no legacy `/sse` or `/messages` endpoints. CLI
transport/host/port options override their environment settings.

The exact hosted catalog is the 46 names in the packaged
[`production_tools.json`](../src/google_seo_mcp/production_tools.json): the unchanged
35 GSC/GA4/cross-platform/SERP reads (including `serp_check`, `serp_aio_monitor`,
`serp_paa_extractor` and `serp_competitor_intersect`) plus exactly the eleven
isolated Bing reads below. Catalog presence does not certify live Bing readiness.
Registration and direct dispatch both enforce the manifest. Arbitrary fetch,
crawl/browser, local file, logs/history, metadata/credential reload, Google
Indexing, sitemap writes and IndexNow are excluded. Future names require review
and a manifest change. The production package has no crawl/SSR/stats/dev extras;
advertools, Scrapy and Twisted must be absent. Local optional crawling uses the
separate `crawl` extra. Legacy stdio IndexNow writes now require the independent
`GOOGLE_SEO_ALLOW_INDEXNOW=true` opt-in; production always refuses that gate.

Consumer bearer keys provide authentication and attribution. Every consumer uses
the same server-side Google identity and its approved property grants. Keys do
not provide property or tenant isolation. Stop onboarding if that isolation is
required; it needs a separate authorization design.

## Configuration and readiness

Use [`deploy/production.env.example`](../deploy/production.env.example) as a
nonsecret reference. The deployed Compose project/service is `google-seo-mcp`.
Supply `GOOGLE_SEO_IMAGE` as a qualified immutable registry digest and
`GOOGLE_SEO_SECRETS_DIR` as an existing protected directory. Compose consumes the
qualified image without building it. It publishes host port 3006 to container
port 8000;
the operator selects the approved bind interface and ingress ACL before launch.
The current publication default is `0.0.0.0`; it is not an ingress authorization.

Container identity is UID/GID 10001, root filesystem read-only, `/tmp` a bounded
64 MiB tmpfs, capabilities dropped, no-new-privileges, memory/swap 512 MiB,
CPU 1, pids 128. There is no host HOME, Docker socket or unrelated data mount.
Health probes run every 30 seconds with 5-second timeout, 20-second start period
and three retries. `unless-stopped` restarts exited containers; unhealthy status
alone does not restart them. JSON container logs rotate at 10 MiB, three files.
The graceful stop timeout is 30 seconds.

Set exact comma-separated `GOOGLE_SEO_ACCEPTED_HOSTS` authorities and
`GOOGLE_SEO_ACCEPTED_ORIGINS` origins; no wildcards. Preserve loopback port 8000
for the container healthcheck and port 3006 for host smoke. Add only approved
exact LAN/tailnet host:port entries when needed. Configure the proxy to preserve
the approved public Host. Forwarded headers cannot make a remote peer local.
Public URL is `https://google-seo.mcp.propel.marketing/mcp`; TLS terminates at
the operator-managed edge. Do not disable Host/Origin checks or TLS verification.

All MCP paths, aliases and methods authenticate before SDK dispatch. Missing,
unknown, malformed, disabled or duplicate authorization yields 401 with Bearer
challenge. Authenticated hostile Host/Origin yields 403. Requests are bounded to
4 MiB, two concurrent requests and 60 requests per minute per consumer; keys for
one consumer share those limits. Admission rejection is 413/429 as appropriate.
Only minimal liveness and local-peer readiness bypass bearer authentication.

| Endpoint/state | Meaning |
| --- | --- |
| `GET /healthz`, 200 `{"status":"ok"}` | Minimal process liveness; no credential or provider check. |
| Local `GET /readyz`, 200, `transport_ready=true`, `status=credential-pending` | Transport ready with intentionally absent Google file when credentials are optional. |
| Local `/readyz`, `credentials-invalid` | Local file/schema invalid; investigate without printing it. Optional mode can still return 200. |
| Local `/readyz`, `transport-ready`, credentials `available` | Offline local file/schema availability only; Google grants/token refresh remain unverified. |
| Local `/readyz`, 503 | Transport not ready, or required credentials missing/invalid. |

Readiness is based on the actual loopback peer, not forwarding headers; remote
requests receive 403. Use operator host-local smoke over enrolled SSH rather
than opening readiness externally. Neither health, initialization nor tool
listing constructs/refreshes Google credentials or contacts a business API.
`GOOGLE_SEO_REQUIRE_GOOGLE_CREDENTIALS=false` is the credential-pending mode.
Enable required mode only for the separately authorized operational phase.

`GOOGLE_SEO_REVISION` is baked by the image build and copied into the OCI revision
label. Supply the exact reviewed 40-character lowercase Git SHA. Unknown/absent
revision falls back to the installed package version in readiness; a version
fallback is not immutable release evidence. Compare the image label, local
readiness SHA and protected merged-main SHA for release acceptance.

## Operator secrets and registry

Operators generate/enroll consumer material through the approved secrets
mechanism; this repository provides no enrollment or plaintext key-generation
commands. The smoke consumer's key is referenced by `GOOGLE_SEO_SMOKE_KEY` and
injected into that smoke process only. Never put it into this env example, URL,
shell argument or published artifact. Do not enable shell tracing or environment
dumps. Presence is established by successful authenticated behavior.

The protected directory is mounted read-only at `/run/secrets`, with
`create_host_path:false`. It must already exist. It contains the required
`consumer-keys.json` and may initially omit `google-seo-service-account.json`.
Mounting a directory permits the absent Google file without Docker creating a
placeholder directory at a missing individual-file source.

The registry schema is JSON `version` integer 1 and `consumers`, a nonempty
array of entries containing exactly `consumer_id`, `key_id`, `sha256`, `enabled`.
Identifiers match `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`; `sha256` is 64 lowercase
hexadecimal characters, and `enabled` is a JSON boolean. Only hashes are stored.
No unknown fields, duplicate JSON object keys, duplicate key IDs or digests
(including disabled entries), or empty active set are accepted. The registry
has a 1 MiB read bound and at most 4096 entries. Missing/unreadable/corrupt
registry fails startup with a sanitized error. Comparison traverses all active
digests using constant-time digest comparison.

Keep the directory operator-owned and restricted, with traversal and file-read
permissions only for the operator/service group used by UID/GID 10001 (for
example directory 0750 and files 0640 with the correct group). Verify permissions
and presence without reading contents into output. These registry/Google
instructions do not replace Bing's enforced custody checks below. Rotation uses
atomic registry replacement and recreation of only this service; the in-memory
registry does not hot-reload.
Verify revoked-key denial and new-key acceptance after recreation using approved
injection. Preserve revocations through code rollback. Any overlap needs approval.

Hosted auth reads only `GOOGLE_SEO_SERVICE_ACCOUNT_FILE`. No ADC, metadata server,
cached OAuth token, browser or developer HOME fallback exists. One shared service
account requests exactly:

- `https://www.googleapis.com/auth/webmasters.readonly`
- `https://www.googleapis.com/auth/analytics.readonly`

Operators later enroll the file and grant only approved GSC Restricted/read and
GA4 Viewer access. No owner/editor, indexing scope or domain-wide delegation is
needed. Missing credentials yield sanitized `credentials_missing` on tool calls
without an outbound attempt. Malformed/provider failures are sanitized. Production
rejects write/private/local/debug gates even when given a truthy override.

DataForSEO uses server-side injected `DATAFORSEO_LOGIN` and
`DATAFORSEO_PASSWORD`, fixed vendor endpoints and bounded requests. Missing
credentials fail without DNS/request. The vendor is billable. No Google business
or paid vendor tool is part of this transport smoke; operational provider testing
and consumer wiring require their separate gate. Do not use `get_capabilities`
as a smoke substitute. Google credential enrollment, property grants and live
Google/DataForSEO verification remain Step 5.3 work.

Hosted SERP responses must contain a coherent successful task/result with an
explicit list of items. An explicit empty list is a qualified empty observation;
missing, null, malformed or errored observations yield sanitized
`vendor_unavailable`. Batch results count only qualified observations and retain
explicit per-item errors. Inspect those payload errors before interpreting a
negative finding or a completed call as a provider result.

## Optional Bing Webmaster provider — Step 5.4

This section governs the additive Bing release on the existing Google service;
it is not a claim that any gate has run. Historical initial-route/Google-enrollment
procedures later in this document do not authorize redoing those operations.
Preserve the existing Google credentials, grants, DataForSEO injection, consumer
registry, ingress/auth design and all Compose hardening/resources.

### Exact path-only configuration and readiness

Only these three Bing runtime fields/environment names are supported:

| Runtime field | Environment name | Default |
| --- | --- | --- |
| `bing_credentials_file` | `GOOGLE_SEO_BING_CREDENTIALS_FILE` | `/run/secrets/bing-webmaster.json` |
| `bing_sites_file` | `GOOGLE_SEO_BING_SITES_FILE` | `/run/secrets/bing-sites.json` |
| `require_bing_credentials` | `GOOGLE_SEO_REQUIRE_BING_CREDENTIALS` | `false` |

Compose fixes the two container paths, like its Google/registry paths; the env
example documents them for direct processes, not Compose path overrides. Only
its Bing-required boolean is forwarded. There is no fourth field, API-key env
fallback, HOME lookup, OAuth/browser/Google credential fallback, caller key/path,
account selector or configurable upstream endpoint. Keep required mode **false**
through credential-pending deployment and until the later separately authorized
grant/provider qualification; switching it is not a grant check.

Reuse the existing protected directory bind at `/run/secrets`, read-only with
`create_host_path:false`. No additional mount, individual-file placeholder,
service or secret materializer is introduced. Bing files remain absent until the
HOLD/resume gate below. The template's `/etc/propel-mcp/google-seo` source directory
is a documented example, **not a verified live path**. The parent operator must
inspect the approved deployed layout, mirror the existing DataForSEO deployment
custody pattern outside Git, and reconcile its actual protected directory/mount
before any later wiring. Do not invent an actual host path or move existing files
to match the example.

Local `/readyz` adds only `bing_credentials_state`:

- `pending`: either document absent, unless a present document is invalid.
- `invalid`: malformed/unreadable/unprotected key or policy, policy mismatch, or
  observed custody/fingerprint change. Present invalid takes precedence over absence.
- `available`: both bounded documents pass local schema/custody, **not** current
  Bing grants, verification, token validity, API access or business usefulness.

With optional Bing, all existing Google readiness/status decisions are unchanged:
healthy Google remains ready when Bing is missing or invalid. Required Bing makes
pending/invalid return 503, subject also to the independent Google/transport gate.
`/healthz` stays minimal HTTP200. Probes never contact Bing. Missing configuration
returns explicit `unavailable` / `provider_not_configured` before DNS/client
construction; invalid files fail closed, never empty business success. Catalog
listing and successful HTTP dispatch are not provider qualification.

### Operator custody and exact approved site policy

The operator enrolls the **EXISTING** Bing Webmaster key in Infisical project
`cypher`, environment `prod`, named `BING_WEBMASTER_API_KEY`. Do not generate,
delete or regenerate a key: it is user-wide and may serve other integrations.
This is a vault name, not a runtime env-key contract. Agents/consumers never
receive the value. No secret value belongs in Git, Compose, `.env`, image layers,
CLI arguments, logs, transcripts, task records or qualification artifacts.

Only after the resume gate may the approved injector materialize a strict JSON
credential document: exactly `version` (integer `1`) and `api_key` (bounded,
nonempty string; no control characters), maximum **16 KiB** file size. Do not
paste a literal key or a placeholder credential document into this runbook.
The separate **nonsecret** policy file is maximum **64 KiB** and must contain
exactly this singleton, with no aliases, alternate host/scheme, implicit default
or additional sites:

```json
{"version":1,"sites":["https://kelleyconstructioninc.com/"]}
```

Both documents reject unknown fields, duplicate JSON keys and invalid schemas.
Protect the nonsecret policy exactly like the credential: static admission is an
authorization boundary, not proof of provider-side grants or tenant isolation.
All consumers share one Bing identity and this approved site; bearer keys provide
authentication/attribution only. Discovery returns approved verified observations
without verification codes. Business reads enforce the static policy and rely
on Bing to enforce current grants; they perform no hidden verification preflight.
Operator policy removal/revocation is required on grant drift; denial is not empty.

For **both** files verify metadata without emitting contents: regular file,
owner root or the service UID **10001**, service-readable (for example root:10001
or 10001:10001, mode **0640**), exactly one hardlink, no symlink at the leaf or
any parent component. The immediate parent must be root/service-owned and not
group- or other-writable (for example root:10001 mode 0750); UID10001 must be able
to traverse the entire no-follow directory chain. No world access, execute bits
or group/other write on the files. Do not relax permissions to bypass an invalid
state. The loader enforces bounded no-follow reads and rechecks configured-path
custody; these instructions do not certify filesystem atomicity between checks.

Composition captures paths, and the first local inspection pins custody state.
Any key/policy replacement, permissions/ownership change, addition after absence
or rotation requires **explicit service recreation** and a fresh loader; no
hot-reload or stale-key fallback. Invalid custody latches fail-closed even if the
file is restored. Rotation/revocation requires separate operator approval and
coordination with existing integrations; this increment authorizes no generation,
deletion or regeneration. Never restore a revoked key on code rollback and never
alter/re-enroll a consumer to make a smoke test pass.

### Exact eleven read tools and interpretation limits

| Tool | Fixed Bing operation |
| --- | --- |
| `bing_list_sites` | `GetUserSites` |
| `bing_rank_traffic_stats` | `GetRankAndTrafficStats` |
| `bing_query_stats` | `GetQueryStats` |
| `bing_page_stats` | `GetPageStats` |
| `bing_page_query_stats` | `GetPageQueryStats` |
| `bing_query_page_stats` | `GetQueryPageStats` |
| `bing_crawl_stats` | `GetCrawlStats` |
| `bing_crawl_issues` | `GetCrawlIssues` |
| `bing_url_info` | `GetUrlInfo` |
| `bing_list_sitemaps` | `GetFeeds` |
| `bing_sitemap_details` | `GetFeedDetails` |

No mutations/admin calls, submission, FetchUrl, IndexNow, generic method proxy,
deferred tools, automatic fan-out/pagination or cross-platform fusion are added.
The upstream is fixed HTTPS `ssl.bing.com:443` JSON GET with redirects and ambient
proxies refused; never log authenticated query URLs or raw provider exceptions.
Application read-only enforcement does not make the user-wide API key scoped
read-only at Bing.

Query/page data updates **weekly**, with top-N selection and unknown coverage,
not an exhaustive daily series. Site traffic/crawl stats have daily cadence;
six-month retention is documented only for crawl stats. Analytics dates must be
supplied together (ordered span at most 366 days); strict integer limit 1..1000,
default 100. Dates/limits filter one response **locally**, not provider date
parameters or pagination. Preserve raw dates, requested/observed periods, cadence,
source/returned row counts, local truncation, warnings and
`provider_completeness=unknown`. UTC-date filtering is a local convention, not
qualified Bing reporting-day/GSC timezone parity. Never sum mixed weekly/top-N
buckets into site totals or infer zero traffic from no matching rows.

Keep raw `AvgClickPosition` and `AvgImpressionPosition` **unscaled**;
`position_scale=undocumented`, normalized `average_position=null`. No guessed
rank divisor, quick-win scoring or fusion with Google rank. CTR requires valid
counts; zero denominator is null. Preserve raw query/selector-context caveats and
crawl-issue masks/unknown bits. `GetUrlInfo`/`UrlInfo` is narrower than GSC URL
inspection: no live fetch, indexed boolean synthesis, canonical/rich-result or
GSC-parity claim; `IsPage` is not proof of indexing. Sitemaps return feed metadata,
not full sitemap URL enumeration. Empty/partial/deferred/denied/provider-error
outcomes must stay distinct from positive data and business qualification.

### Mandatory staged release, HOLD and later live acceptance

These are **parent-operator-only future gates**, not commands for a local builder:

1. Complete independent offline source/fresh-wheel qualification and triage.
   GitHub-first protected PR/merge; verify qualified-head/merged-tree equality.
   Build exact clean merged `main` and qualify the actual immutable final image
   with pip-audit, SBOM and OS scans. **Any findings or unknown scan result STOP**;
   retain raw evidence, no inherited old OS/advisory waiver or global suppression.
2. Before mutation capture the approved own-service resolved Compose config hash
   and compare with running config (STOP on drift); capture previous immutable
   image, protected registry digest/metadata and sibling IDs/images/start times/
   restarts/health. Preserve all unrelated config bytes, resource/security fields,
   registry/revocations, Google/DataForSEO custody and sibling services.
3. Deploy only the existing google-seo service, whose repository Compose service
   key is `google-seo-mcp` (confirm the actual deployed key). Recreate only that
   service using the qualified immutable image, `--no-deps --no-build --pull never`;
   no sibling restart, proxy/auth redesign, package install, prune or host change.
   Keep Bing files absent and required=false. Verify health200, no-key/bad-key401,
   exact46 catalog, denied fences, Bing provider_not_configured, incumbent35
   unchanged/healthy, byte-identical consumer registry and unchanged siblings.
4. **Phase 5: POST HOLD in the assignment thread and WAIT.** No key retrieval,
   materialization, wiring or live Bing call yet. Automatic completion notices,
   technical PASS, premature enrollment or general approval do not resume work.
5. **Only a subsequent Coordinator key-enrolled record after that HOLD** permits
   phase 6. Validate that exact authority/qualified digest/config first. Then use
   the existing approved `cypher-agent` identity to fetch only the named Infisical
   `cypher`/`prod` secret, wire the protected outside-Git file and exact policy in
   the confirmed deployed layout, and explicitly recreate only google-seo. Do not
   change the hash-only consumer registry; read back **byte identity** plus metadata
   and unchanged sibling state after wiring/recreation. Keep required=false until
   separately authorized grant/provider qualification; local available is not it.
6. Phase 7 live budget: sequential, **at most one call per Bing tool (11 total),
   no retries**, plus exactly one `gsc_site_snapshot` and one `serp_check` incumbent
   check under this gate. Pin `https://google-seo.mcp.propel.marketing/mcp`, reject
   redirects/proxies and validate target before process-only smoke bearer injection.
   Require the explicit `https://kelleyconstructioninc.com/` verified pilot from
   the single discovery call; never select the first discovered site. Abort if
   absent/unverified. Use approved page/query/sitemap selectors; unavailable
   selectors mean deferred checks, not writes or extra calls to manufacture data.
   Retain only sanitized receipts, actual attempts, image/SHA and per-tool outcomes.
   Positive data/portal comparison is needed for business usefulness, not merely
   successful transport. A failed auth/read contract STOPs; no account/OAuth/site
   substitution, synthetic live results or undocumented scaling experiments.
7. Phase 8 evidence/report and Coordinator independent public re-smoke remain
   distinct gates. Offline PASS, pending deployment and HOLD are not live Bing
   acceptance or assignment completion. Skill/consumer-package changes and
   promotion require a **separate assignment**; do not promote partial/deferred
   functionality as qualified. Consumers reconnect/restart after authorized catalog
   promotion to clear cached catalogs; they never need upstream keys.

Rollback restores the previously qualified immutable own-service image and only
compatible scoped config, then reruns auth/catalog/health/fence checks. Preserve
current consumer registry bytes, revocations, provider revocations and siblings;
never roll back credential security state, repair unrelated services or broaden
exposure. Unknown mutation outcomes require read-only reconciliation before retry.
Final-image findings, credential exposure, registry drift, incumbent behavior
change or sibling disturbance are STOP conditions, not reasons to bypass gates.

## Protected Python logging and audit meaning

Hosted logging guards standard Python `Logger.callHandlers` delivery before
handler, formatter or fallback dispatch. Only application-emitted audit records
with private provenance and validated scalar fields reach the private JSON sink;
logger names and safe-looking JSON alone do not qualify a record. The sink
reconstructs selected request ID, validated consumer, known tool/denied label,
outcome, duration and optional HTTP status without formatting untrusted arguments,
exceptions or extra fields. Raw third-party records are suppressed while genuine
request/tool audits remain available. Debug/access logging stays disabled.

Offline regressions exercise actual GA4 Data/Admin and GSC client constructors,
deferred SDK logging configuration, root/new/nonpropagating loggers, late handlers
and `lastResort`, including configured Google logging scopes. This is a tested
standard Python logging boundary. Arbitrary native C output, `print`, direct
file-descriptor writes, direct handler calls or trusted code replacing that
implementation are outside its protection. Legacy stdio logging and protocol-only
stdout remain intact; one selected transport per process is supported.

A tool audit `outcome=success` means the handler and result serialization completed
normally. It does not establish provider availability, complete observations or
business success: a returned payload can contain explicit errors, including
partial batch errors. Check the payload and its provenance separately. Request
status and audit outcome likewise describe transport/dispatch behavior.

## Authorized release build and qualification

Use an authorized linux/amd64 build environment with Docker Buildx and approved
standard packaged Syft/Trivy tooling. Record tool provenance/checksums, versions
and current feed timestamps. The approved scoped release-build variance permits
the parent release operator to build on the designated deployment machine from
the **exact protected merged-main SHA**. This permits only the release build and
qualification followed by the new service on port 3006; it authorizes no sibling
restart, image/volume prune, global tool install or unrelated host change. An
authorized off-host release builder is also suitable.

The local implementation environment's historical lack of an image engine and
denied user namespaces do not block local code completion. Source tests and
installed-wheel qualification remain distinct from final-image qualification,
container acceptance and provider readiness. The actual image, OS/Python scans,
hardened container smoke and deployment remain required parent-pending gates
until their evidence exists; no clean image is inferred from local results.

After local CI and protected merge, obtain `REVIEWED_MAIN_SHA` from the protected
merge readback and verify a current `origin/main` readback on the release builder.
Use a clean checkout at that exact SHA and nonsecret identifiers/paths; keep
`QUALIFICATION_DIR` outside the checkout and use a new directory for each audit:

```sh
set -eu
test -n "$REVIEWED_MAIN_SHA"
test "$(git rev-parse --verify "$REVIEWED_MAIN_SHA^{commit}")" = "$REVIEWED_MAIN_SHA"
test "$(git rev-parse refs/remotes/origin/main)" = "$REVIEWED_MAIN_SHA"
test "$(git rev-parse HEAD)" = "$REVIEWED_MAIN_SHA"
test -z "$(git status --porcelain --untracked-files=normal)"
RELEASE_TAG="google-seo-mcp:step54-$REVIEWED_MAIN_SHA"
mkdir -p "$QUALIFICATION_DIR"
docker buildx build --platform linux/amd64 --pull --load \
  --build-arg "GOOGLE_SEO_REVISION=$REVIEWED_MAIN_SHA" \
  --metadata-file "$QUALIFICATION_DIR/build-metadata.json" \
  --tag "$RELEASE_TAG" .
IMAGE_ID="$(docker image inspect --format '{{.Id}}' "$RELEASE_TAG")"
test "$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$IMAGE_ID")" = "$REVIEWED_MAIN_SHA"
docker image inspect --format '{{.Id}} {{.Config.User}} {{index .Config.Labels "org.opencontainers.image.revision"}}' \
  "$IMAGE_ID" > "$QUALIFICATION_DIR/image-identity.txt"
python scripts/audit_production.py image \
  --image "$IMAGE_ID" --audit-python "$AUDIT_PYTHON" \
  --output "$QUALIFICATION_DIR/final-image"
```

`AUDIT_PYTHON` belongs to a separate audit-tool environment containing approved
`pip-audit`; it must never be the production interpreter. The helper requires
preinstalled approved Docker, Syft and Trivy. Without path options it searches
only `/usr/local/bin:/usr/bin:/bin`, independent of ambient `PATH`. For already
verified scoped executables, use the image-only options below; these nonsecret
variables name existing executable paths, not shell commands:

```sh
python scripts/audit_production.py image \
  --image "$IMAGE_ID" --audit-python "$AUDIT_PYTHON" \
  --docker-path "$DOCKER_PATH" --syft-path "$SYFT_PATH" --trivy-path "$TRIVY_PATH" \
  --output "$QUALIFICATION_DIR/final-image-scoped"
```

Select either image invocation for a qualification run. Each supplied path must
resolve to an existing regular executable file; omitted options retain fixed
system lookup. The helper resolves explicit paths before changing child working
directory and records exact resolved argv. Path validation does not verify binary
provenance: the operator must verify source/version/checksum separately. Children
use an allowlisted environment with initially empty private HOME and fixed PATH,
without inherited cloud credentials or proxies. These flags do not apply to
`runtime` mode. The helper performs no tool install, download, daemon startup or
deployment. Its image interface accepts an immutable reference or SHA256 image
ID, records projected identity, exact runtime pip check/freeze/inspect, Python
audit from the separate interpreter, and OS/Python SBOM/Trivy results. For an
already installed noneditable wheel environment, the matching command is:

```sh
python scripts/audit_production.py runtime \
  --runtime-python "$RUNTIME_PYTHON" --audit-python "$AUDIT_PYTHON" \
  --output "$QUALIFICATION_DIR/wheel-runtime"
```

Both use repository `requirements-production.lock` by default (`--lock PATH`
overrides it). They audit installed state and do not implicitly build/install.
Retain `summary.json`, raw command/stdout/stderr/exit/date, scanner versions,
feed metadata and exact installed inventory privately. Inspect artifacts for
secret-bearing scanner output before sharing. A nonzero/missing tool/feed result
or unknown scan result is blocked, never clean. A successful pip check proves
metadata consistency only. Assert no advertools/Scrapy/Twisted, dev/audit/build
extras or editable application in the exact runtime, including separately audited
bootstrap pip. Compare image inventory to the locked production wheel evidence.
Audit the builder's exact pip/setuptools/wheel/packaging versions separately with
`pip-audit` in that audit environment; never install audit tools into the image.
No global vulnerability suppression or historical Twisted exception applies.
For Step 5.4, any final-image pip-audit, SBOM or OS finding is **STOP**: retain raw
evidence and return for disposition. Do not reuse an old advisory/applicability
waiver, suppress findings or continue deployment on a prior release's acceptance.

After qualification, publish/transfer the qualified image using the approved
release mechanism and retain the immutable registry digest. Configure Compose
with that digest, never a mutable `latest`-only tag. Verify the pulled image
matches the qualified SHA/digest and preserve candidate/rollback artifacts.

## Hardened image and transport smoke

Before release acceptance, test the final image on the authorized release builder
with the actual Compose security/resource settings. If this is the deployment
machine, use only the new project/service and approved port 3006 after its
collision/capacity checks; do not disturb siblings. An isolated fixture process
may supply process-local synthetic keys and a hash-only fixture registry in a protected
temporary directory, readable by UID 10001. These are test fixtures, never
enrolled consumer material. No provider credential is required. Use loopback
publication, an immutable `GOOGLE_SEO_IMAGE`, the fixture secrets directory and
an untracked operator env file. Validate without expanding secrets:

```sh
set -eu
docker compose --env-file "$OPERATOR_ENV_FILE" config --quiet
docker compose --env-file "$OPERATOR_ENV_FILE" up -d --no-build --no-deps google-seo-mcp
python scripts/smoke_http.py --url http://127.0.0.1:3006/mcp \
  --allow-http-host 127.0.0.1:3006
docker compose --env-file "$OPERATOR_ENV_FILE" stop google-seo-mcp
docker compose --env-file "$OPERATOR_ENV_FILE" up -d --no-build --no-deps --force-recreate google-seo-mcp
python scripts/smoke_http.py --url http://127.0.0.1:3006/mcp \
  --allow-http-host 127.0.0.1:3006
```

The approved injector wraps only each smoke process to provide
`GOOGLE_SEO_SMOKE_KEY`; the commands reference no value. For host-local published
ports Docker NAT may report a nonloopback peer to `/readyz`. After each startup
above, check pending-mode readiness and the exact release SHA inside the
container over loopback, without weakening local-peer enforcement:

```sh
docker compose --env-file "$OPERATOR_ENV_FILE" exec -T google-seo-mcp python -c \
  'import json,sys,urllib.request; d=json.load(urllib.request.urlopen("http://127.0.0.1:8000/readyz",timeout=3)); assert d["transport_ready"] is True and d["status"]=="credential-pending" and d["revision"]==sys.argv[1]; print(json.dumps({"status":d["status"],"revision":d["revision"]}))' \
  "$REVIEWED_MAIN_SHA"
```

This command projects only safe status/revision and fails rather than printing an
unexpected response. For a host process server bound directly to loopback, the
smoke helper can instead use `--check-local-readiness --expected-revision
"$REVIEWED_MAIN_SHA"`. Retain image identity and runtime revision readbacks together.

The helper validates TLS by default, ignores ambient proxy/CA environment,
refuses every redirect, checks no-key 401 and minimal health, then uses the real
SDK to initialize and exhaust `tools/list` pagination. It compares all unique
names with the installed 46-tool manifest. It makes no `tools/call` request.
Its only output is sanitized status/count/revision; public smoke reports revision
`unavailable` because readiness is local-only. Cleartext is allowed only when
`--allow-http-host` exactly matches an approved literal loopback/RFC1918/ULA/
tailnet authority (or `localhost`); no metadata/link-local or arbitrary DNS host.
This option is for approved internal smoke, never a public TLS bypass. Test both
`/mcp` aliases. Public smoke uses only:

```sh
python scripts/smoke_http.py
```

The helper is a discovery smoke, not the full security matrix. Final-image
qualification must also exercise malformed/unknown/revoked keys, both consumer
identities, methods/aliases, hostile Host/Origin, duplicate auth, body/concurrency/
rate limits, denied direct calls before network/open, redacted logs, missing/
corrupt registry startup, missing provider credentials, graceful SIGTERM and
recreation. Confirm stdout is protocol-only in stdio. Capture actual termination
and health/restart/resource state; Uvicorn may re-raise SIGTERM after graceful
cleanup, so retain the observed signal result plus shutdown evidence. Check
read-only mounts, no socket/HOME, user, caps, limits and logging with narrowly
projected inspect output; never dump full container environment/configuration.

## Rollout, canary and rollback

The parent release operator owns GitHub commit/PR/protected merge, release build,
final-image audit, deployment, secret enrollment, public edge/TLS routing and
final reporting. Local code/tests
do not complete those gates. Before mutation confirm port collision, approved
edge upstream/bind/ACL, DNS/TLS owner, current capacity and protected config
backup/snapshot paths. Retain sanitized sibling-health baselines and disposition
pre-existing unhealthy state without trying to repair it. Capacity must cover
candidate/rollback images, at least 20% free disk and the approved RAM budget
(at least 768 MiB available before admission), with no ongoing swap growth.

Start only the new project from the exact protected merged-main SHA using the
qualified immutable image. No sibling restart, prune or unrelated host change is
in scope. Keep the new public route disabled until host-local
auth/health/catalog smoke passes. The public HTTPS route and its smoke are the
sole operator-deferred Step 5.2 gate; record that pending status explicitly while
the remaining build, scan, container and deployment gates stay mandatory.

When the operator provides the approved new route/TLS change, validate it, reload
only its authorized owner and read back the exact route. Run injected public
HTTPS smoke before asserting public acceptance. Observe a full 10-minute canary
for deployment acceptance: container healthy, no OOM/restart loop, bounded
memory/log/disk and no swap-growth or sibling regression. Record
image digest/SHA, projected security settings, redacted consumer attribution,
local smoke, public smoke or its explicit deferral, and sibling readbacks. A failed
required gate is no-go, never partial deployment success. The public deferral
does not waive the host-local canary. Google/vendor live verification,
credential/property-grant acceptance and operational readiness remain Step 5.3;
consumer client promotion remains separately gated.

Rollback triggers include failed auth/catalog/health/security, wrong revision,
credential fallback, broken TLS/proxy, audit failure, OOM/restart loop, capacity
breach or sibling degradation. Disable only the new route/exposure, then stop
only the new Compose service. Initial release rollback removes/disables the new
service and route; it never exposes an unauthenticated upstream. Later releases
may restore the last qualified immutable image and compatible config, then rerun
acceptance. Restore only the exact backed-up route change, validate/read back it
and verify siblings. Preserve revocations and write fences. Never restart other
projects, prune images/volumes, reset repositories or revert secret revocation.
If an outcome is unknown, inspect read-only before retrying. No business-data
write is part of this procedure, so no Google/IndexNow data migration is reversed.
