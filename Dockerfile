# Official Python image metadata and linux/amd64 manifest verified from Docker Hub.
# Python 3.11.17, bookworm; rebuild/requalify explicitly when this digest changes.
FROM python:3.11-slim-bookworm@sha256:8a00ecb83ed9d0864dfd102a1bdb2067fda907ceb30bb86d09da9ee558b19590 AS wheel-builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1
WORKDIR /build

# Build tools are pinned and hash verified independently of runtime dependencies.
# packaging is needed by wheel, and never copied into the final environment.
RUN printf '%s\n' \
      'pip==26.2.1 --hash=sha256:71138adf1f4ca900cdb7d289c21b7494329f2332b6d85f0e1c42108c0384ed3e' \
      'setuptools==84.0.0 --hash=sha256:51a52592b3b99e102b609654876bd65f19f999935166d1352678931132b0c670' \
      'wheel==0.48.0 --hash=sha256:3217dcc807155e45db462d7ef2431f5ddda0d7273b700d05a67b271ceb1287ab' \
      'packaging==26.3 --hash=sha256:d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c' \
      > /tmp/build-tools.lock \
    && python -m pip install --index-url https://pypi.org/simple --require-hashes --no-deps -r /tmp/build-tools.lock \
    && python -c 'import platform; assert platform.machine() == "x86_64", "Production lock requires linux/amd64"'

COPY requirements-production.lock ./
# jstyleson is source-only: hash-check its source, then build it with the pinned
# tools above. Build isolation must not resolve unpinned backend dependencies.
RUN python -m pip wheel --index-url https://pypi.org/simple \
      --require-hashes --no-build-isolation --no-deps \
      --wheel-dir /wheelhouse -r requirements-production.lock \
    && sed -n '1p' /tmp/build-tools.lock > /tmp/bootstrap-pip.lock \
    && python -m pip download --index-url https://pypi.org/simple \
      --require-hashes --no-deps --only-binary=:all: \
      --dest /wheelhouse -r /tmp/bootstrap-pip.lock

COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN python -m pip wheel --no-build-isolation --no-deps --wheel-dir /wheelhouse . \
    && python -c 'from pathlib import Path; import zipfile; wheels=list(Path("/wheelhouse").glob("google_seo_mcp-*.whl")); assert len(wheels)==1; assert "google_seo_mcp/production_tools.json" in zipfile.ZipFile(wheels[0]).namelist()' \
    && python -c 'from pathlib import Path; import hashlib; wheels=sorted(Path("/wheelhouse").glob("*.whl")); Path("/wheelhouse/runtime-wheels.lock").write_text("".join(str(p)+" --hash=sha256:"+hashlib.sha256(p.read_bytes()).hexdigest()+"\n" for p in wheels))' \
    && python -m venv --without-pip /opt/venv \
    && python -m pip --python /opt/venv/bin/python install \
      --no-index --no-deps --require-hashes -r /wheelhouse/runtime-wheels.lock \
    && /opt/venv/bin/python -m pip check \
    && /opt/venv/bin/python -c 'from importlib.metadata import distributions; names={d.metadata["Name"].lower().replace("_","-") for d in distributions()}; assert not names.intersection({"advertools","scrapy","twisted","setuptools","wheel","packaging","build","pip-tools","pip-audit","pytest","ruff","playwright","scipy","statsmodels"})' \
    && mkdir -p /opt/venv/share \
    && cp /wheelhouse/runtime-wheels.lock /opt/venv/share/runtime-wheels.lock

FROM python:3.11-slim-bookworm@sha256:8a00ecb83ed9d0864dfd102a1bdb2067fda907ceb30bb86d09da9ee558b19590 AS runtime

ARG GOOGLE_SEO_REVISION=unknown
ENV GOOGLE_SEO_REVISION=${GOOGLE_SEO_REVISION}
LABEL org.opencontainers.image.source="https://github.com/cypher-propel/google-seo-mcp-claude-code" \
      org.opencontainers.image.revision="${GOOGLE_SEO_REVISION}" \
      org.opencontainers.image.base.name="docker.io/library/python:3.11-slim-bookworm" \
      org.opencontainers.image.base.digest="sha256:8a00ecb83ed9d0864dfd102a1bdb2067fda907ceb30bb86d09da9ee558b19590"

# Remove the base's bootstrap tooling. Only the separately audited, pinned pip
# in /opt/venv remains for exact final-runtime pip check/freeze/inspect evidence.
RUN python -c 'import os,re; assert re.fullmatch(r"unknown|[a-f0-9]{40}",os.environ["GOOGLE_SEO_REVISION"]), "Invalid release revision"' \
    && python -m pip uninstall --yes pip setuptools wheel packaging \
    && python -c 'from importlib.metadata import distributions; names=[d.metadata["Name"] for d in distributions()]; assert not names, "Unexpected global Python distributions: "+repr(names)' \
    && mkdir -p /app \
    && chmod 0555 /app
COPY --from=wheel-builder /opt/venv /opt/venv

ENV PATH=/opt/venv/bin:$PATH \
    HOME=/tmp \
    XDG_CACHE_HOME=/tmp/cache \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    GOOGLE_SEO_PROFILE=production \
    GOOGLE_SEO_AUTH_MODE=service-account \
    GOOGLE_SEO_HOST=0.0.0.0 \
    GOOGLE_SEO_PORT=8000 \
    GOOGLE_SEO_CONSUMER_KEYS_FILE=/run/secrets/consumer-keys.json \
    GOOGLE_SEO_SERVICE_ACCOUNT_FILE=/run/secrets/google-seo-service-account.json \
    GOOGLE_SEO_REQUIRE_GOOGLE_CREDENTIALS=false \
    GSC_ALLOW_DESTRUCTIVE=false \
    GOOGLE_SEO_ALLOW_INDEXNOW=false \
    GOOGLE_SEO_ALLOW_LOCAL_FILES=false \
    GOOGLE_SEO_ALLOW_PRIVATE_FETCH=false
WORKDIR /app
USER 10001:10001
EXPOSE 8000
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request; r=urllib.request.urlopen('http://127.0.0.1:8000/healthz',timeout=3); assert r.status==200"]
ENTRYPOINT ["google-seo-mcp"]
CMD ["--transport", "streamable-http"]
