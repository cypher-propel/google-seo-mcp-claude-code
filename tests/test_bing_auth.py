"""Permanent offline custody regressions; every document/key is synthetic."""

import json
import os
import socket
import traceback
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from google_seo_mcp.bing import auth

_REAL_HTTPX_CLIENT = httpx.Client
SITE = "https://kelleyconstructioninc.com/"
KEY = "  SYNTHETIC-only+a%2Fb&quoted\"unicode-é  "


@pytest.fixture(autouse=True)
def deny_network_and_reset(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("unexpected network/client access")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(auth, "_boundary", None)
    import httpx

    monkeypatch.setattr(httpx, "Client", forbidden)
    monkeypatch.setattr(httpx, "AsyncClient", forbidden)


@pytest.fixture
def documents(tmp_path):
    tmp_path.chmod(0o700)
    key, policy = tmp_path / "synthetic-key.json", tmp_path / "synthetic-sites.json"
    write_json(key, {"version": 1, "api_key": KEY})
    write_json(policy, {"version": 1, "sites": [SITE]})
    return SimpleNamespace(bing_credentials_file=key, bing_sites_file=policy)


def write_json(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)


def configured(documents):
    auth.configure_bing_auth(documents)
    return auth.BingCredentialLoader()


def assert_failure(loader, code="credentials_invalid"):
    with pytest.raises(auth.BingAuthError) as error:
        loader.load()
    assert str(error.value) == code
    assert error.value.code == code
    assert error.value.__context__ is None
    return error.value


def test_missing_file_precedes_dns(documents):
    documents.bing_credentials_file.unlink()
    loader = configured(documents)
    assert auth.bing_credentials_state() == "pending"
    assert_failure(loader, "credentials_missing")


@pytest.mark.parametrize("missing", ["bing_credentials_file", "bing_sites_file"])
def test_either_missing_is_pending(documents, missing):
    getattr(documents, missing).unlink()
    assert_failure(configured(documents), "credentials_missing")
    assert auth.bing_credentials_state() == "pending"


@pytest.mark.parametrize("missing", ["bing_credentials_file", "bing_sites_file"])
def test_present_malformed_wins_over_missing(documents, missing):
    getattr(documents, missing).unlink()
    other = (documents.bing_sites_file if missing == "bing_credentials_file"
             else documents.bing_credentials_file)
    other.write_text('{"api_key":"SYNTHETIC-secret-unclosed', encoding="utf-8")
    assert_failure(configured(documents))
    assert auth.bing_credentials_state() == "invalid"


def test_malformed_file_redacts_value(documents, caplog, capsys):
    documents.bing_credentials_file.write_text('{"api_key": "' + KEY, encoding="utf-8")
    error = assert_failure(configured(documents))
    rendered = "".join(traceback.format_exception(error)) + repr(error) + caplog.text
    captured = capsys.readouterr()
    rendered += captured.out + captured.err
    assert KEY not in rendered
    assert str(documents.bing_credentials_file) not in rendered
    assert "ValidationError" not in rendered
    assert "JSONDecodeError" not in rendered


def test_validation_error_never_exposes_pydantic_json(documents):
    write_json(documents.bing_credentials_file,
               {"version": 1, "api_key": {"nested": KEY}})
    error = assert_failure(configured(documents))
    assert not hasattr(error, "json")
    assert not hasattr(error, "errors")
    assert KEY not in repr(error.__dict__)


def test_no_home_env_oauth_fallback(documents, monkeypatch):
    monkeypatch.setenv("BING_API_KEY", "SYNTHETIC-ENV")
    monkeypatch.setenv("BING_WEBMASTER_API_KEY", "SYNTHETIC-ENV")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/synthetic/never-open")
    monkeypatch.setenv("GOOGLE_SEO_BING_CREDENTIALS_FILE", "/synthetic/never-open")
    monkeypatch.setattr(Path, "home", lambda: pytest.fail("HOME fallback"))
    documents.bing_credentials_file.unlink()
    assert_failure(configured(documents), "credentials_missing")


def test_configure_and_constructor_capture_paths_only(documents, monkeypatch):
    with monkeypatch.context() as patch:
        patch.setattr(os, "open", lambda *a, **k: pytest.fail("composition read"))
        patch.setattr(Path, "stat", lambda *a, **k: pytest.fail("composition stat"))
        loader = configured(documents)
    assert loader.load().api_key.get_secret_value() == KEY


def test_unconfigured_has_no_hidden_default_site():
    loader = auth.BingCredentialLoader()
    assert auth.bing_credentials_state() == "pending"
    assert_failure(loader, "credentials_missing")
    with pytest.raises(auth.BingAuthError, match="credentials_missing"):
        _ = loader.allowed_sites


def test_literal_key_private_and_available_is_only_local_shape(documents):
    loader = configured(documents)
    assert auth.bing_credentials_state() == "available"
    document = loader.load()
    assert document.api_key.get_secret_value() == KEY
    for output in (repr(document), str(document), document.model_dump_json(),
                   repr(document.model_dump()), repr(loader), repr(auth._boundary)):
        assert KEY not in output
        assert str(documents.bing_credentials_file) not in output
    assert "api_key" not in document.model_dump()


def test_verified_site_allowlist_denies_other_property(documents):
    # Static operator policy is not a provider verification cache.
    loader = configured(documents)
    loader.authorize_site(SITE)
    assert loader.allowed_sites == frozenset({SITE})
    for site in ("https://other-public.com/", "http://kelleyconstructioninc.com/",
                 "https://www.kelleyconstructioninc.com/", SITE.rstrip("/"), SITE + "path"):
        with pytest.raises(auth.BingAuthError, match="site_denied"):
            loader.authorize_site(site)


@pytest.mark.parametrize("sites", [[], ["https://other-public.com/"],
                                  [SITE, "https://other-public.com/"], [SITE, SITE]])
def test_only_explicit_approved_singleton_policy(documents, sites):
    write_json(documents.bing_sites_file, {"version": 1, "sites": sites})
    assert_failure(configured(documents))
    assert auth.bing_credentials_state() == "invalid"


@pytest.mark.parametrize("target", ["bing_credentials_file", "bing_sites_file"])
@pytest.mark.parametrize("mode", [0o644, 0o660, 0o666, 0o700, 0o000])
def test_unprotected_permissions_rejected(documents, target, mode):
    getattr(documents, target).chmod(mode)
    assert_failure(configured(documents))


def test_group_read_protected_files_permitted(documents):
    documents.bing_credentials_file.chmod(0o640)
    documents.bing_sites_file.chmod(0o440)
    assert configured(documents).load().api_key.get_secret_value() == KEY


def test_writable_parent_rejected(documents):
    documents.bing_credentials_file.parent.chmod(0o770)
    assert_failure(configured(documents))


def test_untrusted_owner_rejected(documents, monkeypatch):
    # Synthetic stat objects: no chown privileges or real credential metadata.
    info = SimpleNamespace(st_uid=123456, st_mode=stat_mode())
    with pytest.raises(ValueError, match="invalid_file"):
        auth._protected(info)


def stat_mode():
    import stat

    return stat.S_IFREG | 0o600


@pytest.mark.parametrize("target", ["bing_credentials_file", "bing_sites_file"])
def test_file_size_caps(documents, target):
    cap = 16384 if target == "bing_credentials_file" else 65536
    path = getattr(documents, target)
    path.write_bytes(b" " * (cap + 1))
    assert_failure(configured(documents))


def test_exact_document_caps_admitted(documents):
    for path, cap in ((documents.bing_credentials_file, 16384),
                      (documents.bing_sites_file, 65536)):
        raw = path.read_bytes()
        path.write_bytes(raw + b" " * (cap - len(raw)))
    assert auth.bing_credentials_state() == "pending"
    assert configured(documents).load().api_key.get_secret_value() == KEY


@pytest.mark.parametrize("raw", [b'{"version":1,"version":1,"api_key":"synthetic"}',
                                 b'{"version":1,"api_key":"a","extra":"synthetic"}',
                                 b'{"version":true,"api_key":"synthetic"}',
                                 b'{"version":1,"api_key":"  "}', b'[]', b'\xff'])
def test_invalid_strict_documents(documents, raw):
    documents.bing_credentials_file.write_bytes(raw)
    assert_failure(configured(documents))


@pytest.mark.parametrize("kind", ["symlink", "directory", "fifo", "hardlink"])
def test_nonregular_and_linked_files_refused_without_blocking(documents, kind):
    path = documents.bing_credentials_file
    saved = path.with_name("synthetic-saved.json")
    path.rename(saved)
    if kind == "symlink":
        path.symlink_to(saved)
    elif kind == "directory":
        path.mkdir(mode=0o700)
    elif kind == "fifo":
        os.mkfifo(path, 0o600)
    else:
        os.link(saved, path)
    assert_failure(configured(documents))


def test_parent_symlink_escape_refused(documents):
    root = documents.bing_credentials_file.parent
    alias = root / "linked-parent"
    alias.symlink_to(root, target_is_directory=True)
    documents.bing_credentials_file = alias / documents.bing_credentials_file.name
    assert_failure(configured(documents))


@pytest.mark.parametrize("target", ["bing_credentials_file", "bing_sites_file"])
@pytest.mark.parametrize("change", ["replace", "rewrite", "delete", "permission"])
def test_credential_rotation_invalidates_client(documents, target, change):
    loader = configured(documents)
    assert loader.load().api_key.get_secret_value() == KEY
    path = getattr(documents, target)
    original = path.read_bytes()
    if change == "replace":
        replacement = path.with_name("replacement.json")
        replacement.write_bytes(original)
        replacement.chmod(0o600)
        replacement.replace(path)
    elif change == "rewrite":
        path.write_bytes(original + b" ")
    elif change == "delete":
        path.unlink()
    else:
        path.chmod(0o400)
    assert_failure(loader, "credentials_missing" if change == "delete" else "credentials_invalid")
    assert auth.bing_credentials_state() == ("pending" if change == "delete" else "invalid")
    # Restoring bytes cannot revive the prior identity/client generation.
    if path.exists():
        path.chmod(0o600)
    path.write_bytes(original)
    path.chmod(0o600)
    assert_failure(loader)
    new_loader = configured(documents)
    assert_failure(loader)
    assert new_loader.load().api_key.get_secret_value() == KEY


def test_missing_then_enrolled_requires_recreation(documents):
    path = documents.bing_credentials_file
    path.unlink()
    loader = configured(documents)
    assert_failure(loader, "credentials_missing")
    write_json(path, {"version": 1, "api_key": KEY})
    assert_failure(loader)
    assert configured(documents).load().api_key.get_secret_value() == KEY


def test_reconfigure_revokes_existing_loader_even_same_paths(documents):
    old = configured(documents)
    old.load()
    new = configured(documents)
    assert_failure(old)
    assert new.load().api_key.get_secret_value() == KEY


def test_read_race_invalidates_without_returning_cached_key(documents, monkeypatch):
    loader = configured(documents)
    loader.load()
    original = os.read
    changed = False

    def racing_read(fd, count):
        nonlocal changed
        raw = original(fd, count)
        if not changed:
            changed = True
            documents.bing_credentials_file.write_bytes(b"invalid synthetic replacement")
        return raw

    monkeypatch.setattr(os, "read", racing_read)
    assert_failure(loader)
    assert auth.bing_credentials_state() == "invalid"


def test_concurrent_loads_are_consistent(documents):
    from concurrent.futures import ThreadPoolExecutor

    loader = configured(documents)
    with ThreadPoolExecutor(max_workers=4) as executor:
        values = list(executor.map(lambda _: loader.load().api_key.get_secret_value(), range(12)))
    assert values == [KEY] * 12


def test_rotated_key_only_usable_after_recreation(documents):
    old = configured(documents)
    old.load()
    write_json(documents.bing_credentials_file, {"version": 1, "api_key": "SYNTHETIC-rotated"})
    assert_failure(old)
    new = configured(documents)
    assert new.load().api_key.get_secret_value() == "SYNTHETIC-rotated"
    assert_failure(old)


def test_missing_after_available_is_pending_never_stale(documents):
    loader = configured(documents)
    loader.load()
    documents.bing_sites_file.unlink()
    assert auth.bing_credentials_state() == "pending"
    assert_failure(loader, "credentials_missing")
    documents.bing_credentials_file.write_text("malformed synthetic", encoding="utf-8")
    assert auth.bing_credentials_state() == "invalid"
    assert_failure(loader)


def test_atomic_replacement_during_read_refused(documents, monkeypatch):
    loader = configured(documents)
    original = os.read
    replaced = False

    def replace_during_read(fd, count):
        nonlocal replaced
        raw = original(fd, count)
        if not replaced:
            replaced = True
            replacement = documents.bing_credentials_file.with_name("new-key.json")
            write_json(replacement, {"version": 1, "api_key": "SYNTHETIC-new"})
            replacement.replace(documents.bing_credentials_file)
        return raw

    monkeypatch.setattr(os, "read", replace_during_read)
    assert_failure(loader)


@pytest.fixture
def separate_documents(tmp_path):
    # Independent parents ensure a later policy read cannot mask a key race.
    for name in ("key-ancestor", "policy-ancestor"):
        (tmp_path / name / "protected").mkdir(mode=0o700, parents=True)
    key = tmp_path / "key-ancestor" / "protected" / "key.json"
    policy = tmp_path / "policy-ancestor" / "protected" / "sites.json"
    write_json(key, {"version": 1, "api_key": KEY})
    write_json(policy, {"version": 1, "sites": [SITE]})
    return SimpleNamespace(bing_credentials_file=key, bing_sites_file=policy)


def assert_custody_race(documents, monkeypatch, target, baseline, mutate):
    loader = configured(documents)
    if baseline:
        loader.load()
    path = getattr(documents, target)
    identity = (path.stat().st_dev, path.stat().st_ino)
    original = os.read
    restore = None
    opened = set()
    real_open, real_close = os.open, os.close

    def tracked_open(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        opened.add(fd)
        return fd

    def tracked_close(fd):
        real_close(fd)
        opened.remove(fd)

    def racing_read(fd, count):
        nonlocal restore
        raw = original(fd, count)
        info = os.fstat(fd)
        if restore is None and (info.st_dev, info.st_ino) == identity:
            restore = mutate(path)
        return raw

    with monkeypatch.context() as patch:
        patch.setattr(os, "open", tracked_open)
        patch.setattr(os, "close", tracked_close)
        patch.setattr(os, "read", racing_read)
        assert_failure(loader)
        assert not opened
    assert restore is not None
    assert auth.bing_credentials_state() == "invalid"
    restore()
    # Even a first-inspection race permanently revokes this generation.
    assert_failure(loader)
    assert auth.bing_credentials_state() == "invalid"
    assert configured(documents).load().api_key.get_secret_value() == KEY
    assert_failure(loader)


@pytest.mark.parametrize("target", ["bing_credentials_file", "bing_sites_file"])
@pytest.mark.parametrize("baseline", [False, True])
def test_parent_permissions_changed_during_read_must_fail(
    separate_documents, monkeypatch, target, baseline,
):
    def mutate(path):
        path.parent.chmod(0o777)
        return lambda: path.parent.chmod(0o700)

    assert_custody_race(separate_documents, monkeypatch, target, baseline, mutate)


@pytest.mark.parametrize("target", ["bing_credentials_file", "bing_sites_file"])
@pytest.mark.parametrize("baseline", [False, True])
def test_parent_symlink_swap_during_read_must_fail(
    separate_documents, monkeypatch, target, baseline,
):
    def mutate(path):
        root = path.parent
        retired = root.with_name("retired")
        replacement = root.with_name("replacement")
        replacement.mkdir(mode=0o700)
        write_json(replacement / path.name,
                   {"version": 1, "api_key": "SYNTHETIC-different"}
                   if target == "bing_credentials_file" else {"version": 1, "sites": [SITE]})
        root.rename(retired)
        root.symlink_to(replacement, target_is_directory=True)

        def restore():
            root.unlink()
            retired.rename(root)

        return restore

    assert_custody_race(separate_documents, monkeypatch, target, baseline, mutate)


@pytest.mark.parametrize("target", ["bing_credentials_file", "bing_sites_file"])
@pytest.mark.parametrize("baseline", [False, True])
@pytest.mark.parametrize("change", ["ancestor_replace", "ancestor_symlink", "parent_missing",
                                   "leaf_missing", "protected_mode"])
def test_in_read_custody_change_latches_recreation(
    separate_documents, monkeypatch, target, baseline, change,
):
    def mutate(path):
        if change == "protected_mode":
            path.parent.chmod(0o500)
            return lambda: path.parent.chmod(0o700)
        root = path if change == "leaf_missing" else path.parent
        if change.startswith("ancestor"):
            root = root.parent
        retired = root.with_name("retired")
        root.rename(retired)
        if change == "ancestor_replace":
            # Preserve the original parent and leaf inode; only the ancestor
            # identity changes. A leaf-only or immediate-parent check misses it.
            root.mkdir(mode=0o700)
            (retired / path.parent.name).rename(root / path.parent.name)
        elif change == "ancestor_symlink":
            root.symlink_to(retired, target_is_directory=True)

        def restore():
            if change == "ancestor_replace":
                (root / path.parent.name).rename(retired / path.parent.name)
                root.rmdir()
            elif change == "ancestor_symlink":
                root.unlink()
            retired.rename(root)

        return restore

    assert_custody_race(separate_documents, monkeypatch, target, baseline, mutate)


@pytest.mark.parametrize("during_read", [False, True])
def test_unrelated_ancestor_entries_do_not_invalidate(separate_documents, monkeypatch, during_read):
    loader = configured(separate_documents)
    loader.load()
    ancestor = separate_documents.bing_credentials_file.parent.parent
    original = os.read
    fired = False

    def churn(fd, count):
        nonlocal fired
        raw = original(fd, count)
        if not fired:
            fired = True
            (ancestor / "unrelated-entry").mkdir(mode=0o700)
        return raw

    if during_read:
        monkeypatch.setattr(os, "read", churn)
    else:
        (ancestor / "unrelated-entry").mkdir(mode=0o700)
    assert loader.load().api_key.get_secret_value() == KEY
    assert auth.bing_credentials_state() == "available"


@pytest.mark.parametrize("target", ["bing_credentials_file", "bing_sites_file"])
def test_directory_protection_change_between_reads_latches(separate_documents, target):
    loader = configured(separate_documents)
    loader.load()
    parent = getattr(separate_documents, target).parent
    parent.chmod(0o500)  # Still protected; changed custody metadata must not be ignored.
    assert_failure(loader)
    parent.chmod(0o700)
    assert_failure(loader)
    assert configured(separate_documents).load().api_key.get_secret_value() == KEY


@pytest.mark.parametrize("result", ["available", "malformed", "missing", "symlink", "race"])
def test_custody_descriptors_closed_on_all_paths(separate_documents, monkeypatch, result):
    path = separate_documents.bing_credentials_file
    if result == "malformed":
        path.write_bytes(b"invalid synthetic JSON")
    elif result == "missing":
        path.unlink()
    elif result == "symlink":
        saved = path.with_name("saved.json")
        path.rename(saved)
        path.symlink_to(saved)
    opened = set()
    real_open, real_close, real_read = os.open, os.close, os.read

    def tracked_open(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        opened.add(fd)
        return fd

    def tracked_close(fd):
        real_close(fd)
        opened.remove(fd)

    def race(fd, count):
        raw = real_read(fd, count)
        path.parent.chmod(0o777)
        return raw

    monkeypatch.setattr(os, "open", tracked_open)
    monkeypatch.setattr(os, "close", tracked_close)
    if result == "race":
        monkeypatch.setattr(os, "read", race)
    for _ in range(5):
        # Snapshot ownership supersedes the obsolete per-file admission helper.
        # Reconfigure each iteration so closure is exercised, not latch-only.
        loader = configured(separate_documents)
        state, _ = loader._boundary.inspect()
        assert state == ("available" if result == "available" else
                         "pending" if result == "missing" else "invalid")
        assert not opened


def test_unreadable_policy_wins_missing_key(documents, monkeypatch):
    documents.bing_credentials_file.unlink()
    original = os.open

    def unreadable(path, *args, **kwargs):
        if path == documents.bing_sites_file.name:
            raise PermissionError("SYNTHETIC-sensitive-exception")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", unreadable)
    loader = configured(documents)
    assert auth.bing_credentials_state() == "invalid"
    assert_failure(loader)


@pytest.mark.parametrize("target", ["bing_credentials_file", "bing_sites_file"])
@pytest.mark.parametrize("baseline", [False, True])
@pytest.mark.parametrize("isolate_nlink", [False, True])
def test_hardlink_at_eof_rejected_independent_of_timestamps(
    separate_documents, monkeypatch, target, baseline, isolate_nlink,
):
    loader = configured(separate_documents)
    if baseline:
        loader.load()
    path = getattr(separate_documents, target)
    before = path.stat()
    identity = (before.st_dev, before.st_ino)
    extra = path.with_name("synthetic-extra-link")
    real_read, real_fstat, real_stat = os.read, os.fstat, os.stat
    fired = False
    observations = []

    def observed(info):
        if (info.st_dev, info.st_ino) != identity or not isolate_nlink:
            return info
        # Freeze every other fingerprint field; only the real link count changes.
        fields = {name: getattr(before, name) for name in (
            "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns",
            "st_mode", "st_uid", "st_gid",
        )}
        fields["st_nlink"] = info.st_nlink
        observations.append(fields.copy())
        return SimpleNamespace(**fields)

    def read(fd, count):
        nonlocal fired
        raw = real_read(fd, count)
        info = real_fstat(fd)
        if not raw and not fired and (info.st_dev, info.st_ino) == identity:
            os.link(path, extra)
            fired = True
            assert real_fstat(fd).st_nlink == 2
        return raw

    with monkeypatch.context() as patch:
        patch.setattr(os, "read", read)
        if isolate_nlink:
            patch.setattr(os, "fstat", lambda fd: observed(real_fstat(fd)))
            patch.setattr(os, "stat", lambda *a, **k: observed(real_stat(*a, **k)))
        assert_failure(loader)
    assert fired
    assert path.stat().st_nlink == 2
    if isolate_nlink:
        assert any(item["st_nlink"] == 2 for item in observations)
        for item in observations:
            assert all(value == getattr(before, name) for name, value in item.items()
                       if name != "st_nlink")
    assert auth.bing_credentials_state() == "invalid"
    extra.unlink()
    assert_failure(loader)
    assert configured(separate_documents).load().api_key.get_secret_value() == KEY
    assert_failure(loader)


def test_leaf_fingerprint_includes_link_count_only_change(documents):
    before = documents.bing_credentials_file.stat()
    fields = {name: getattr(before, name) for name in (
        "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns",
        "st_mode", "st_uid", "st_gid", "st_nlink",
    )}
    fields["st_nlink"] = 2
    assert auth._fingerprint(before) != auth._fingerprint(SimpleNamespace(**fields))


@pytest.mark.parametrize("observation", ["descriptor", "configured_name"])
@pytest.mark.parametrize("predicate", ["owner", "writable", "executable", "unreadable",
                                       "nonregular", "hardlink"])
def test_all_post_read_leaf_predicates_enforced(
    documents, monkeypatch, observation, predicate,
):
    # Isolate predicates from fingerprints: deleting either post-read protection
    # call must fail even if the fingerprint otherwise rejects the same metadata.
    import stat

    path = documents.bing_credentials_file
    before = path.stat()
    identity = (before.st_dev, before.st_ino)
    real_read, real_fstat, real_stat = os.read, os.fstat, os.stat
    eof = False
    injected = False

    def observed(info, source):
        nonlocal injected
        if not eof or source != observation or (info.st_dev, info.st_ino) != identity:
            return info
        fields = {name: getattr(info, name) for name in (
            "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns",
            "st_mode", "st_uid", "st_gid", "st_nlink",
        )}
        if predicate == "owner":
            fields["st_uid"] = os.geteuid() + 123456
        elif predicate == "writable":
            fields["st_mode"] |= 0o020
        elif predicate == "executable":
            fields["st_mode"] |= 0o100
        elif predicate == "unreadable":
            fields["st_mode"] = stat.S_IFREG
        elif predicate == "nonregular":
            fields["st_mode"] = stat.S_IFDIR | 0o600
        else:
            fields["st_nlink"] = 2
        injected = True
        return SimpleNamespace(**fields)

    def read(fd, count):
        nonlocal eof
        raw = real_read(fd, count)
        info = real_fstat(fd)
        if not raw and (info.st_dev, info.st_ino) == identity:
            eof = True
        return raw

    monkeypatch.setattr(os, "read", read)
    monkeypatch.setattr(os, "fstat", lambda fd: observed(real_fstat(fd), "descriptor"))
    monkeypatch.setattr(os, "stat", lambda *a, **k: observed(real_stat(*a, **k), "configured_name"))
    monkeypatch.setattr(auth, "_fingerprint", lambda info: (1,))
    assert_failure(configured(documents))
    assert injected
    assert auth.bing_credentials_state() == "invalid"


# SA-1: every variant below starts a fresh boundary, not an already latched one.
_ROLES = ("bing_credentials_file", "bing_sites_file")
_CHANGES = ("chmod", "protected_mode", "replace", "replace_changed", "rewrite",
            "delete", "hardlink", "parent_chmod", "parent_protected", "parent_missing",
            "parent_replace", "parent_symlink", "ancestor_replace", "ancestor_symlink",
            "ancestor_mode")


def snapshot_mutation(path, change):
    """Real persistent filesystem changes, returning a complete restoration."""
    raw = path.read_bytes()
    if change in ("chmod", "protected_mode"):
        path.chmod(0o666 if change == "chmod" else 0o400)
        return lambda: path.chmod(0o600)
    if change in ("replace", "replace_changed"):
        replacement = path.with_name("replacement.json")
        replacement.write_bytes(raw + (b" " if change == "replace_changed" else b""))
        replacement.chmod(0o600)
        replacement.replace(path)
        return lambda: path.write_bytes(raw)
    if change in ("rewrite", "delete"):
        if change == "delete":
            path.unlink()
        else:
            path.write_bytes(raw + b" ")

        def restore_leaf():
            path.write_bytes(raw)
            path.chmod(0o600)

        return restore_leaf
    if change == "hardlink":
        extra = path.with_name("extra-link")
        os.link(path, extra)
        assert path.stat().st_nlink == 2
        return extra.unlink
    root = path.parent.parent if change.startswith("ancestor") else path.parent
    before = root.stat()
    if change in ("parent_chmod", "parent_protected", "ancestor_mode"):
        root.chmod(0o777 if change == "parent_chmod" else 0o500)
        return lambda: root.chmod(before.st_mode & 0o7777)
    retired = root.with_name(root.name + "-retired")
    root.rename(retired)
    if change.endswith("symlink"):
        root.symlink_to(retired, target_is_directory=True)
    elif change.endswith("replace"):
        root.mkdir(mode=0o700)
        if change == "ancestor_replace":
            (retired / path.parent.name).rename(root / path.parent.name)
        else:
            (root / path.name).write_bytes(raw)
            (root / path.name).chmod(0o600)

    def restore_root():
        if change.endswith("symlink"):
            root.unlink()
        elif change == "ancestor_replace":
            (root / path.parent.name).rename(retired / path.parent.name)
            root.rmdir()
        elif change == "parent_replace":
            (root / path.name).unlink()
            root.rmdir()
        retired.rename(root)

    return restore_root


def public_snapshot(loader, entry):
    if entry == "state":
        return auth.bing_credentials_state()
    if entry == "sites":
        return loader.allowed_sites
    if entry in ("authorize", "denied"):
        return loader.authorize_site(SITE if entry == "authorize" else "https://other.example/")
    return loader.load()


def filesystem_custody(path):
    observations = []
    for item in (path, path.parent, path.parent.parent):
        try:
            info = item.lstat()
            observations.append((info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                                 info.st_gid, info.st_nlink, info.st_size))
        except FileNotFoundError:
            observations.append(None)
    return observations


def rejected_snapshot(loader, entry):
    if entry == "state":
        assert public_snapshot(loader, entry) == "invalid"
    else:
        with pytest.raises(auth.BingAuthError, match="^credentials_invalid$") as error:
            public_snapshot(loader, entry)
        assert error.value.__context__ is None


def install_cross_read(monkeypatch, documents, target, phase, change, ordinal=1):
    other = _ROLES[1] if target == _ROLES[0] else _ROLES[0]
    trigger = getattr(documents, other).stat()
    identity = (trigger.st_dev, trigger.st_ino)
    real_read, real_fstat = os.read, os.fstat
    receipt = {"fired": False, "count": 0, "restore": None}

    def read(fd, count):
        raw = real_read(fd, count)
        info = real_fstat(fd)
        if ((info.st_dev, info.st_ino) == identity
                and bool(raw) == (phase == "data")):
            receipt["count"] += 1
            if receipt["count"] == ordinal:
                receipt["restore"] = snapshot_mutation(getattr(documents, target), change)
                receipt["fired"] = True
        return raw

    monkeypatch.setattr(os, "read", read)
    return receipt


@pytest.mark.parametrize("target", _ROLES)
@pytest.mark.parametrize("baseline", [False, True])
@pytest.mark.parametrize("phase", ["data", "eof"])
@pytest.mark.parametrize("entry", ["load", "sites", "authorize", "state", "denied"])
@pytest.mark.parametrize("change", _CHANGES)
def test_snapshot_symmetric_cross_document_public_matrix(
    separate_documents, monkeypatch, target, baseline, phase, entry, change,
):
    loader = configured(separate_documents)
    if baseline:
        public_snapshot(loader, "load" if entry == "denied" else entry)
    path = getattr(separate_documents, target)
    before = filesystem_custody(path)
    with monkeypatch.context() as patch:
        receipt = install_cross_read(patch, separate_documents, target, phase, change)
        rejected_snapshot(loader, entry)
    assert receipt["fired"]
    assert filesystem_custody(path) != before  # persistent, not a restored history
    assert loader._boundary.custody_failed and loader._boundary.invalidated
    receipt["restore"]()
    for public in ("load", "sites", "authorize", "state", "denied"):
        rejected_snapshot(loader, public)
    assert_failure(auth.BingCredentialLoader())  # constructor cannot reset latch
    fresh = configured(separate_documents)
    assert fresh.load().api_key.get_secret_value() == KEY
    assert_failure(loader)


@pytest.mark.parametrize("target", _ROLES)
@pytest.mark.parametrize("parser", [auth.BingCredentialDocument, auth.BingSitePolicy])
@pytest.mark.parametrize("baseline", [False, True])
@pytest.mark.parametrize("entry", ["load", "sites", "authorize", "state"])
@pytest.mark.parametrize("change", ["replace", "hardlink", "ancestor_replace"])
def test_snapshot_parsing_span(separate_documents, monkeypatch, target, parser,
                               baseline, entry, change):
    loader = configured(separate_documents)
    if baseline:
        public_snapshot(loader, entry)
    validate = parser.model_validate
    restores = []

    def parse(*args, **kwargs):
        candidate = validate(*args, **kwargs)
        restores.append(snapshot_mutation(getattr(separate_documents, target), change))
        return candidate

    with monkeypatch.context() as patch:
        patch.setattr(parser, "model_validate", parse)
        rejected_snapshot(loader, entry)
    assert len(restores) == 1
    restores[0]()
    assert_failure(loader)


@pytest.mark.parametrize("baseline", [False, True])
def test_snapshot_both_baselines_and_handles_span_admission(
    separate_documents, monkeypatch, baseline,
):
    loader = configured(separate_documents)
    if baseline:
        loader.load()
    opened, leaf_fds, baselined, parsed = set(), {}, set(), set()
    real_open, real_close, real_fstat, real_read = os.open, os.close, os.fstat, os.read
    names = {getattr(separate_documents, role).name for role in _ROLES}

    def opened_fd(path, *a, **k):
        fd = real_open(path, *a, **k)
        opened.add(fd)
        if path in names:
            assert path not in leaf_fds  # verification uses stat, never leaf reopen
            leaf_fds[path] = fd
        return fd

    def fstat(fd):
        info = real_fstat(fd)
        if fd in leaf_fds.values():
            baselined.add(fd)
        return info

    def held():
        assert len(leaf_fds) == 2
        assert set(leaf_fds.values()) <= baselined <= opened

    def read(fd, count):
        held()
        return real_read(fd, count)

    def close(fd):
        held() if not parsed else None
        assert parsed == names
        assert loader._boundary.snapshot is not None  # decision precedes cleanup
        opened.remove(fd)
        real_close(fd)

    with monkeypatch.context() as patch:
        patch.setattr(os, "open", opened_fd)
        patch.setattr(os, "fstat", fstat)
        patch.setattr(os, "read", read)
        patch.setattr(os, "close", close)
        for model, name in (
            (auth.BingCredentialDocument, separate_documents.bing_credentials_file.name),
            (auth.BingSitePolicy, separate_documents.bing_sites_file.name),
        ):
            validate = model.model_validate

            def parse(*args, _validate=validate, _name=name, **kwargs):
                held()
                parsed.add(_name)
                return _validate(*args, **kwargs)

            patch.setattr(model, "model_validate", parse)
        assert loader.load().api_key.get_secret_value() == KEY
    assert not opened


@pytest.mark.parametrize("target", _ROLES)
@pytest.mark.parametrize("baseline", [False, True])
@pytest.mark.parametrize("business,ordinal", [(False, 1), (False, 2),
                                             (True, 1), (True, 2), (True, 3), (True, 4)])
@pytest.mark.parametrize("change", ["chmod", "replace", "hardlink", "parent_chmod",
                                   "ancestor_replace"])
def test_snapshot_actual_client_zero_dispatch(separate_documents, monkeypatch, target,
                                             baseline, business, ordinal, change):
    from google_seo_mcp.bing import client
    from google_seo_mcp.bing.models import BingOperation, BingToolRequest

    monkeypatch.setattr(client, "_GLOBAL", client._Admission())
    loader = configured(separate_documents)
    if baseline:
        loader.load()
    operation = BingOperation.GET_QUERY_STATS if business else BingOperation.GET_USER_SITES
    request = BingToolRequest(operation=operation, **({"site_url": SITE} if business else {}))
    dispatched, constructed = [], []

    def handler(request):
        dispatched.append(request.method)
        return httpx.Response(200, json={"d": []})

    def actual_httpx(*args, **kwargs):
        assert isinstance(kwargs["transport"], client._GatedTransport)
        constructed.append(True)
        return _REAL_HTTPX_CLIENT(*args, **kwargs)

    monkeypatch.setattr(httpx, "Client", actual_httpx)
    transport = httpx.MockTransport(handler)
    real_client = client.BingReadClient(loader, transport=transport, max_retries=0)
    path = getattr(separate_documents, target)
    before = filesystem_custody(path)
    with monkeypatch.context() as patch:
        receipt = install_cross_read(patch, separate_documents, target, "eof", change, ordinal)
        result = real_client.read(operation, request)
    assert receipt["fired"] and receipt["count"] == ordinal
    assert filesystem_custody(path) != before
    assert result.status == "unavailable" and result.error.code == "credentials_invalid"
    assert dispatched == [] and constructed == []
    assert loader._boundary.custody_failed
    receipt["restore"]()
    assert_failure(loader)
    # A fresh valid generation uses the SAME global slot, with actual HTTPX.
    healthy = client.BingReadClient(configured(separate_documents), transport=transport,
                                    max_retries=0)
    result = healthy.read(operation, request)
    assert result.status == "empty" and result.error is None
    assert dispatched == ["GET"] and constructed == [True]
    assert client._GLOBAL.slot.acquire(blocking=False)
    client._GLOBAL.slot.release()


@pytest.mark.parametrize("target", _ROLES)
@pytest.mark.parametrize("baseline", [False, True])
@pytest.mark.parametrize("entry", ["load", "sites", "authorize", "state"])
@pytest.mark.parametrize("field", ["st_uid", "st_gid"])
@pytest.mark.parametrize("source", ["retained", "configured"])
def test_snapshot_ancestor_owner_group_drift(separate_documents, monkeypatch, target,
                                            baseline, entry, field, source):
    # No chown privilege is assumed. Only the selected final chain source has
    # synthetic owner/group drift; all main matrix attacks use real filesystem I/O.
    loader = configured(separate_documents)
    if baseline:
        public_snapshot(loader, entry)
    ancestor = getattr(separate_documents, target).parent.parent.stat()
    identity = (ancestor.st_dev, ancestor.st_ino)
    real_fstat, real_read, real_open = os.fstat, os.read, os.open
    other = getattr(separate_documents, _ROLES[1] if target == _ROLES[0] else _ROLES[0]).stat()
    trigger = (other.st_dev, other.st_ino)
    fired = False
    originals = set()
    injected = []

    def opened(*a, **k):
        fd = real_open(*a, **k)
        if not fired:
            originals.add(fd)
        return fd

    def read(fd, count):
        nonlocal fired
        raw = real_read(fd, count)
        info = real_fstat(fd)
        if not raw and (info.st_dev, info.st_ino) == trigger:
            fired = True
        return raw

    def fstat(fd):
        info = real_fstat(fd)
        if (fired and (info.st_dev, info.st_ino) == identity
                and ((fd in originals) == (source == "retained"))):
            fields = {name: getattr(info, name) for name in
                      ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid")}
            fields[field] += 123456
            injected.append(fd)
            return SimpleNamespace(**fields)
        return info

    monkeypatch.setattr(os, "open", opened)
    monkeypatch.setattr(os, "read", read)
    monkeypatch.setattr(os, "fstat", fstat)
    rejected_snapshot(loader, entry)
    assert fired and injected


@pytest.mark.parametrize("target", _ROLES)
@pytest.mark.parametrize("observation", ["descriptor", "configured_name"])
@pytest.mark.parametrize("predicate", ["owner", "writable", "executable", "unreadable",
                                       "nonregular", "hardlink"])
def test_snapshot_all_leaf_predicates_both_roles(separate_documents, monkeypatch, target,
                                                observation, predicate):
    # Reuse the preserved independent-predicate regression, retargeting only the
    # selected path while leaving the real key/policy configured correctly.
    documents = separate_documents
    path = getattr(documents, target)
    before = path.stat()
    identity = (before.st_dev, before.st_ino)
    real_read, real_fstat, real_stat = os.read, os.fstat, os.stat
    eof, injected = False, False

    def observed(info, source):
        nonlocal injected
        if not eof or source != observation or (info.st_dev, info.st_ino) != identity:
            return info
        import stat
        fields = {name: getattr(info, name) for name in (
            "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode",
            "st_uid", "st_gid", "st_nlink")}
        updates = {"owner": ("st_uid", os.geteuid() + 123456),
                   "writable": ("st_mode", info.st_mode | 0o020),
                   "executable": ("st_mode", info.st_mode | 0o100),
                   "unreadable": ("st_mode", stat.S_IFREG),
                   "nonregular": ("st_mode", stat.S_IFDIR | 0o600),
                   "hardlink": ("st_nlink", 2)}
        field, value = updates[predicate]
        fields[field] = value
        injected = True
        return SimpleNamespace(**fields)

    def read(fd, count):
        nonlocal eof
        raw = real_read(fd, count)
        info = real_fstat(fd)
        if not raw and (info.st_dev, info.st_ino) == identity:
            eof = True
        return raw

    monkeypatch.setattr(os, "read", read)
    monkeypatch.setattr(os, "fstat", lambda fd: observed(real_fstat(fd), "descriptor"))
    monkeypatch.setattr(os, "stat", lambda *a, **k: observed(real_stat(*a, **k), "configured_name"))
    monkeypatch.setattr(auth, "_fingerprint", lambda info: (1,))
    assert_failure(configured(documents))
    assert injected


@pytest.mark.parametrize("fault", ["first_walk", "second_walk", "second_leaf", "read_key",
                                    "read_policy", "parse_key", "parse_policy",
                                    "observe_key", "observe_policy", "close"])
def test_snapshot_fault_cleanup_and_privacy(separate_documents, monkeypatch, fault, caplog, capsys):
    loader = configured(separate_documents)
    opened, attempted = set(), []
    real_open, real_close, real_read = os.open, os.close, os.read
    role_by_fd = {}
    fired = False
    marker = "SYNTHETIC-foreign-" + str(separate_documents.bing_credentials_file)

    def fail():
        nonlocal fired
        fired = True
        raise OSError(marker)

    roots = 0

    def opened_fd(path, *a, **k):
        nonlocal roots
        if path == "/":
            roots += 1
            if (fault == "first_walk" and roots == 1
                    or fault == "second_walk" and roots == 2):
                fail()
        if fault == "second_leaf" and path == separate_documents.bing_sites_file.name:
            fail()
        fd = real_open(path, *a, **k)
        opened.add(fd)
        if path == separate_documents.bing_credentials_file.name:
            role_by_fd[fd] = "key"
        if path == separate_documents.bing_sites_file.name:
            role_by_fd[fd] = "policy"
        return fd

    def close(fd):
        attempted.append(fd)
        opened.remove(fd)
        real_close(fd)
        if fault == "close" and not fired:
            fail()  # platform close may report error after releasing the FD

    def read(fd, count):
        if fault == "read_" + role_by_fd.get(fd, ""):
            fail()
        return real_read(fd, count)

    with monkeypatch.context() as patch:
        patch.setattr(os, "open", opened_fd)
        patch.setattr(os, "close", close)
        patch.setattr(os, "read", read)
        if fault.startswith("parse"):
            model = auth.BingCredentialDocument if fault.endswith("key") else auth.BingSitePolicy
            patch.setattr(model, "model_validate", lambda *a, **k: fail())
        if fault.startswith("observe"):
            original = auth._HeldDocument.observe

            def observe(held, descriptors):
                if held.path == (separate_documents.bing_credentials_file if fault.endswith("key")
                                 else separate_documents.bing_sites_file):
                    # Inject at the actual final configured-name syscall, so the
                    # production safe exception boundary is exercised.
                    with monkeypatch.context() as final_patch:
                        final_patch.setattr(os, "stat", lambda *a, **k: fail())
                        return original(held, descriptors)
                return original(held, descriptors)

            patch.setattr(auth._HeldDocument, "observe", observe)
        error = assert_failure(loader)
    assert fired and not opened and len(attempted) == len(set(attempted))
    assert loader._boundary.custody_failed
    assert_failure(loader)
    rendered = ("".join(traceback.format_exception(error)) + caplog.text
                + repr(loader._boundary.__dict__))
    captured = capsys.readouterr()
    # Paths are captured configuration, intentionally private; inspect error and
    # emitted output only, not internal configuration fields.
    assert marker not in rendered + captured.out + captured.err
    assert KEY not in rendered + captured.out + captured.err


def test_snapshot_baseexception_unwinds_all_handles(separate_documents, monkeypatch):
    class Cancelled(BaseException):
        pass

    loader = configured(separate_documents)
    opened = set()
    real_open, real_close = os.open, os.close

    def opened_fd(*a, **k):
        fd = real_open(*a, **k)
        opened.add(fd)
        return fd

    def close(fd):
        opened.remove(fd)
        real_close(fd)

    def cancel(*a, **k):
        raise Cancelled()

    monkeypatch.setattr(os, "open", opened_fd)
    monkeypatch.setattr(os, "close", close)
    monkeypatch.setattr(os, "read", cancel)
    with pytest.raises(Cancelled):
        loader.load()
    assert not opened
    assert loader._boundary.snapshot is None


@pytest.mark.parametrize("target", _ROLES)
@pytest.mark.parametrize("kind", ["none", "missing_parent", "missing_leaf"])
def test_snapshot_absence_and_invalid_sibling(separate_documents, target, kind):
    path = getattr(separate_documents, target)
    if kind == "none":
        setattr(separate_documents, target, None)
    elif kind == "missing_parent":
        path.unlink()
        path.parent.rmdir()
    else:
        path.unlink()
    loader = configured(separate_documents)
    assert_failure(loader, "credentials_missing")
    other = getattr(separate_documents, _ROLES[1] if target == _ROLES[0] else _ROLES[0])
    other.write_bytes(b"malformed synthetic")
    assert_failure(loader)
    assert loader._boundary.custody_failed


@pytest.mark.parametrize("target", _ROLES)
def test_snapshot_pending_sibling_does_not_hide_opened_custody_race(
    separate_documents, monkeypatch, target,
):
    other = _ROLES[1] if target == _ROLES[0] else _ROLES[0]
    getattr(separate_documents, other).unlink()
    loader = configured(separate_documents)
    path = getattr(separate_documents, target)
    read = os.read
    fired = []

    def race(fd, count):
        raw = read(fd, count)
        if not raw and not fired:
            path.chmod(0o666)
            fired.append(True)
        return raw

    monkeypatch.setattr(os, "read", race)
    assert_failure(loader)
    assert fired and auth.bing_credentials_state() == "invalid"


def test_snapshot_observation_limit_not_atomic(separate_documents, monkeypatch):
    loader = configured(separate_documents)
    original = auth._HeldDocument.observe
    fired = []

    def observe(held, descriptors):
        original(held, descriptors)
        if held.path == separate_documents.bing_credentials_file:
            # Deliberately AFTER key's last observation, not a required rejection.
            held.path.chmod(0o666)
            fired.append(True)

    with monkeypatch.context() as patch:
        patch.setattr(auth._HeldDocument, "observe", observe)
        assert loader.load().api_key.get_secret_value() == KEY
    assert fired and separate_documents.bing_credentials_file.stat().st_mode & 0o022
    assert_failure(loader)  # the next observation rejects


def test_snapshot_restored_directory_metadata_control(separate_documents, monkeypatch):
    loader = configured(separate_documents)
    read = os.read
    fired = []

    def transient(fd, count):
        raw = read(fd, count)
        if not fired:
            parent = separate_documents.bing_credentials_file.parent
            parent.chmod(0o500)
            parent.chmod(0o700)
            fired.append(True)
        return raw

    monkeypatch.setattr(os, "read", transient)
    assert loader.load().api_key.get_secret_value() == KEY
    assert fired  # no false promise of detecting a fully restored history


@pytest.mark.parametrize("target", _ROLES)
@pytest.mark.parametrize("baseline", [False, True])
@pytest.mark.parametrize("phase", ["data", "eof"])
@pytest.mark.parametrize("entry", ["load", "sites", "authorize", "state"])
def test_snapshot_cross_hardlink_nlink_only(separate_documents, monkeypatch, target,
                                           baseline, phase, entry):
    loader = configured(separate_documents)
    if baseline:
        public_snapshot(loader, entry)
    path = getattr(separate_documents, target)
    before = path.stat()
    real_fstat, real_stat = os.fstat, os.stat
    observations = []

    def frozen(info):
        if (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino):
            return info
        fields = {name: getattr(before, name) for name in (
            "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode",
            "st_uid", "st_gid")}
        fields["st_nlink"] = info.st_nlink
        observations.append(fields)
        return SimpleNamespace(**fields)

    with monkeypatch.context() as patch:
        receipt = install_cross_read(patch, separate_documents, target, phase, "hardlink")
        patch.setattr(os, "fstat", lambda fd: frozen(real_fstat(fd)))
        patch.setattr(os, "stat", lambda *a, **k: frozen(real_stat(*a, **k)))
        rejected_snapshot(loader, entry)
    assert receipt["fired"] and path.stat().st_nlink == 2
    assert any(info["st_nlink"] == 2 for info in observations)
    assert all(all(value == getattr(before, name) for name, value in info.items()
                   if name != "st_nlink") for info in observations)
    receipt["restore"]()
    assert_failure(loader)


def test_snapshot_close_cancellation_still_attempts_every_handle(separate_documents, monkeypatch):
    class Cancelled(BaseException):
        pass

    loader = configured(separate_documents)
    opened, attempted = set(), []
    real_open, real_close = os.open, os.close

    def opened_fd(*a, **k):
        fd = real_open(*a, **k)
        opened.add(fd)
        return fd

    def close(fd):
        opened.remove(fd)
        attempted.append(fd)
        real_close(fd)
        if len(attempted) == 1:
            raise Cancelled()

    monkeypatch.setattr(os, "open", opened_fd)
    monkeypatch.setattr(os, "close", close)
    with pytest.raises(Cancelled):
        loader.load()
    assert not opened and len(attempted) == len(set(attempted))
    assert loader._boundary.custody_failed
    assert_failure(loader)


def test_snapshot_reconfigure_waits_for_inspection(separate_documents, monkeypatch):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    loader = configured(separate_documents)
    entered, release, replacing = threading.Event(), threading.Event(), threading.Event()
    original = os.read

    def paused(fd, count):
        if not entered.is_set():
            entered.set()
            assert release.wait(5)
        return original(fd, count)

    def replace():
        replacing.set()
        auth.configure_bing_auth(separate_documents)

    with monkeypatch.context() as patch, ThreadPoolExecutor(max_workers=2) as workers:
        patch.setattr(os, "read", paused)
        current = workers.submit(loader.load)
        try:
            assert entered.wait(5)
            new = workers.submit(replace)
            assert replacing.wait(5)
            assert not loader._boundary.lock.acquire(blocking=False)
        finally:
            release.set()
        assert current.result(5).api_key.get_secret_value() == KEY
        new.result(5)
    assert_failure(loader)
    assert auth.BingCredentialLoader().load().api_key.get_secret_value() == KEY


@pytest.mark.parametrize("business", [False, True])
@pytest.mark.parametrize("target", _ROLES)
def test_snapshot_actual_client_between_successful_inspections(separate_documents, monkeypatch,
                                                              business, target):
    from google_seo_mcp.bing import client
    from google_seo_mcp.bing.models import BingOperation, BingToolRequest

    monkeypatch.setattr(client, "_GLOBAL", client._Admission())
    monkeypatch.setattr(httpx, "Client", _REAL_HTTPX_CLIENT)
    loader = configured(separate_documents)
    load = loader.load
    calls, dispatched, restores = [], [], []

    def returned():
        document = load()
        calls.append(True)
        if len(calls) == 1:
            restores.append(snapshot_mutation(getattr(separate_documents, target), "replace"))
        return document

    monkeypatch.setattr(loader, "load", returned)
    operation = BingOperation.GET_QUERY_STATS if business else BingOperation.GET_USER_SITES
    request = BingToolRequest(operation=operation, **({"site_url": SITE} if business else {}))

    def handler(request):
        dispatched.append(True)
        return httpx.Response(200, json={"d": []})

    actual = client.BingReadClient(loader, transport=httpx.MockTransport(handler), max_retries=0)
    result = actual.read(operation, request)
    assert restores and calls == [True]
    assert result.error.code == "credentials_invalid" and dispatched == []
    restores[0]()
    assert_failure(loader)


@pytest.mark.parametrize("target", _ROLES)
@pytest.mark.parametrize("baseline", [False, True])
def test_snapshot_read_growth_bounded(separate_documents, monkeypatch, target, baseline):
    loader = configured(separate_documents)
    if baseline:
        loader.load()
    path = getattr(separate_documents, target)
    before = path.stat()
    cap = 16384 if target == _ROLES[0] else 65536
    read, fstat = os.read, os.fstat
    lengths, requested, fired = [], [], []

    def grow(fd, count):
        raw = read(fd, count)
        info = fstat(fd)
        if (info.st_dev, info.st_ino) == (before.st_dev, before.st_ino):
            requested.append(count)
            lengths.append(len(raw))
            if not fired:
                with path.open("ab") as stream:
                    stream.write(b" " * (cap + 1))
                fired.append(True)
        return raw

    monkeypatch.setattr(os, "read", grow)
    assert_failure(loader)
    assert fired and sum(lengths) == cap + 1
    assert max(requested) <= 8192


@pytest.mark.parametrize("missing", _ROLES)
def test_snapshot_missing_role_not_reopened_midcall(separate_documents, monkeypatch, missing):
    path = getattr(separate_documents, missing)
    raw = path.read_bytes()
    path.unlink()
    loader = configured(separate_documents)
    read = os.read
    fired = []

    def enroll(fd, count):
        result = read(fd, count)
        if not fired:
            path.write_bytes(raw)
            path.chmod(0o600)
            fired.append(True)
        return result

    with monkeypatch.context() as patch:
        patch.setattr(os, "read", enroll)
        assert_failure(loader, "credentials_missing")
    assert fired and path.exists()
    assert_failure(loader)
    assert configured(separate_documents).load().api_key.get_secret_value() == KEY
