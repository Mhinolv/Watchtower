import json
import os
import stat
from pathlib import Path

import pytest

from watchtower_engine.inventory import apps, sparkle
from watchtower_engine.inventory.sparkle import (
    NOTE_CREDENTIALS, NOTE_LOCAL, NOTE_NOT_HTTPS, NOTE_UPDATE, Target, check, parse_appcast, url_problem,
)
from watchtower_engine.models import CoverageRecord as C
from watchtower_engine.models import ItemRecord as I
from watchtower_engine.refresh import Source, run_refresh
from watchtower_engine.store import Store

from contract import Clock
from test_apps import make_app

FIX = Path(__file__).parent / "fixtures" / "sparkle"
FEED = "https://example.com/appcast.xml"
T1, T2 = "2026-10-28T09:12:00Z", "2026-10-29T09:12:00Z"


def appcast(name):
    return (FIX / name).read_bytes()


class FakeFetch:
    """Answers by URL with bytes or raises. Never uses the network."""

    def __init__(self, answers=None):
        self.answers, self.calls = answers or {}, []

    def __call__(self, url):
        self.calls.append(url)
        answer = self.answers.get(url, OSError("network is disabled in tests"))
        if isinstance(answer, BaseException):
            raise answer
        return answer


def app_item(installed="3.3.0", name="Quillnote"):
    return I(f"com.example.{name.lower()}", "apps", name, "manual", kind="app", installed_version=installed,
             origin="Manual", note="Update this app from its vendor.", attributes={"path": f"/Applications/{name}.app"})


def run(targets, data, fetch, now=T2, os_version="15.1"):
    return check(targets, data, fetch=fetch, now=lambda: now, os_version=os_version)


# URL rules


@pytest.mark.parametrize("url,problem", [
    ("https://example.com/appcast.xml", None),
    ("https://example.com/appcast.xml?channel=beta", None),
    ("http://example.com/appcast.xml", NOTE_NOT_HTTPS),
    ("ftp://example.com/appcast.xml", NOTE_NOT_HTTPS),
    ("appcast.xml", NOTE_NOT_HTTPS),
    ("https://user:secret@example.com/appcast.xml", NOTE_CREDENTIALS),
    ("https://token@example.com/appcast.xml", NOTE_CREDENTIALS),
    ("https://example.com/appcast.xml?token=abc", NOTE_CREDENTIALS),
    ("https://example.com/appcast.xml?api_key=abc&x=1", NOTE_CREDENTIALS),
    ("https://localhost/appcast.xml", NOTE_LOCAL),
    ("https://127.0.0.1/appcast.xml", NOTE_LOCAL),
    ("https://10.0.0.5/appcast.xml", NOTE_LOCAL),
    ("https://192.168.1.2:8443/appcast.xml", NOTE_LOCAL),
    ("https://[::1]/appcast.xml", NOTE_LOCAL),
    ("https://169.254.169.254/latest", NOTE_LOCAL),
    ("https://nas.local/appcast.xml", NOTE_LOCAL),
    # QA 14-1 defect 2: numeric host forms that the OS reads as a local address.
    ("https://2130706433/appcast.xml", NOTE_LOCAL),
    ("https://127.1/appcast.xml", NOTE_LOCAL),
    ("https://0x7f.0.0.1/appcast.xml", NOTE_LOCAL),
    ("https://017700000001/appcast.xml", NOTE_LOCAL),
    ("https://0/appcast.xml", NOTE_LOCAL),
    ("https://0xa000005/appcast.xml", NOTE_LOCAL),
    ("https://[::ffff:127.0.0.1]/appcast.xml", NOTE_LOCAL),
    ("https://[fd00::1]/appcast.xml", NOTE_LOCAL),
    ("https://100.64.0.1/appcast.xml", NOTE_LOCAL),
    ("https://8.8.8.8/appcast.xml", None),
])
def test_url_rules(url, problem):
    assert url_problem(url) == problem


def test_credentials_are_never_shown():
    assert sparkle.shown_url("https://user:secret@example.com/a.xml") is None
    assert sparkle.shown_url("https://example.com/a.xml?token=x") is None
    assert sparkle.shown_url(FEED) == FEED


def test_redirect_to_an_unsafe_address_is_refused():
    handler = sparkle._SafeRedirects()
    with pytest.raises(Exception):
        handler.redirect_request(None, None, 302, "Found", {}, "http://example.com/appcast.xml")
    with pytest.raises(Exception):
        handler.redirect_request(None, None, 302, "Found", {}, "https://127.0.0.1/appcast.xml")


# Parse (untrusted XML)


def test_parse_reads_version_build_minimum_os_and_channel():
    releases = parse_appcast(appcast("stable.xml"))
    assert [(r.version, r.build, r.minimum_os, r.channel) for r in releases] == [
        ("3.4.1", "341", "14.0", None),
        ("3.3.0", "330", None, None),  # from the enclosure attributes
    ]  # the Windows release is left out
    beta = parse_appcast(appcast("beta.xml"))
    assert [(r.version, r.channel) for r in beta] == [("3.4.1", None), ("3.5b1", "beta")]


@pytest.mark.parametrize("data", [
    b"<rss><channel><item><title>no version</title></item></channel></rss>",
    b"not xml at all",
    b"<rss><channel>",
])
def test_parse_refuses_documents_without_a_release(data):
    with pytest.raises(ValueError):
        parse_appcast(data)


def test_parse_refuses_dtd_and_entities():
    with pytest.raises(ValueError, match="DTD or entities"):
        parse_appcast(appcast("entities.xml"))


# QA 14-1 defect 1: the same document in another encoding must also be refused.
ENTITY_APPCAST = ('<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE rss [<!ENTITY a "EXPANDED">]>'
                  '<rss xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle" version="2"><channel>'
                  '<item><enclosure sparkle:version="9" sparkle:shortVersionString="&a;"/></item></channel></rss>')


@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-le", "utf-16-be"])
def test_parse_refuses_dtd_and_entities_in_any_encoding(encoding):
    with pytest.raises(ValueError, match="DTD or entities"):
        parse_appcast(ENTITY_APPCAST.encode(encoding))


def test_parse_refuses_a_doctype_after_the_first_4096_bytes():
    data = ('<?xml version="1.0"?><!--' + "x" * 5000 + '--><!DOCTYPE rss SYSTEM "http://127.0.0.1:9/x.dtd">'
            + ENTITY_APPCAST.split("]>", 1)[1].replace("&a;", "1.0"))
    with pytest.raises(ValueError, match="DTD or entities"):
        parse_appcast(data.encode())


def test_parse_refuses_a_doctype_without_entities():
    data = appcast("stable.xml").replace(b"<rss", b"<!DOCTYPE rss SYSTEM \"https://example.com/x.dtd\">\n<rss", 1)
    with pytest.raises(ValueError, match="DTD or entities"):
        parse_appcast(data)


def test_parse_reads_a_utf16_appcast_without_a_dtd():
    text = appcast("stable.xml").decode().replace('encoding="utf-8"', 'encoding="UTF-16"')
    assert parse_appcast(text.encode("utf-16"))[0].version == "3.4.1"


# Compare


def test_newer_stable_is_update_available(tmp_path):
    item = app_item("3.3.0")
    result = run([Target(item, FEED, "330")], tmp_path, FakeFetch({FEED: appcast("stable.xml")}))
    assert (item.state, item.latest_version, item.origin) == ("update_available", "3.4.1", "Sparkle feed")
    assert item.note == NOTE_UPDATE == "Use the app's Check for Updates command to install it."
    assert item.attributes["sparkleFeed"] == FEED
    assert item.attributes["sparkleLatest"] == "3.4.1 (341)"
    assert item.attributes["sparkleChannel"] == "Stable"
    assert item.attributes["sparkleMinimumOs"] == "14.0"
    assert item.attributes["sparkleChecked"] == T2
    assert result.coverage == C("sparkle", "Sparkle feeds", "complete", note="1 of 1 read")


def test_same_build_is_up_to_date(tmp_path):
    item = app_item("3.4.1")
    run([Target(item, FEED, "341")], tmp_path, FakeFetch({FEED: appcast("stable.xml")}))
    assert (item.state, item.latest_version, item.note) == ("up_to_date", "3.4.1", None)


def test_only_a_newer_beta_stays_up_to_date_with_a_note(tmp_path):
    item = app_item("3.4.1")
    run([Target(item, FEED, "341")], tmp_path, FakeFetch({FEED: appcast("beta.xml")}))
    assert (item.state, item.latest_version) == ("up_to_date", "3.4.1")
    assert item.note == "A beta (3.5b1) is available."


def test_newer_version_for_a_newer_macos_is_a_manual_update(tmp_path):
    item = app_item("3.3.0")
    run([Target(item, FEED, "330")], tmp_path, FakeFetch({FEED: appcast("newer-os.xml")}), os_version="15.1")
    assert item.state == "manual"
    assert item.note == "3.4.1 needs macOS 15.2. This Mac has 15.1."
    item2 = app_item("3.3.0")
    run([Target(item2, FEED, "330")], tmp_path, FakeFetch({FEED: appcast("newer-os.xml")}), os_version="15.2")
    assert item2.state == "update_available"


@pytest.mark.parametrize("url,note", [
    ("http://example.com/appcast.xml", "Watchtower reads HTTPS feeds only."),
    ("https://user:pw@example.com/appcast.xml", "The feed address has credentials. Watchtower did not read it."),
    ("https://127.0.0.1/appcast.xml", NOTE_LOCAL),
])
def test_rejected_feed_is_unknown_and_never_fetched(tmp_path, url, note):
    item = app_item()
    fetch = FakeFetch()
    result = run([Target(item, url, "330")], tmp_path, fetch)
    assert (item.state, item.note) == ("unknown", note)
    assert fetch.calls == []
    if note == NOTE_CREDENTIALS:
        assert "sparkleFeed" not in item.attributes
    assert result.coverage.note == "0 of 1 read"


def test_failed_check_keeps_the_previous_evidence(tmp_path):
    first = app_item("3.3.0")
    run([Target(first, FEED, "330")], tmp_path, FakeFetch({FEED: appcast("stable.xml")}), now=T1)
    again = app_item("3.3.0")
    result = run([Target(again, FEED, "330")], tmp_path, FakeFetch(), now=T2)  # the feed fails
    assert (again.state, again.latest_version) == ("update_available", "3.4.1")  # earlier badge and version
    assert again.error == "Feed check failed."
    assert again.attributes["sparkleChecked"] == T1  # data from the earlier check
    assert result.coverage.state == "failed" and result.coverage.note == "0 of 1 read"
    assert "network is disabled" in result.coverage.detail


def test_failed_check_with_no_earlier_data_keeps_the_manual_route(tmp_path):
    item = app_item("3.3.0")
    run([Target(item, FEED, "330")], tmp_path, FakeFetch())
    assert (item.state, item.origin, item.latest_version) == ("manual", "Manual", None)
    assert item.error == "Feed check failed."


def test_bad_appcast_is_a_failed_check(tmp_path):
    item = app_item("3.3.0")
    run([Target(item, FEED, "330")], tmp_path, FakeFetch({FEED: appcast("entities.xml")}))
    assert item.error == "Feed check failed." and "DTD" in item.detail


def test_coverage_counts_feeds_read(tmp_path):
    other = "https://example.org/feed.xml"
    targets = [Target(app_item(name="A"), FEED, "330"), Target(app_item(name="B"), other, "330"),
               Target(app_item(name="C"), "http://example.net/x.xml", "330")]
    result = run(targets, tmp_path, FakeFetch({FEED: appcast("stable.xml")}))
    assert (result.coverage.state, result.coverage.note) == ("partial", "1 of 3 read")
    assert result.coverage.error == "Some Sparkle feeds did not load."
    assert run([], tmp_path, FakeFetch()).coverage.state == "not_run"


def test_cache_file_is_private(tmp_path):
    run([Target(app_item(), FEED, "330")], tmp_path, FakeFetch({FEED: appcast("stable.xml")}))
    path = tmp_path / "cache" / "sparkle.json"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert json.loads(path.read_text())["com.example.quillnote"]["build"] == "341"


# The app inventory


def test_app_inventory_checks_feeds_of_manual_apps_only(tmp_path):
    root = tmp_path / "Applications"
    make_app(root, "Quillnote.app", "com.example.quillnote", version="3.3.0", build="330",
             extra={"SUFeedURL": FEED})
    make_app(root, "Plain.app", "com.example.plain", version="1.0", build="100")
    fetch = FakeFetch({FEED: appcast("stable.xml")})
    result = apps.collect((str(root),), sparkle_check=lambda t: check(t, tmp_path / "data", fetch=fetch,
                                                                       now=lambda: T2, os_version="15.1"))
    items = {i.name: i for i in result.items}
    assert (items["Quillnote"].state, items["Quillnote"].latest_version) == ("update_available", "3.4.1")
    assert (items["Plain"].state, items["Plain"].origin) == ("manual", "Manual")  # v1 manual route
    assert fetch.calls == [FEED]
    assert [c.source for c in result.extra_coverage] == ["sparkle"]


def test_without_a_check_the_inventory_is_unchanged(tmp_path):
    root = tmp_path / "Applications"
    make_app(root, "Quillnote.app", "com.example.quillnote", version="3.3.0", build="330",
             extra={"SUFeedURL": FEED})
    result = apps.collect((str(root),))
    assert result.items[0].state == "manual" and not hasattr(result, "extra_coverage")


def test_cask_linked_app_with_a_version_is_not_checked(tmp_path):
    root = tmp_path / "Applications"
    make_app(root, "Fluff.app", "com.example.fluff", version="1.2", build="100", extra={"SUFeedURL": FEED})
    cask = {"token": "fluff", "installed": "1.2", "artifacts": [{"app": ["Fluff.app"]}]}
    cask_item = I("cask:fluff", "homebrew", "fluff", "update_available", kind="cask", installed_version="1.2",
                  latest_version="1.3")
    fetch = FakeFetch({FEED: appcast("stable.xml")})
    result = apps.collect((str(root),), [cask], [cask_item],
                          sparkle_check=lambda t: check(t, tmp_path / "data", fetch=fetch))
    assert result.items[0].latest_version == "1.3" and fetch.calls == []


def test_refresh_saves_the_sparkle_coverage(tmp_path):
    from watchtower_engine.inventory.homebrew import SourceResult

    def apps_source():
        r = SourceResult(C("apps", "Applications", "complete"), [app_item()])
        r.extra_coverage = [C("sparkle", "Sparkle feeds", "complete", note="1 of 1 read")]
        return r

    with Store(tmp_path, clock=Clock(*[f"2026-10-29T10:{m:02d}:00Z" for m in range(10)])) as s:
        state = run_refresh(s, [Source("apps", "Applications", apps_source)])
    cov = {c["source"]: c for c in state["coverage"]}
    assert cov["sparkle"]["note"] == "1 of 1 read" and cov["sparkle"]["state"] == "complete"


# #67: a host name that resolves to a local address. The tests use a fake resolver, never DNS.

import functools
import socket


class FakeResolver:
    """Answers by host name with a list of addresses. Each call takes the next answer."""

    def __init__(self, *answers):
        self.answers, self.calls = list(answers), []

    def __call__(self, host, port):
        self.calls.append((host, port))
        return self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]


class Stop(Exception):
    pass


def resolving(resolver):
    return functools.partial(sparkle.fetch_feed, resolve=resolver)


@pytest.mark.parametrize("addresses", [["10.0.0.5"], ["127.0.0.1"], ["169.254.169.254"], ["192.168.1.2", "10.1.1.1"],
                                       ["::1"], ["fe80::1%en0"], ["fd00::5"], ["100.64.0.1"],
                                       ["93.184.216.34", "192.168.1.2"]])
def test_a_host_name_that_resolves_to_a_local_address_is_refused(tmp_path, monkeypatch, addresses):
    connects = []
    monkeypatch.setattr(socket, "create_connection", lambda *a, **kw: connects.append(a) or (_ for _ in ()).throw(Stop()))
    item = app_item()
    result = run([Target(item, "https://updates.example.com/appcast.xml", "330")], tmp_path,
                 resolving(FakeResolver(addresses)))
    assert (item.state, item.note) == ("unknown", NOTE_LOCAL)
    assert item.error is None
    assert connects == []  # Refused before any connection.
    assert result.coverage.note == "0 of 1 read"


def test_the_connection_goes_to_the_checked_address_not_a_later_dns_answer(monkeypatch):
    connects = []

    def create_connection(address, *args, **kwargs):
        connects.append(address)
        raise Stop()

    monkeypatch.setattr(socket, "create_connection", create_connection)
    resolver = FakeResolver(["93.184.216.34"], ["127.0.0.1"])  # A second DNS answer would be local.
    with pytest.raises(Exception):
        sparkle.fetch_feed("https://updates.example.com/appcast.xml", resolve=resolver)
    assert resolver.calls == [("updates.example.com", 443)]
    assert connects == [("93.184.216.34", 443)]


def test_tls_still_checks_the_host_name(monkeypatch):
    wrapped = []

    class Context:
        def wrap_socket(self, sock, server_hostname=None, **kw):
            wrapped.append(server_hostname)
            raise Stop()

    monkeypatch.setattr(socket, "create_connection", lambda *a, **kw: object())
    conn = sparkle._PinnedHTTPSConnection("updates.example.com", addresses=["93.184.216.34"], context=Context())
    with pytest.raises(Stop):
        conn.connect()
    assert wrapped == ["updates.example.com"]


def test_a_host_name_that_does_not_resolve_is_a_failed_check(tmp_path):
    item = app_item()
    result = run([Target(item, "https://updates.example.com/appcast.xml", "330")], tmp_path,
                 resolving(FakeResolver([])))
    assert item.error == sparkle.ERROR_FAILED
    assert result.coverage.state == "failed"


def test_numeric_hosts_are_still_refused_before_any_lookup(tmp_path):
    resolver = FakeResolver(["93.184.216.34"])
    item = app_item()
    run([Target(item, "https://127.1/appcast.xml", "330")], tmp_path, resolving(resolver))
    assert (item.state, item.note) == ("unknown", NOTE_LOCAL)
    assert resolver.calls == []


# #77: try each checked address in order until one connects. A fake resolver and a fake connection, no network.

import io
import ssl

A1, A2, A3 = "93.184.216.34", "93.184.216.35", "2606:2800:220:1::1"
HOST_URL = "https://updates.example.com/appcast.xml"


class FakeSocket:
    """A connected socket that answers one HTTP request with a canned response."""

    def __init__(self, body: bytes):
        self.response = (b"HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: "
                         + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
        self.sent = b""

    def sendall(self, data):
        self.sent += data

    def makefile(self, mode="rb", buffering=None):
        return io.BytesIO(self.response)

    def settimeout(self, value):
        pass

    def close(self):
        pass


class FakeNetwork:
    """Stands in for `socket.create_connection` and the TLS wrap. `up` lists the addresses that answer."""

    def __init__(self, monkeypatch, up=(), body=b"", tls_error=None):
        self.up, self.body, self.tls_error = set(up), body, tls_error
        self.connects, self.wrapped = [], []
        monkeypatch.setattr(socket, "create_connection", self.connect)
        monkeypatch.setattr(ssl.SSLContext, "wrap_socket", self.wrap)

    def connect(self, address, timeout=None, source_address=None):
        self.connects.append(address)
        if address[0] not in self.up:
            raise ConnectionRefusedError(f"{address[0]} does not answer")
        return FakeSocket(self.body)

    def wrap(self, sock, server_hostname=None, **kwargs):
        self.wrapped.append(server_hostname)
        if self.tls_error:
            raise self.tls_error
        return sock


def second_address_check(tmp_path, monkeypatch, up, addresses=(A1, A2), now=T2):
    net = FakeNetwork(monkeypatch, up, appcast("stable.xml"))
    resolver = FakeResolver(list(addresses))
    item = app_item("3.3.0")
    result = run([Target(item, HOST_URL, "330")], tmp_path, resolving(resolver), now=now)
    return net, resolver, item, result


def test_the_second_address_is_tried_when_the_first_does_not_connect(tmp_path, monkeypatch):
    net, resolver, item, result = second_address_check(tmp_path, monkeypatch, up={A2})
    assert net.connects == [(A1, 443), (A2, 443)]  # In the order of the answer.
    assert (item.state, item.latest_version, item.error) == ("update_available", "3.4.1", None)
    assert result.coverage.state == "complete" and result.coverage.note == "1 of 1 read"
    assert resolver.calls == [("updates.example.com", 443)]  # One lookup: no later DNS answer moves the connection.
    assert net.wrapped == ["updates.example.com"]  # TLS checks the certificate against the host name.


def test_the_first_address_that_connects_is_the_only_one_used(tmp_path, monkeypatch):
    net, _, item, _ = second_address_check(tmp_path, monkeypatch, up={A1, A2})
    assert net.connects == [(A1, 443)] and item.latest_version == "3.4.1"


def test_a_later_address_in_a_longer_list_is_reached(tmp_path, monkeypatch):
    net, _, item, _ = second_address_check(tmp_path, monkeypatch, up={A3}, addresses=(A1, A2, A3))
    assert net.connects == [(A1, 443), (A2, 443), (A3, 443)] and item.latest_version == "3.4.1"


def test_every_address_failing_is_a_failed_check_that_keeps_the_last_good_result(tmp_path, monkeypatch):
    second_address_check(tmp_path, monkeypatch, up={A2}, now=T1)  # A good check fills the cache.
    net, _, again, result = second_address_check(tmp_path, monkeypatch, up=set(), now=T2)
    assert net.connects == [(A1, 443), (A2, 443)]  # Each checked address was tried.
    assert (again.state, again.latest_version) == ("update_available", "3.4.1")  # The earlier badge and version.
    assert again.error == "Feed check failed." and again.attributes["sparkleChecked"] == T1
    assert result.coverage.state == "failed" and "does not answer" in result.coverage.detail


def test_a_local_address_anywhere_in_the_answer_is_refused_before_any_connect(tmp_path, monkeypatch):
    for addresses in ((A1, "192.168.1.2"), ("10.0.0.5", A1), (A1, A2, "127.0.0.1"), (A1, "fd00::5")):
        net, _, item, _ = second_address_check(tmp_path, monkeypatch, up={A1, A2}, addresses=addresses)
        assert (item.state, item.note) == ("unknown", NOTE_LOCAL)
        assert net.connects == []  # The global address is not used either.


def test_a_tls_failure_on_a_connected_address_is_not_retried_on_the_next(tmp_path, monkeypatch):
    net = FakeNetwork(monkeypatch, {A1, A2}, appcast("stable.xml"), tls_error=ssl.SSLCertVerificationError("bad host"))
    item = app_item("3.3.0")
    result = run([Target(item, HOST_URL, "330")], tmp_path, resolving(FakeResolver([A1, A2])))
    assert net.connects == [(A1, 443)] and net.wrapped == ["updates.example.com"]
    assert item.error == "Feed check failed." and result.coverage.state == "failed"


def test_checked_addresses_keep_the_order_drop_repeats_and_scope_ids():
    resolver = FakeResolver([A2, A1, A2, A3 + "%en0"])
    assert sparkle.checked_addresses("updates.example.com", 443, resolver) == [A2, A1, A3]


def test_checked_addresses_refuse_the_whole_list_for_one_local_address():
    with pytest.raises(sparkle.LocalAddress):
        sparkle.checked_addresses("updates.example.com", 443, FakeResolver([A1, "100.64.0.1"]))
    with pytest.raises(OSError):
        sparkle.checked_addresses("updates.example.com", 443, FakeResolver([]))


def test_a_redirect_host_is_checked_and_tried_the_same_way(tmp_path, monkeypatch):
    redirect = (b"HTTP/1.1 302 Found\r\nLocation: https://cdn.example.net/appcast.xml\r\nContent-Length: 0\r\n\r\n")

    class Net(FakeNetwork):
        def connect(self, address, timeout=None, source_address=None):
            self.connects.append(address)
            if address[0] in ("93.184.216.40",):
                raise ConnectionRefusedError("down")
            sock = FakeSocket(self.body)
            if len(self.connects) == 1:
                sock.response = redirect
            return sock

    net = Net(monkeypatch, up=(), body=appcast("stable.xml"))
    resolver = FakeResolver([A1], ["93.184.216.40", A2])  # The second host: first address down, second up.
    item = app_item("3.3.0")
    run([Target(item, HOST_URL, "330")], tmp_path, resolving(resolver))
    assert [h for h, _ in resolver.calls] == ["updates.example.com", "cdn.example.net"]
    assert net.connects == [(A1, 443), ("93.184.216.40", 443), (A2, 443)]
    assert item.latest_version == "3.4.1" and net.wrapped == ["updates.example.com", "cdn.example.net"]
