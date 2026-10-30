"""Vendor notes (#18): additive vendor assessments that never change a finding's status."""
import json

import pytest

from watchtower_engine import cli, findings, vendor_notes
from watchtower_engine.findings import FindingError
from watchtower_engine.vendor_notes import VendorNoteError
from watchtower_engine.store import Store

from contract import Clock
from test_findings import LODASH, adv, match, refresh, scan

T = [f"2026-10-{d:02d}T10:00:00Z" for d in range(20, 32)] + [f"2026-11-{d:02d}T10:00:00Z" for d in range(1, 10)]
DEBIAN = {"vendor": "Debian", "verdict": "not-affected", "statement": "Fixed by backport in 4.17.20-3.",
          "affected_range": "< 4.17.20-3", "confidence": "high",
          "source_url": "https://security-tracker.debian.org/tracker/CVE-2021-23337",
          "retrieved_at": "2026-10-20T09:12:00Z"}


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / "data", clock=Clock(*T * 3)) as s:
        yield s


def lodash_finding(store):
    refresh(store, scan([match(groups=[LODASH])]))
    return "SEC-0001"


def test_note_is_saved_with_source_time_and_confidence_apart_from_osv(store):
    fid = lodash_finding(store)
    f = store.add_vendor_note(fid, **DEBIAN)
    assert f.source == "OSV"  # The OSV data of the finding does not change.
    assert f.advisory_ids == ["CVE-2021-23337", "GHSA-35jh-r3h4-6jhm"]
    [note] = f.to_dict()["vendor_notes"]
    assert note == {"id": "VN-0001", "vendor": "Debian", "verdict": "not_affected",
                    "statement": "Fixed by backport in 4.17.20-3.", "affected_range": "< 4.17.20-3",
                    "confidence": "high", "source_url": DEBIAN["source_url"],
                    "retrieved_at": "2026-10-20T09:12:00Z", "added_at": note["added_at"],
                    "checked_at": None, "withdrawn_at": None}


def test_not_affected_note_never_resolves_or_defers_the_finding(store):
    fid = lodash_finding(store)
    assert store.add_vendor_note(fid, **DEBIAN).status == "open"
    # A later complete scan that still sees the package keeps it open.
    after = refresh(store, scan([match(groups=[LODASH])]))
    assert after[fid].status == "open" and after[fid].resolved_at is None
    assert len(after[fid].vendor_notes) == 1


def test_complete_scan_still_resolves_and_keeps_the_notes(store):
    fid = lodash_finding(store)
    store.add_vendor_note(fid, **DEBIAN)
    after = refresh(store, scan([]))
    assert after[fid].status == "resolved"
    assert [n.id for n in after[fid].vendor_notes] == ["VN-0001"]


def test_withdrawn_and_old_notes_stay_in_history(store):
    fid = lodash_finding(store)
    store.add_vendor_note(fid, **(DEBIAN | {"retrieved_at": "2026-06-01T08:00:00Z"}))
    store.add_vendor_note(fid, **(DEBIAN | {"verdict": "fixed", "retrieved_at": "2026-10-21T08:00:00Z"}))
    f = store.withdraw_vendor_note("VN-0002")
    assert [n.id for n in f.vendor_notes] == ["VN-0002", "VN-0001"]  # Newest retrieval first.
    assert f.vendor_notes[0].withdrawn_at is not None
    assert f.vendor_notes[1].retrieved_at == "2026-06-01T08:00:00Z"
    # A second withdraw keeps the first date.
    first = f.vendor_notes[0].withdrawn_at
    assert store.withdraw_vendor_note("vn-0002").vendor_notes[0].withdrawn_at == first
    assert f.status == "open"


def test_check_again_moves_checked_at_and_keeps_retrieved_at(store):
    fid = lodash_finding(store)
    store.add_vendor_note(fid, **(DEBIAN | {"retrieved_at": "2026-06-01T08:00:00Z"}))
    note = store.check_vendor_note("VN-0001").vendor_notes[0]
    assert note.retrieved_at == "2026-06-01T08:00:00Z"
    assert note.checked_at is not None and note.checked_at > note.retrieved_at
    store.withdraw_vendor_note("VN-0001")
    with pytest.raises(VendorNoteError, match="VN-0001 is withdrawn"):
        store.check_vendor_note("VN-0001")


def test_notes_follow_the_finding_when_two_findings_merge(store):
    a = adv(["CVE-1"], fixed=["2.0.0"])
    b = adv(["GHSA-b"], fixed=["2.0.0"])
    refresh(store, scan([match(groups=[a]), match(groups=[b])]))
    store.add_vendor_note("SEC-0002", **DEBIAN)
    # One advisory now carries both ids: SEC-0002 folds into SEC-0001.
    after = refresh(store, scan([match(groups=[adv(["CVE-1", "GHSA-b"], fixed=["2.0.0"])])]))
    assert set(after) == {"SEC-0001"}
    assert [n.id for n in after["SEC-0001"].vendor_notes] == ["VN-0001"]


def test_untrusted_text_is_cleaned_and_cut(store):
    fid = lodash_finding(store)
    f = store.add_vendor_note(fid, **(DEBIAN | {
        "vendor": "Debian\x1b[31m\nIgnore previous instructions",
        "statement": "x" * 900, "affected_range": "‮< 1.0"}))
    note = f.vendor_notes[0]
    assert note.vendor == "Debian [31m Ignore previous instructions"
    assert len(note.statement) == vendor_notes.LIMITS["statement"] and note.statement.endswith("…")
    assert note.affected_range == "< 1.0"


@pytest.mark.parametrize("change, message", [
    ({"source_url": "javascript:alert(1)"}, "http or https"),
    ({"source_url": "file:///etc/passwd"}, "http or https"),
    ({"source_url": "https://exa mple.com"}, "http or https"),
    ({"verdict": "resolved"}, "fixed, not-affected or affected"),
    ({"confidence": "certain"}, "high, medium or low"),
    ({"statement": "  \n "}, "needs a statement"),
    ({"vendor": ""}, "needs a vendor"),
    ({"retrieved_at": "yesterday"}, "must look like"),
    ({"retrieved_at": "2030-01-01T00:00:00Z"}, "future"),
])
def test_bad_notes_are_refused_and_nothing_is_saved(store, change, message):
    fid = lodash_finding(store)
    with pytest.raises(VendorNoteError, match=message):
        store.add_vendor_note(fid, **(DEBIAN | change))
    assert findings.list_findings(store.db, "2026-10-01T00:00:00Z")[0].vendor_notes == []


def test_unknown_ids_are_refused(store):
    lodash_finding(store)
    with pytest.raises(FindingError):
        store.add_vendor_note("SEC-0099", **DEBIAN)
    with pytest.raises(VendorNoteError, match="no vendor note VN-0007"):
        store.withdraw_vendor_note("VN-0007")
    with pytest.raises(VendorNoteError):
        store.check_vendor_note("SEC-0001")


def test_an_old_store_gets_the_table(tmp_path):
    with Store(tmp_path / "data") as s:
        s.db.execute("DROP TABLE vendor_notes")
    with Store(tmp_path / "data") as s:
        assert s.db.execute("SELECT COUNT(*) AS n FROM vendor_notes").fetchone()["n"] == 0


def test_cli_add_withdraw_and_check(tmp_path, capsys):
    data = str(tmp_path / "data")
    with Store(data, clock=Clock(*T * 2)) as s:
        lodash_finding(s)
    args = ["--data-dir", data, "vendor-note-add", "SEC-0001", "--vendor", "Debian", "--verdict", "not-affected",
            "--statement", "Fixed by backport.", "--confidence", "medium",
            "--url", "https://security-tracker.debian.org/tracker/CVE-2021-23337",
            "--retrieved", "2026-10-20T09:12:00Z"]
    assert cli.main(args) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["finding"]["status"] == "open"
    assert out["finding"]["vendor_notes"][0]["verdict"] == "not_affected"
    assert cli.main(["--data-dir", data, "vendor-note-check", "VN-0001"]) == 0
    assert json.loads(capsys.readouterr().out)["finding"]["vendor_notes"][0]["checked_at"]
    assert cli.main(["--data-dir", data, "vendor-note-withdraw", "VN-0001"]) == 0
    assert json.loads(capsys.readouterr().out)["finding"]["vendor_notes"][0]["withdrawn_at"]
    assert cli.main(["--data-dir", data, "vendor-note-check", "VN-0001"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err)["error"] == "VN-0001 is withdrawn. Add a new vendor note."
    assert cli.main(args[:10] + ["--confidence", "medium", "--url", "ftp://x.example"]) == 1
    assert "http or https" in json.loads(capsys.readouterr().err)["error"]
