import time

from wtf.knowledge.files import artifact_kind, classify_file, is_dashcam_name
from wtf.model import Finding, FindingStore, Resource, Risk
from wtf.scanners.docker import parse_size

OLD = time.time() - 400 * 86400


def test_dashcam_names():
    for n in ["20230512_143012_F.MP4", "2023_0512_143012_001F.MP4", "NO20230512-143012-000123F.MP4",
              "FILE230512-143012F.MOV", "EVENT0001.MP4"]:
        assert is_dashcam_name(n), n
    assert not is_dashcam_name("vacation.mp4")


def test_ytdlp_fragment_is_safe():
    v = classify_file("/tmp/x/Song [dQw4w9WgXcQ].f137.mp4", 10**9, OLD, 180)
    assert v.kind == "ytdlp" and v.risk == Risk.SAFE


def test_movie_and_camera():
    assert classify_file("/tmp/Film.2019.1080p.BDRip.x264.mkv", 5 * 10**9, OLD, 180).kind == "movie"
    assert classify_file("/tmp/IMG_1234.MOV", 10**9, OLD, 180).risk == Risk.PERSONAL


def test_backup_path_raises_risk():
    v = classify_file("/Users/x/backup/sdcard-full.img.gz", 10**9, OLD, 180)
    assert v.risk >= Risk.PERSONAL


def test_partial_download():
    assert classify_file("/tmp/big.iso.crdownload", 10**9, OLD, 180).kind == "partial"


def test_artifacts_need_project_marker():
    assert artifact_kind("node_modules", {"package.json"})
    assert not artifact_kind("node_modules", {"README.md"})
    assert artifact_kind("target", {"Cargo.toml"})
    assert not artifact_kind("build", {"notes.txt"})


def test_parse_docker_sizes():
    assert parse_size("3.46GB") == 3_460_000_000
    assert parse_size("28.84MiB") == int(28.84 * 1024**2)
    assert parse_size("0B") == 0


def test_store_runs_drop_unseen_but_keep_resolved():
    s = FindingStore()
    a = Finding("a", "sc", Resource.DISK, "A")
    b = Finding("b", "sc", Resource.DISK, "B")
    s.upsert([a, b])
    s.mark_resolved("b", "в Корзине")
    s.begin_run("sc")
    s.replace_scanner("sc", [Finding("c", "sc", Resource.DISK, "C")])
    s.finish_run("sc")
    ids = {f.id for f in s.snapshot()}
    assert ids == {"b", "c"}


def test_finding_roundtrip():
    from wtf.model import Action, ActionKind

    f = Finding("x", "sc", Resource.DISK, "X", actions=[Action(ActionKind.KILL, "k", pids=[(1, 2.0)])],
                facts=[("a", "b")])
    g = Finding.from_dict(f.to_dict())
    assert g.actions[0].pids == [(1, 2.0)] and g.facts == [("a", "b")] and g.resource == Resource.DISK
