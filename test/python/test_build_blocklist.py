"""Unit tests for tools/build_blocklist.py — the blob it emits is what the
firmware binary-searches, so both the hashing and the source parsing have to be
exact."""
import io
import pathlib

import pytest


def decode_blob(blob, hash_bytes=5):
    assert len(blob) % hash_bytes == 0, 'blob must be a whole number of hashes'
    return [int.from_bytes(blob[i:i + hash_bytes], 'little')
            for i in range(0, len(blob), hash_bytes)]


# ---------- fnv ----------

def test_fnv_matches_shared_vectors(builder, hash_vectors):
    for domain, expected in hash_vectors:
        assert builder.fnv(domain.encode()) == expected, domain


def test_fnv_empty_input_is_truncated_offset_basis(builder):
    assert builder.fnv(b'') == builder.FNV_OFFSET & builder.MASK


def test_fnv_is_truncated_to_hash_bytes(builder):
    assert builder.MASK == (1 << (builder.HASH_BYTES * 8)) - 1
    for domain in ('a', 'example.com', 'doubleclick.net', 'x' * 200):
        assert 0 <= builder.fnv(domain.encode()) <= builder.MASK


def test_fnv_is_case_sensitive_so_callers_must_normalise(builder):
    assert builder.fnv(b'Example.com') != builder.fnv(b'example.com')


def test_hash_bytes_matches_firmware(builder):
    firmware = (pathlib.Path(builder.__file__).resolve().parents[1] / 'src' / 'dns_core.h').read_text()
    assert f'HASH_BYTES = {builder.HASH_BYTES};' in firmware


# ---------- norm ----------

@pytest.mark.parametrize('raw,expected', [
    ('Example.COM', 'example.com'),
    ('  example.com \n', 'example.com'),
    ('example.com.', 'example.com'),
    ('.example.com', 'example.com'),
    ('*.example.com', 'example.com'),
    ('*example.com', 'example.com'),
    ('www.example.com', 'example.com'),
    ('WWW.Example.com', 'example.com'),
    ('wwww.example.com', 'wwww.example.com'),
    ('www2.example.com', 'www2.example.com'),
    ('sub.www.example.com', 'sub.www.example.com'),
    ('', ''),
])
def test_norm(builder, raw, expected):
    assert builder.norm(raw) == expected


# ---------- read_source ----------

def test_read_source_prefers_a_local_file(builder, tmp_path, monkeypatch):
    f = tmp_path / 'hosts'
    f.write_text('0.0.0.0 ads.example.com\n')
    monkeypatch.setattr(builder.urllib.request, 'urlopen',
                        lambda *a, **k: pytest.fail('should not hit the network for a local path'))
    assert builder.read_source(str(f)) == '0.0.0.0 ads.example.com\n'


def test_read_source_downloads_a_url(builder, monkeypatch):
    monkeypatch.setattr(builder.urllib.request, 'urlopen',
                        lambda url, timeout=None: io.BytesIO(b'0.0.0.0 remote.example.com\n'))
    assert 'remote.example.com' in builder.read_source('https://host/list.txt')


def test_read_source_tolerates_undecodable_bytes(builder, tmp_path):
    f = tmp_path / 'hosts'
    f.write_bytes(b'0.0.0.0 ads.example.com\n\xff\xfe bad bytes\n')
    assert 'ads.example.com' in builder.read_source(str(f))


# ---------- main: source parsing ----------

def build(run_builder, tmp_path, text, name='hosts'):
    src = tmp_path / name
    src.write_text(text)
    out = tmp_path / 'blocklist.bin'
    captured, blob = run_builder(out, src)
    return captured, decode_blob(blob)


def hashes_of(builder, *domains):
    return sorted(builder.fnv(d.encode()) for d in domains)


def test_hosts_format_takes_the_domain_not_the_ip(builder, run_builder, tmp_path):
    _, got = build(run_builder, tmp_path, '\n'.join([
        '0.0.0.0 ads.example.com',
        '127.0.0.1 tracker.example.com',
        ':: v6.example.com',
        '::1 v6loop.example.com',
    ]))
    assert got == hashes_of(builder, 'ads.example.com', 'tracker.example.com',
                            'v6.example.com', 'v6loop.example.com')


def test_bare_domain_lists_are_accepted(builder, run_builder, tmp_path):
    _, got = build(run_builder, tmp_path, 'ads.example.com\ntracker.example.net\n')
    assert got == hashes_of(builder, 'ads.example.com', 'tracker.example.net')


def test_comments_and_directives_are_skipped(builder, run_builder, tmp_path):
    _, got = build(run_builder, tmp_path, '\n'.join([
        '# a comment',
        '! adblock-style comment',
        '/regex/style/line',
        '',
        '   ',
        '0.0.0.0 kept.example.com # trailing comment',
    ]))
    assert got == hashes_of(builder, 'kept.example.com')


def test_entries_without_a_dot_are_skipped(builder, run_builder, tmp_path):
    _, got = build(run_builder, tmp_path, 'localhost\n0.0.0.0 localhost\nkept.example.com\n')
    assert got == hashes_of(builder, 'kept.example.com')


def test_lines_with_an_unknown_leading_token_are_skipped(builder, run_builder, tmp_path):
    _, got = build(run_builder, tmp_path, '192.168.1.5 printer.lan\nkept.example.com\n')
    assert got == hashes_of(builder, 'kept.example.com')


def test_hosts_lines_with_extra_aliases_keep_only_the_first_name(builder, run_builder, tmp_path):
    _, got = build(run_builder, tmp_path, '0.0.0.0 ads.example.com alias.example.com\n')
    assert got == hashes_of(builder, 'ads.example.com')


def test_domains_are_normalised_before_hashing(builder, run_builder, tmp_path):
    _, got = build(run_builder, tmp_path, '0.0.0.0 WWW.Ads.Example.COM.\n')
    assert got == hashes_of(builder, 'ads.example.com')


def test_duplicates_across_sources_collapse(builder, run_builder, tmp_path):
    a = tmp_path / 'a.txt'
    b = tmp_path / 'b.txt'
    a.write_text('0.0.0.0 ads.example.com\nwww.ads.example.com\n')
    b.write_text('ads.example.com\nother.example.com\n')
    out = tmp_path / 'out.bin'
    captured, blob = run_builder(out, a, b)
    assert decode_blob(blob) == hashes_of(builder, 'ads.example.com', 'other.example.com')
    assert 'source domains   : 2' in captured.out


# ---------- main: output blob ----------

def test_blob_is_sorted_little_endian_and_five_bytes_per_entry(builder, run_builder, tmp_path):
    domains = [f'ads{i}.example.com' for i in range(50)]
    _, got = build(run_builder, tmp_path, '\n'.join(domains))
    assert len(got) == 50
    assert got == sorted(got)
    assert got == hashes_of(builder, *domains)


def test_blob_is_empty_when_nothing_parses(run_builder, tmp_path):
    _, got = build(run_builder, tmp_path, '# nothing here\n')
    assert got == []


def test_a_failing_source_is_skipped_not_fatal(builder, run_builder, tmp_path):
    good = tmp_path / 'good.txt'
    good.write_text('ads.example.com\n')
    out = tmp_path / 'out.bin'
    captured, blob = run_builder(out, tmp_path / 'missing-file-or-url', good)
    assert decode_blob(blob) == hashes_of(builder, 'ads.example.com')
    assert 'skipped' in captured.err


def test_summary_reports_entries_size_and_lookup_depth(run_builder, tmp_path):
    captured, got = build(run_builder, tmp_path, '\n'.join(f'ads{i}.example.com' for i in range(8)))
    assert 'hash entries     : 8' in captured.out
    assert 'collisions       : 0' in captured.out
    assert f'flash blob       : {8 * 5:,} bytes' in captured.out
    assert 'lookup           : ~3 reads/query' in captured.out


def test_collisions_are_reported_and_deduplicated(builder, run_builder, tmp_path, monkeypatch):
    monkeypatch.setattr(builder, 'fnv', lambda b: 1 if b.startswith(b'ads') else 2)
    captured, got = build(run_builder, tmp_path, 'ads1.example.com\nads2.example.com\nother.example.com\n')
    assert got == [1, 2]
    assert 'collisions       : 1' in captured.out


def test_default_output_path_is_used_when_no_args(builder, monkeypatch, tmp_path, capsys):
    src = tmp_path / 'hosts'
    src.write_text('ads.example.com\n')
    monkeypatch.setattr(builder, 'DEFAULT_SOURCES', [str(src)])
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(builder.sys, 'argv', ['build_blocklist.py'])
    builder.main()
    capsys.readouterr()
    assert decode_blob((tmp_path / 'blocklist.bin').read_bytes()) == hashes_of(builder, 'ads.example.com')


def test_default_sources_are_used_when_only_an_output_is_given(builder, monkeypatch, tmp_path, capsys):
    src = tmp_path / 'hosts'
    src.write_text('default.example.com\n')
    monkeypatch.setattr(builder, 'DEFAULT_SOURCES', [str(src)])
    out = tmp_path / 'out.bin'
    monkeypatch.setattr(builder.sys, 'argv', ['build_blocklist.py', str(out)])
    builder.main()
    capsys.readouterr()
    assert decode_blob(out.read_bytes()) == hashes_of(builder, 'default.example.com')


# ---------- the shipped blob ----------

def test_committed_blocklist_is_a_sorted_hash_table(builder):
    path = pathlib.Path(builder.__file__).resolve().parents[1] / 'data' / 'blocklist.bin'
    if not path.exists():
        pytest.skip('blocklist.bin not built yet')
    blob = path.read_bytes()
    assert len(blob) % builder.HASH_BYTES == 0
    hashes = decode_blob(blob, builder.HASH_BYTES)
    assert hashes == sorted(hashes), 'firmware binary-searches this file'
    assert len(set(hashes)) == len(hashes)
