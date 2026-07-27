import importlib.util
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
FIXTURES = REPO_ROOT / 'test' / 'fixtures'


def _load_builder():
    path = REPO_ROOT / 'tools' / 'build_blocklist.py'
    spec = importlib.util.spec_from_file_location('build_blocklist', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules['build_blocklist'] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope='session')
def builder():
    """tools/build_blocklist.py loaded as a module (it is a script, not a package)."""
    return _load_builder()


@pytest.fixture
def run_builder(builder, monkeypatch, capsys):
    """Runs the builder's main() with the given argv, returning (captured, blob bytes)."""
    def run(out_path, *sources):
        monkeypatch.setattr(sys, 'argv', ['build_blocklist.py', str(out_path), *[str(s) for s in sources]])
        builder.main()
        captured = capsys.readouterr()
        blob = pathlib.Path(out_path).read_bytes() if pathlib.Path(out_path).exists() else b''
        return captured, blob
    return run


@pytest.fixture(scope='session')
def hash_vectors():
    """(domain, hash) pairs shared with the firmware's native tests."""
    vectors = []
    for line in (FIXTURES / 'hash_vectors.txt').read_text().splitlines():
        line = line.split('#', 1)[0].strip()
        if line:
            domain, hexhash = line.split()
            vectors.append((domain, int(hexhash, 16)))
    return vectors
