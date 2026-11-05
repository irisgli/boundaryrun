import shutil
from pathlib import Path

import pytest

from boundaryrun.pipeline import load_scenario
from boundaryrun.sandbox import docker_available, image_present

ROOT = Path(__file__).resolve().parents[1]
SCENARIO = ROOT / "scenarios" / "docvault-idor"


@pytest.fixture(scope="session")
def scenario():
    return load_scenario(SCENARIO)


@pytest.fixture
def workspace(tmp_path, scenario):
    ws = tmp_path / "ws"
    shutil.copytree(scenario.target, ws, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    return ws


def pytest_configure(config):
    (ROOT / ".runs").mkdir(exist_ok=True)


def pytest_collection_modifyitems(config, items):
    ok, info = docker_available()
    reason = info if not ok else ("runner image missing; run `boundaryrun build-sandbox`" if not image_present() else None)
    if reason:
        skip = pytest.mark.skip(reason=f"docker unavailable: {reason}")
        for item in items:
            if "docker" in item.keywords:
                item.add_marker(skip)
