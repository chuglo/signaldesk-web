from pathlib import Path
import tomllib


ROOT = Path(__file__).parents[1]


def test_flask_is_pinned_exactly_in_project_and_lock() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert "Flask==3.1.0" in project["project"]["dependencies"]

    lock = (ROOT / "uv.lock").read_text()
    assert 'name = "flask"\nversion = "3.1.0"' in lock
