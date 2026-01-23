# tests/conftest.py
import pytest
from pathlib import Path

def pytest_collection_modifyitems(config, items):
    for item in items:
        p = Path(str(item.fspath)).as_posix()
        if "/tests/integration/" in p or p.endswith("/tests/integration"):
            item.add_marker(pytest.mark.integration)
        elif "/tests/unit/" in p or p.endswith("/tests/unit"):
            item.add_marker(pytest.mark.unit)
