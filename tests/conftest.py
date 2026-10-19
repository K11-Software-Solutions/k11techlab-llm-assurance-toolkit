import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(EXAMPLES))


@pytest.fixture
def vulnerable_target_file() -> Path:
    return EXAMPLES / "targets" / "demo_vulnerable.yaml"


@pytest.fixture
def hardened_target_file() -> Path:
    return EXAMPLES / "targets" / "demo_hardened.yaml"
