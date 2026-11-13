"""pytest 配置:把仓库根目录加入 sys.path,使测试可在 `python -I -m pytest` 下运行。"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.session import workspace  # noqa: E402


@pytest.fixture()
def client() -> TestClient:
    workspace.clear()
    with TestClient(app) as c:
        yield c
    workspace.clear()


@pytest.fixture()
def demo_client(client: TestClient) -> TestClient:
    resp = client.post("/api/demo")
    assert resp.status_code == 200
    return client
