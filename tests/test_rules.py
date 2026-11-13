"""自定义规则:增删改、启停、非法正则保护、重新检查不叠加旧结果。"""
from __future__ import annotations

import json


def _upload_simple(client) -> None:
    har = {"log": {"entries": [
        {"request": {"method": "GET", "url": "https://x.test/a?internal=abc12345",
                     "headers": []},
         "response": {"status": 200, "headers": [], "content": {}}},
    ]}}
    resp = client.post(
        "/api/upload",
        files={"file": ("t.har", json.dumps(har).encode(), "application/json")},
    )
    assert resp.status_code == 200


def test_create_fieldname_rule_and_rescan(client) -> None:
    _upload_simple(client)
    before = len(client.get("/api/findings").json()["findings"])
    resp = client.post("/api/rules", json={
        "name": "内部字段",
        "match_type": "fieldname",
        "pattern": "internal",
        "locations": ["query"],
    })
    assert resp.status_code == 200
    after = client.get("/api/findings").json()["findings"]
    assert len(after) == before + 1
    assert after[-1]["target"]["name"] == "internal"


def test_create_regex_rule_scoped_to_location(client) -> None:
    _upload_simple(client)
    # 只检查响应头:查询参数里的命中不应出现
    resp = client.post("/api/rules", json={
        "name": "abc 正则",
        "match_type": "regex",
        "pattern": r"abc\d+",
        "locations": ["response_header"],
    })
    assert resp.status_code == 200
    findings = client.get("/api/findings").json()["findings"]
    assert all(f["location"] != "query" for f in findings)


def test_invalid_regex_rejected_and_keeps_state(client) -> None:
    _upload_simple(client)
    before = client.get("/api/findings").json()
    resp = client.post("/api/rules", json={
        "name": "坏正则",
        "match_type": "regex",
        "pattern": r"([unclosed",
        "locations": ["query"],
    })
    assert resp.status_code == 400
    assert "非法正则" in resp.json()["detail"]
    # 规则未写入,旧扫描结果不变
    rules = client.get("/api/rules").json()["rules"]
    assert all(r["name"] != "坏正则" for r in rules)
    after = client.get("/api/findings").json()
    assert len(after["findings"]) == len(before["findings"])


def test_invalid_regex_via_patch_rejected(client) -> None:
    _upload_simple(client)
    create = client.post("/api/rules", json={
        "name": "临时", "match_type": "regex",
        "pattern": r"abc", "locations": ["query"],
    }).json()
    rid = create["rule"]["id"]
    resp = client.patch(f"/api/rules/{rid}", json={"pattern": r"(["})
    assert resp.status_code == 400
    # 旧 pattern 保留
    rules = {r["id"]: r for r in client.get("/api/rules").json()["rules"]}
    assert rules[rid]["pattern"] == r"abc"


def test_toggle_rule(client) -> None:
    _upload_simple(client)
    create = client.post("/api/rules", json={
        "name": "可停用", "match_type": "fieldname",
        "pattern": "internal", "locations": ["query"],
    }).json()
    rid = create["rule"]["id"]
    assert any(f["target"]["name"] == "internal"
               for f in client.get("/api/findings").json()["findings"])
    client.patch(f"/api/rules/{rid}", json={"enabled": False})
    assert all(f["target"].get("name") != "internal"
               for f in client.get("/api/findings").json()["findings"])


def test_builtin_rule_cannot_be_deleted_or_edited(client) -> None:
    _upload_simple(client)
    bid = client.get("/api/rules").json()["rules"][0]["id"]
    assert client.delete(f"/api/rules/{bid}").status_code == 400
    assert client.patch(f"/api/rules/{bid}", json={"pattern": "x"}).status_code == 400
    # 但可以启停
    assert client.patch(f"/api/rules/{bid}", json={"enabled": False}).status_code == 200


def test_rescan_does_not_stack_old_results(client) -> None:
    _upload_simple(client)
    client.post("/api/rules", json={
        "name": "内部字段", "match_type": "fieldname",
        "pattern": "internal", "locations": ["query"],
    })
    findings_1 = client.get("/api/findings").json()["findings"]
    target_ids = {f["id"] for f in findings_1 if f["target"].get("name") == "internal"}
    assert len(target_ids) == 1
    # 再次全量重扫(模拟规则反复修改),同一位置仍是同一条发现项,不叠加
    client.post("/api/rules/rescan")
    findings_2 = client.get("/api/findings").json()["findings"]
    target_ids_2 = {f["id"] for f in findings_2 if f["target"].get("name") == "internal"}
    assert target_ids == target_ids_2


def test_delete_rule_removes_its_findings(client) -> None:
    _upload_simple(client)
    create = client.post("/api/rules", json={
        "name": "内部字段", "match_type": "fieldname",
        "pattern": "internal", "locations": ["query"],
    }).json()
    rid = create["rule"]["id"]
    assert any(f["target"].get("name") == "internal"
               for f in client.get("/api/findings").json()["findings"])
    client.delete(f"/api/rules/{rid}")
    assert all(f["target"].get("name") != "internal"
               for f in client.get("/api/findings").json()["findings"])
    # 规则列表里也不存在了
    assert all(r["id"] != rid for r in client.get("/api/rules").json()["rules"])


def test_treatment_choice_survives_rescan(client) -> None:
    _upload_simple(client)
    client.post("/api/rules", json={
        "name": "内部字段", "match_type": "fieldname",
        "pattern": "internal", "locations": ["query"],
    })
    fid = next(
        f["id"] for f in client.get("/api/findings").json()["findings"]
        if f["target"].get("name") == "internal"
    )
    client.post("/api/findings/treatment", json={
        "finding_ids": [fid], "treatment": "pseudo", "handled": True,
    })
    # 新增一条无关规则触发重扫
    client.post("/api/rules", json={
        "name": "另一条", "match_type": "fieldname",
        "pattern": "nothing-matches", "locations": ["query"],
    })
    findings = {f["id"]: f for f in client.get("/api/findings").json()["findings"]}
    assert findings[fid]["treatment"] == "pseudo"
    assert findings[fid]["handled"] is True
