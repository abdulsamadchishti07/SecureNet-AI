"""Execute dashboard JavaScript against an isolated live API and browser."""

import re

from playwright.sync_api import expect


def test_admin_live_event_details_and_acknowledged_unblock(page, login, sensor, detection):
    login()
    expect(page.locator("#connection-status")).to_have_text("Connected", timeout=10000)
    assert sensor.publish(detection())
    expect(page.locator("#total-events")).to_have_text("1", timeout=10000)
    expect(page.locator("#alert-rows")).to_contain_text("10.10.0.9")
    page.get_by_role("button", name="Inspect event").first.click()
    expect(page.locator("#event-dialog")).to_contain_text("unified_v1")
    expect(page.locator("#event-dialog")).to_contain_text("sensor-local")
    page.get_by_role("button", name="Close event details").click()
    page.get_by_role("button", name="Response", exact=True).click()
    page.get_by_role("button", name="Request unblock").first.click()
    expect(page.locator("#notice")).to_contain_text("acknowledgement")
    page.get_by_role("tab", name="Unblocked", exact=True).click()
    expect(page.locator("#block-rows")).to_contain_text("10.10.0.9", timeout=12000)
    expect(page.locator("#block-rows")).to_contain_text("UNBLOCKED")
    expect(page.locator("#actual-blocks")).to_have_text("0")


def test_operator_filters_and_no_admin_controls(page, login, sensor, detection):
    login("browser_operator")
    expect(page.get_by_role("button", name="Add user", exact=True)).to_have_count(0)
    assert sensor.publish(detection())
    assert sensor.publish(detection("BENIGN"))
    expect(page.locator("#total-events")).to_have_text("2", timeout=10000)
    page.get_by_label("Threat class").select_option("BENIGN")
    page.get_by_role("button", name="Apply filters").click()
    expect(page.locator("#alert-rows tr")).to_have_count(1)
    expect(page.locator("#alert-rows")).to_contain_text("BENIGN")
    page.get_by_role("button", name="Response", exact=True).click()
    expect(page.get_by_role("button", name="Request unblock")).to_have_count(0)


def test_reconnect_uses_new_ticket_and_logout_clears_session(page, login):
    issued = []
    page.on("response", lambda response: issued.append(response.url)
            if response.url.endswith("/api/auth/ws-ticket") and response.status == 200 else None)
    login()
    expect(page.locator("#connection-status")).to_have_text("Connected", timeout=10000)
    page.context.set_offline(True)
    expect(page.locator("#connection-status")).not_to_have_text("Connected", timeout=15000)
    page.context.set_offline(False)
    expect(page.locator("#connection-status")).to_have_text("Connected", timeout=20000)
    assert len(issued) >= 2
    initial_refresh = page.evaluate("localStorage.getItem('securenet_refresh_token')")
    assert initial_refresh
    page.reload()
    expect(page.locator("#workspace")).to_be_visible(timeout=10000)
    expect(page.locator("#connection-status")).to_have_text("Connected", timeout=10000)
    rotated_refresh = page.evaluate("localStorage.getItem('securenet_refresh_token')")
    assert rotated_refresh and rotated_refresh != initial_refresh
    page.get_by_role("button", name="Sign out", exact=True).click()
    expect(page.locator("#login-screen")).to_be_visible()
    assert page.evaluate("Object.keys(localStorage).length + Object.keys(sessionStorage).length") == 0


def test_expired_session_returns_to_login(page, login):
    login()
    page.route("**/api/stats", lambda route: route.fulfill(status=401,
        json={"detail": "Invalid or expired authentication token"}))
    page.get_by_role("button", name="Refresh", exact=True).click()
    expect(page.locator("#login-screen")).to_be_visible(timeout=10000)
    expect(page.locator("#login-error")).to_contain_text("expired")


def test_mobile_layout_and_admin_provisioning(page, login):
    page.set_viewport_size({"width": 390, "height": 844})
    login()
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    page.get_by_role("button", name="Add user", exact=True).click()
    dialog = page.locator("#user-dialog")
    dialog.get_by_label("New username").fill("new_analyst")
    dialog.get_by_label("Email").fill("new-analyst@example.com")
    dialog.get_by_label("New password").fill("ProvisionedPassword123!")
    dialog.get_by_role("button", name="Create account", exact=True).click()
    expect(dialog).not_to_be_visible(timeout=10000)
    expect(page.locator("#notice")).to_contain_text("created")
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")


def test_failed_request_is_visible_and_untrusted_text_is_inert(page, login):
    login()
    page.route("**/api/stats", lambda route: route.fulfill(status=503,
        json={"detail": "Database temporarily unavailable"}))
    page.get_by_role("button", name="Refresh", exact=True).click()
    expect(page.locator("#notice")).to_contain_text("unavailable")
    payload = [{"id": 1, "event_id": "test-event", "observed_at": "2026-11-09T00:00:00Z",
        "src_ip": "10.10.0.9", "dst_ip": "10.10.0.2", "src_port": 40000, "dst_port": 80,
        "protocol": 6, "label": "PORTSCAN", "confidence": .99, "decision_action": "alert",
        "sensor_id": '<img src=x onerror="window.injection=true">', "model_run": "unified_v1"}]
    page.route(re.compile(r".*/api/alerts(?:\?.*)?$"), lambda route: route.fulfill(json=payload))
    page.get_by_role("button", name="Apply filters").click()
    expect(page.locator("#alert-rows")).to_contain_text("<img src=x")
    assert page.evaluate("window.injection === undefined")


def test_stopped_sensor_leaves_unblock_pending(page, login, dashboard_server, detection):
    from backend.firewall import FirewallController
    event = detection().to_dict()
    body = {"event": event, "decision": {"action": "candidate", "reason": "repeated_high_score_flows", "evidence_count": 3},
            "firewall": FirewallController().block_ip(event["src_ip"], event["label"])}
    config = dashboard_server.config
    assert dashboard_server.client.post("/api/alerts/ingest", json=body, headers={
        "X-Sensor-Token": config.SENSOR_API_TOKEN, "X-Sensor-ID": config.SENSOR_ID}).status_code == 201
    login()
    page.get_by_role("button", name="Response", exact=True).click()
    page.get_by_role("button", name="Request unblock").click()
    expect(page.locator("#block-rows")).to_contain_text("UNBLOCK_REQUESTED")
    expect(page.locator("#pending-unblocks")).to_have_text("1")
    page.get_by_role("button", name="Refresh", exact=True).click()
    expect(page.locator("#pending-unblocks")).to_have_text("1")
    expect(page.locator("#block-rows")).not_to_contain_text("UNBLOCKED")


def test_duplicate_delivery_and_pagination(page, login, dashboard_server, detection):
    config = dashboard_server.config
    headers = {"X-Sensor-Token": config.SENSOR_API_TOKEN, "X-Sensor-ID": config.SENSOR_ID}
    for index in range(27):
        body = {"event": detection().to_dict(), "decision": {"action": "alert", "reason": "single_flow"}}
        assert dashboard_server.client.post("/api/alerts/ingest", json=body, headers=headers).status_code == 201
        if index == 0:
            assert dashboard_server.client.post("/api/alerts/ingest", json=body, headers=headers).status_code == 200
    login()
    expect(page.locator("#total-events")).to_have_text("27", timeout=10000)
    expect(page.locator("#alert-rows tr")).to_have_count(25)
    expect(page.locator("#live-feed .feed-item")).to_have_count(8)
    page.locator("#alerts-next").click()
    expect(page.locator("#alert-rows tr")).to_have_count(2)
    expect(page.locator("#alert-page-label")).to_contain_text("26–27")
    page.locator("#alerts-prev").click()
    expect(page.locator("#alert-rows tr")).to_have_count(25)


def test_provisioning_rejects_byte_limit_and_duplicate_user(page, login):
    login()
    page.get_by_role("button", name="Add user", exact=True).click()
    dialog = page.locator("#user-dialog")
    dialog.get_by_label("New username").fill("browser_operator")
    dialog.get_by_label("Email").fill("another@example.com")
    dialog.get_by_label("New password").fill("😀" * 19)
    dialog.get_by_role("button", name="Create account").click()
    expect(page.locator("#user-error")).to_contain_text("72 UTF-8 bytes")
    dialog.get_by_label("New password").fill("ValidPassword123!")
    dialog.get_by_role("button", name="Create account").click()
    expect(page.locator("#user-error")).to_contain_text("already registered")
    expect(dialog).to_be_visible()


def test_enforced_block_and_rolled_back_tab(page, login, dashboard_server, detection):
    from datetime import datetime, timedelta, timezone
    from uuid import uuid4
    from backend.fw_client import nft_block_command
    event = detection().to_dict()
    block_id = str(uuid4())
    now = datetime.now(timezone.utc)
    body = {
        "event": event,
        "decision": {"action": "candidate", "reason": "repeated_high_score_flows", "evidence_count": 3},
        "firewall": {
            "mode": "enforced",
            "ip": event["src_ip"],
            "threat": event["label"],
            "status": "blocked",
            "block": {
                "block_id": block_id,
                "ip": event["src_ip"],
                "threat": event["label"],
                "mode": "enforced",
                "blocked_at": now.isoformat(),
                "unblock_at": (now + timedelta(minutes=15)).isoformat(),
            },
            "command": nft_block_command(event["src_ip"], 900),
        },
    }
    config = dashboard_server.config
    headers = {"X-Sensor-Token": config.SENSOR_API_TOKEN, "X-Sensor-ID": config.SENSOR_ID}
    assert dashboard_server.client.post("/api/alerts/ingest", json=body, headers=headers).status_code == 201
    login()
    expect(page.locator("#actual-blocks")).to_have_text("1", timeout=10000)
    expect(page.locator(".page-heading .badge")).to_have_text("ENFORCED · NFTABLES")
    page.get_by_role("button", name="Response", exact=True).click()
    expect(page.locator("#block-rows")).to_contain_text("enforced")
    assert dashboard_server.client.post(
        "/api/sensor/reconcile",
        json={"mode": "enforced", "active_block_ids": [], "reason": "shutdown_rollback"},
        headers=headers,
    ).status_code == 200
    page.get_by_role("tab", name="Rolled back", exact=True).click()
    expect(page.locator("#block-rows")).to_contain_text("ROLLED_BACK", timeout=10000)
    expect(page.locator("#actual-blocks")).to_have_text("0")

