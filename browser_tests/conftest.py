"""Opt-in browser fixtures: real loopback HTTP and a private temporary database."""

from contextlib import suppress
from pathlib import Path
import shutil
import socket
from threading import Thread
import time
from types import SimpleNamespace

import httpx
import pytest
from playwright.sync_api import sync_playwright
from sqlalchemy import create_engine
import uvicorn

from backend.config import Settings
from backend.main import create_app
from backend.manage import bootstrap_admin
from backend.worker import ResponseDispatcher
from ml_engine.datasets import get_dataset
from ml_engine.preprocess import SELECTED_COLUMNS
from sniffer.events import DetectionEvent
from sniffer.rules import ResponsePolicy

PASSWORD = "BrowserTestPassword123!"


@pytest.fixture
def dashboard_server(tmp_path):
    assert (Path(__file__).resolve().parents[1] / "frontend/dist/index.html").is_file(), (
        "Build the React dashboard first: cd frontend && npm ci && npm run build")
    config = Settings(DATABASE_URL="sqlite:///" + str(tmp_path / "browser.sqlite"),
                      SECRET_KEY="browser-user-test-key-" * 3,
                      SENSOR_API_TOKEN="browser-sensor-test-key-" * 3)
    engine = create_engine(config.DATABASE_URL, connect_args={"check_same_thread": False})
    application = create_app(config, engine=engine)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(application, log_level="error", access_log=False))
    thread = Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    client = httpx.Client(base_url=f"http://127.0.0.1:{port}", trust_env=False, timeout=5)
    try:
        deadline = time.monotonic() + 10
        while not server.started and time.monotonic() < deadline:
            time.sleep(.05)
        assert server.started, "Private browser server did not start"
        bootstrap_admin(engine, "browser_admin", "browser-admin@example.com", PASSWORD)
        response = client.post("/api/auth/login", data={"username": "browser_admin", "password": PASSWORD})
        headers = {"Authorization": "Bearer " + response.json()["access_token"]}
        response = client.post("/api/auth/register", headers=headers, json={
            "username": "browser_operator", "email": "browser-operator@example.com", "password": PASSWORD})
        assert response.status_code == 201
        yield SimpleNamespace(url=str(client.base_url).rstrip("/"), config=config,
                              client=client, headers=headers, password=PASSWORD, tmp_path=tmp_path)
    finally:
        client.close()
        server.should_exit = True
        thread.join(timeout=10)
        with suppress(OSError):
            listener.close()
        engine.dispose()
        assert not thread.is_alive(), "Private browser server failed to stop"


@pytest.fixture(scope="session")
def browser():
    with sync_playwright() as playwright:
        executable = shutil.which("chromium") or shutil.which("google-chrome")
        instance = playwright.chromium.launch(executable_path=executable, headless=True,
                                             args=["--no-sandbox"])
        yield instance
        instance.close()


@pytest.fixture
def page(browser):
    context = browser.new_context(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
    page = context.new_page()
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    yield page
    context.close()
    assert not errors, "Uncaught browser errors: " + repr(errors)


@pytest.fixture
def login(page, dashboard_server):
    def sign_in(username="browser_admin"):
        page.goto(dashboard_server.url)
        page.get_by_label("Username", exact=True).fill(username)
        page.get_by_label("Password", exact=True).fill(PASSWORD)
        page.get_by_role("button", name="Sign in", exact=True).click()
        page.locator("#workspace").wait_for(state="visible")
    return sign_in


@pytest.fixture
def sensor(dashboard_server):
    config = dashboard_server.config
    with ResponseDispatcher(dashboard_server.tmp_path / "events.jsonl",
            policy=ResponsePolicy(min_flows=1), api_url=dashboard_server.url,
            api_token=config.SENSOR_API_TOKEN, sensor_id=config.SENSOR_ID) as worker:
        yield worker


@pytest.fixture
def detection():
    def make(label="PORTSCAN"):
        features = {name: 1 for name in SELECTED_COLUMNS}
        features.update({"Src Port": 40000, "Dst Port": 80, "Protocol": 6})
        probabilities = dict.fromkeys(get_dataset("unified").classes, 0.0)
        probabilities[label] = .99
        probabilities["BENIGN" if label != "BENIGN" else "PORTSCAN"] = .01
        return DetectionEvent(src_ip="10.10.0.9", dst_ip="10.10.0.2", features=features,
            label=label, confidence=.99, probabilities=probabilities, model_scope="unified",
            model_sha256="a" * 64, source="pcap")
    return make
