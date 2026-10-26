"""Bounded, read-only checks of the explicitly owned Secblitz public hosts.

Run with system Python for --http (cryptography), or a Playwright Python for
--browser. No credentials, redirects, arbitrary targets, or secret-body reads.
Evidence is printed as JSON; executable downloads are hashed in memory only.
"""

import argparse
import base64
import datetime
import hashlib
import http.client
import json
from pathlib import Path
import socket
import ssl
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
HOSTS = ("secblitz.lol", "www.secblitz.lol", "beacons.lol")
SETUP = "/downloads/secblitz-0.4.2-windows-x64-setup.exe"
PORTABLE = "/downloads/secblitz-0.4.2-windows-x64.exe"
FEED = "/releases/stable.json"
HASHES = {
    SETUP: (3813017, "28c93869508923b2ea865267025dc6c0d9e92e5d343e5a78f175d32e5b1b83c4"),
    PORTABLE: (4697088, "78c666e456b3f72fbe503e4aad6213b1baec4f7172e3e8cacd17f9bf893b4672"),
}
HEADERS = ("date", "content-type", "content-length", "content-encoding",
           "content-disposition", "content-range", "accept-ranges", "location",
           "cache-control", "etag", "last-modified", "vary", "cf-cache-status",
           "content-security-policy", "x-frame-options", "x-content-type-options",
           "strict-transport-security", "referrer-policy", "permissions-policy",
           "access-control-allow-origin", "access-control-allow-credentials",
           "speculation-rules")
RESULTS = []


def emit(**data):
    RESULTS.append(json.loads(json.dumps(data)))
    print(json.dumps(data, sort_keys=True), flush=True)


def request(host, path, method="GET", headers=None, cap=131072, tls=True):
    assert host in HOSTS and path.startswith("/")
    conn = (http.client.HTTPSConnection if tls else http.client.HTTPConnection)(host, timeout=20)
    try:
        conn.request(method, path, headers={"User-Agent": "Secblitz-owner-review/1.0",
                                           "Accept-Encoding": "identity", **(headers or {})})
        response = conn.getresponse()
        fields = {k: response.getheader(k) for k in HEADERS if response.getheader(k) is not None}
        body = b"" if method == "HEAD" else response.read(cap + 1)
        assert len(body) <= cap, "Public response exceeded read cap"
        emit(kind="http", host=host, path=path, method=method, tls=tls,
             status=response.status, headers=fields, bytes=len(body),
             sha256=hashlib.sha256(body).hexdigest() if body else None)
        return response.status, fields, body
    finally:
        conn.close()
        time.sleep(0.15)


def http_checks():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    for host in HOSTS:
        with socket.create_connection((host, 443), timeout=20) as raw:
            with ssl.create_default_context().wrap_socket(raw, server_hostname=host) as sock:
                cert = sock.getpeercert()
                emit(kind="tls", host=host, version=sock.version(), cipher=sock.cipher()[0],
                     not_after=cert["notAfter"], hostname_verified=True)
        request(host, "/", "HEAD", tls=False)
        request(host, "/", "HEAD")
    _, _, home = request(HOSTS[0], "/")
    for path in ("/?q=SECURITY_REVIEW_PLAIN_20261003&next=https%3A%2F%2Fwww.secblitz.lol%2F",
                 "/?q=SECURITY_REVIEW_%3Cplain%3E%22%27%26",
                 "/security-review-missing-20261003", "/README.md", "/test_video.py",
                 "/public/README.md", "/assets/../README.md", "/assets/%2e%2e/README.md",
                 "/%2e%2e/README.md", "/%2e%2e/%2e%2e/README.md"):
        status, _, body = request(HOSTS[0], path)
        emit(kind="public_classification", path=path, status=status,
             same_as_index=body == home, marker_reflected=b"SECURITY_REVIEW_" in body)
    # proof of its body. Stop the run if a config/key-like route looks exposed.
    for path in ("/.git/config", "/.env", "/wrangler.jsonc", "/_headers",
                 "/assets/update-public-key.hex", "/release-signing-key.pem",
                 "/.config/secblitz/release-signing-key.pem",
                 "/assets/%2e%2e/%2e%2e/.env",
                 "/%2e%2e/.git/config",
                 "/%2e%2e/.config/secblitz/release-signing-key.pem"):
        status, fields, _ = request(HOSTS[0], path, "HEAD")
        html = fields.get("content-type", "").startswith("text/html")
        emit(kind="sensitive_head_only", path=path,
             classification="consistent_with_html_fallback" if status == 200 and html
             else "not_served" if status in (400, 403, 404) else "needs_owner_review")
        if status == 200 and not html:
            raise RuntimeError(f"STOP: possible exposed config/key route {path}; body not requested")
    for host in HOSTS:
        for path in (FEED, SETUP):
            request(host, path, "HEAD")
    _, fields, _ = request(HOSTS[0], "/install.sh", "HEAD")
    emit(kind="install_script", text_plain=fields.get("content-type", "").startswith("text/plain"),
         nosniff=fields.get("x-content-type-options") == "nosniff")
    for host in ("www.secblitz.lol", "beacons.lol"):
        request(host, "/?next=https%3A%2F%2Fwww.secblitz.lol%2F&review=plain", "HEAD")
    request("www.secblitz.lol", "//beacons.lol/releases/stable.json", "HEAD")
    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex((ROOT / "assets/update-public-key.hex").read_text().strip()))
    for host in (HOSTS[0], HOSTS[2]):
        status, fields, body = request(host, FEED, cap=16384)
        assert status == 200 and "location" not in fields
        envelope = json.loads(body)
        payload = base64.b64decode(envelope["payload"], validate=True)
        key.verify(base64.b64decode(envelope["signature"], validate=True), payload)
        manifest = json.loads(payload)
        assert manifest["version"] == "0.4.2"
        assert manifest["filename"] == SETUP.rsplit("/", 1)[1]
        assert (manifest["size"], manifest["sha256"]) == HASHES[SETUP]
        assert manifest["published_at"] <= time.time() + 600
        assert time.time() <= manifest["expires_at"] + 600
        assert 0 < manifest["expires_at"] - manifest["published_at"] <= 90 * 86400
        emit(kind="signed_feed", host=host, verified=True, payload=manifest)
        for path in (SETUP, PORTABLE):
            status, fields, body = request(host, path, cap=5 * 1024 * 1024)
            assert status == 200 and "location" not in fields
            assert (len(body), hashlib.sha256(body).hexdigest()) == HASHES[path]
            emit(kind="artifact", host=host, path=path, verified=True)
    for path in ("/", "/app.js", "/styles.css?v=marketing", "/assets/secblitz.svg", FEED):
        request(HOSTS[0], path, headers={"Origin": "https://www.secblitz.lol", "Accept-Encoding": "gzip, br"})
    for path in (SETUP, "/assets/secblitz-demo.mp4?v=marketing"):
        request(HOSTS[0], path, headers={"Range": "bytes=0-63"}, cap=5 * 1024 * 1024)
    for path in ("/app.js", "/styles.css?v=marketing", "/assets/poster.webp?v=marketing",
                 "/assets/fonts/schibsted-grotesk-latin.woff2"):
        request(HOSTS[0], path, "HEAD")


def browser_checks(executable=None, frame_only=False):
    from playwright.sync_api import sync_playwright

    def wait(page, expression):
        # wait_for_function, which correctly meets the live unsafe-eval ban.
        for _ in range(100):
            if page.evaluate("() => (" + expression + ")"):
                return
            page.wait_for_timeout(100)
        raise AssertionError(f"Timed out: {expression}")

    with sync_playwright() as pw:
        if frame_only:
            framing_checks(pw, executable)
            return
        browser = pw.chromium.launch(channel="chromium", executable_path=executable,
                                     args=["--disable-gpu"])
        emit(kind="browser_version", version=browser.version, channel="chromium")
        context = browser.new_context(reduced_motion="reduce", viewport={"width": 1440, "height": 1000},
                                      service_workers="block")
        remote, errors, requests = [], [], []

        def route_request(route):
            url = route.request.url
            if urlsplit(url).hostname not in HOSTS:
                remote.append(url)
                route.abort()
            else:
                requests.append(url)
                if len(requests) > 60:
                    route.abort()
                    raise RuntimeError("Browser request cap exceeded")
                route.continue_()

        context.route("**/*", route_request)
        page = context.new_page()
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
        response = page.goto("https://secblitz.lol/?q=SECURITY_REVIEW_PLAIN_20261003#SECURITY_REVIEW_FRAGMENT", wait_until="networkidle")
        initial = response.text()
        video = page.locator("video")
        video.scroll_into_view_if_needed()
        wait(page, "document.querySelector('video').readyState >= 1")
        reduced = video.evaluate("v => ({paused:v.paused, autoplay:v.autoplay, controls:v.controls, muted:v.muted, defaultMuted:v.defaultMuted, loop:v.loop, src:v.currentSrc, time:v.currentTime})")
        assert reduced["paused"] and not reduced["autoplay"] and not reduced["controls"]
        assert reduced["muted"] and reduced["defaultMuted"] and reduced["loop"]
        assert page.locator("#video-still").is_visible()
        assert page.locator("figcaption, video[controls], #recording button").count() == 0
        assert "SECURITY_REVIEW_" not in page.locator("body").inner_text()
        emit(kind="browser_initial", status=response.status, initial_sha256=hashlib.sha256(initial.encode()).hexdigest(),
             scripts=page.locator("script").evaluate_all("ss=>ss.map(s=>({src:s.src,type:s.type,inline:!s.src}))"),
             reduced=reduced, marker_reflected="SECURITY_REVIEW_" in initial)
        context.grant_permissions(["clipboard-read", "clipboard-write"], origin="https://secblitz.lol")
        page.locator(".download-details summary").click()
        page.locator("#copy-sha").click()
        copied = page.evaluate("navigator.clipboard.readText()")
        assert copied == HASHES[SETUP][1]
        emit(kind="browser_behavior", reduced_poster=True,
             clipboard_exact=True, errors=errors, blocked_external_requests=remote,
             requests=requests)
        # Record incomplete playback and still attempt framing in a fresh browser.
        playback_error = None
        try:
            video.scroll_into_view_if_needed()
            page.emulate_media(reduced_motion="no-preference")
            wait(page, "document.querySelector('video').currentTime > 0.3")
            assert video.evaluate("v=>!v.paused && v.autoplay && v.muted && v.loop && !v.controls")
            page.emulate_media(reduced_motion="reduce")
            wait(page, "document.querySelector('video').paused")
            assert page.locator("#video-still").is_visible()
            emit(kind="playback", verified=True)
        except Exception as error:
            emit(kind="playback", verified=False, error=str(error))
            playback_error = error
        context.close()
        browser.close()
        framing_checks(pw, executable)
        if playback_error:
            raise playback_error


def framing_checks(pw, executable):
    browser = pw.chromium.launch(channel="chromium", executable_path=executable,
                                 args=["--disable-gpu"])
    context = browser.new_context(service_workers="block")
    context.route("**/*", lambda r: r.continue_() if r.request.url == "https://secblitz.lol/" else r.abort())
    parent = context.new_page()
    parent.route("https://www.secblitz.lol/security-review-frame", lambda r: r.fulfill(
        content_type="text/html", body='<iframe src="https://secblitz.lol/"></iframe>'))
    errors, failures = [], []
    parent.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    parent.on("requestfailed", lambda r: failures.append({"url": r.url, "error": r.failure}))
    session = context.new_cdp_session(parent)
    session.send("Log.enable")
    session.on("Log.entryAdded", lambda e: errors.append(e["entry"]["text"]))
    parent.goto("https://www.secblitz.lol/security-review-frame")
    parent.wait_for_timeout(1000)
    rendered = sum(frame.locator("h1").count() for frame in parent.frames[1:])
    emit(kind="framing", rendered_headings=rendered, console=errors, failures=failures,
         frame_urls=[f.url for f in parent.frames])
    assert rendered == 0 and (any("frame-ancestors" in e for e in errors)
                              or any("ERR_BLOCKED_BY_RESPONSE" in f["error"] for f in failures))
    context.close()
    browser.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--http", action="store_true")
    group.add_argument("--browser", action="store_true")
    group.add_argument("--frame", action="store_true", help="Run only the isolated framing check")
    parser.add_argument("--chromium", help="Optional installed Chromium executable for browser diagnostics")
    args = parser.parse_args()
    emit(kind="start", utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
         mode="http" if args.http else "frame" if args.frame else "browser")
    try:
        http_checks() if args.http else browser_checks(args.chromium, args.frame)
    except Exception as error:
        emit(kind="run_failure", error_type=type(error).__name__,
             error=str(error).splitlines()[0][:300] if str(error) else "Assertion failed")
        raise
    finally:
        mode = "http" if args.http else "frame" if args.frame else "browser"
        output = Path("/tmp/opencode") / f"secblitz-security-{mode}.json"
        output.write_text(json.dumps(RESULTS, indent=2) + "\n")
