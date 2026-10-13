"""
Tests for the portal half of the token gate.

This SDK used to have no portal validation at all — `init` checked the shape of
the string and proceeded. A revoked token, one already activated by another
application, and one that was never issued all initialised successfully, while
the other three SDKs refused all three.

So these tests are the point of the change rather than a formality around it.
Every one of them mocks `urllib.request.urlopen`: the suite must not depend on
whether a live government portal happens to be reachable, and a test that
reached it would be asserting against production.

The rule is in panda-spec/token-format.md: fail closed. A timeout, a refused
connection, a 500, or a body that will not parse must all mean *no key is
generated*. The one thing that must never happen is an unreachable portal
being read as approval.
"""

import io
import json
import socket
import urllib.error

import pytest

from panda.crypto.token import (
    DEFAULT_VALIDATION_URL,
    DEMO_TOKEN,
    InvalidTokenError,
    validate_token,
)

# A well-formed live token. Not the demo token, so it goes to the portal.
LIVE_TOKEN = "panda_live_" + "a" * 48


@pytest.fixture(autouse=True)
def _online(_skip_online_token_validation, monkeypatch):
    """
    Turn the portal back on for this module.

    `tests/conftest.py` disables online validation for every test, so that no
    other test in the suite reaches production. These tests are about the
    portal call, so they need it enabled and then mocked — and naming the
    conftest fixture as a parameter is what guarantees the order, rather than
    depending on which autouse fixture pytest happens to apply first.

    The request still never leaves the process: `portal_returns` and
    `portal_unreachable` replace `urlopen`. What is enabled here is the code
    path, not the network.
    """
    monkeypatch.delenv("PANDA_SKIP_ONLINE_VALIDATION", raising=False)


class FakeResponse:
    """Just enough of an http.client.HTTPResponse to be used as one."""

    def __init__(self, body, status=200):
        self._body = body.encode("utf-8") if isinstance(body, str) else body
        self.status = status

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def portal_returns(monkeypatch, body, status=200):
    """Make the portal answer with this body and status. Returns the calls list."""
    calls = []

    def fake_urlopen(request, timeout=None):
        calls.append({"request": request, "timeout": timeout})
        return FakeResponse(body, status)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    return calls


def portal_unreachable(monkeypatch, error):
    """Make the portal fail to answer at all."""
    calls = []

    def fake_urlopen(request, timeout=None):
        calls.append({"request": request, "timeout": timeout})
        raise error

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    return calls


class TestTheHappyPath:
    def test_a_valid_token_passes(self, monkeypatch):
        portal_returns(monkeypatch, json.dumps({"valid": True}))
        validate_token(LIVE_TOKEN)  # must not raise

    def test_it_posts_the_token_as_json_to_the_portal(self, monkeypatch):
        calls = portal_returns(monkeypatch, json.dumps({"valid": True}))

        validate_token(LIVE_TOKEN)

        assert len(calls) == 1
        request = calls[0]["request"]
        assert request.full_url == DEFAULT_VALIDATION_URL
        assert request.get_method() == "POST"
        assert json.loads(request.data.decode("utf-8")) == {"token": LIVE_TOKEN}
        assert request.get_header("Content-type") == "application/json"

    def test_it_waits_no_longer_than_the_timeout(self, monkeypatch):
        # init is a one-time interactive step; a long hang reads as a freeze.
        calls = portal_returns(monkeypatch, json.dumps({"valid": True}))

        validate_token(LIVE_TOKEN)

        assert calls[0]["timeout"] == 5

    def test_the_validation_url_can_be_overridden(self, monkeypatch):
        monkeypatch.setenv("PANDA_VALIDATION_URL", "https://portal.test/validate")
        calls = portal_returns(monkeypatch, json.dumps({"valid": True}))

        validate_token(LIVE_TOKEN)

        assert calls[0]["request"].full_url == "https://portal.test/validate"


class TestThePortalRefuses:
    def test_a_revoked_token_is_refused(self, monkeypatch):
        portal_returns(monkeypatch, json.dumps({"valid": False, "reason": "revoked"}))

        with pytest.raises(InvalidTokenError) as exc:
            validate_token(LIVE_TOKEN)

        assert "revoked" in str(exc.value)

    def test_an_already_activated_token_is_refused(self, monkeypatch):
        portal_returns(
            monkeypatch, json.dumps({"valid": False, "reason": "already_activated"})
        )

        with pytest.raises(InvalidTokenError) as exc:
            validate_token(LIVE_TOKEN)

        assert "already been used" in str(exc.value)

    def test_an_unrecognised_reason_is_refused(self, monkeypatch):
        portal_returns(monkeypatch, json.dumps({"valid": False, "reason": "invalid"}))

        with pytest.raises(InvalidTokenError) as exc:
            validate_token(LIVE_TOKEN)

        assert "not recognized" in str(exc.value)

    def test_a_missing_reason_is_still_refused(self, monkeypatch):
        # `valid: false` with no reason must not fall through to success. A
        # portal that omits the field is not a portal that approves.
        portal_returns(monkeypatch, json.dumps({"valid": False}))

        with pytest.raises(InvalidTokenError):
            validate_token(LIVE_TOKEN)

    def test_the_string_true_is_refused(self, monkeypatch):
        # Only the JSON boolean true is consent. A string is a truthy value in
        # Python, JavaScript and PHP alike, so `if not result["valid"]` read
        # `{"valid": "true"}` as a valid response — and, worse, read
        # `{"valid": "false"}` as one too. See the test below.
        portal_returns(monkeypatch, json.dumps({"valid": "true"}))

        with pytest.raises(InvalidTokenError):
            validate_token(LIVE_TOKEN)

    def test_the_string_false_is_refused(self, monkeypatch):
        # The dangerous one. A response explicitly saying the token is not
        # valid, read as approval, because "false" is a non-empty string and
        # therefore truthy. panda-go refused it — decoding a string into a Go
        # bool fails — while Node, PHP and this SDK accepted it.
        portal_returns(monkeypatch, json.dumps({"valid": "false"}))

        with pytest.raises(InvalidTokenError):
            validate_token(LIVE_TOKEN)

    def test_a_number_is_refused(self, monkeypatch):
        portal_returns(monkeypatch, json.dumps({"valid": 1}))

        with pytest.raises(InvalidTokenError):
            validate_token(LIVE_TOKEN)

    def test_null_is_refused(self, monkeypatch):
        portal_returns(monkeypatch, json.dumps({"valid": None}))

        with pytest.raises(InvalidTokenError):
            validate_token(LIVE_TOKEN)


class TestFailClosed:
    """An unreachable portal must never be read as approval."""

    def test_a_refused_connection_is_refused(self, monkeypatch):
        portal_unreachable(monkeypatch, urllib.error.URLError("connection refused"))

        with pytest.raises(InvalidTokenError) as exc:
            validate_token(LIVE_TOKEN)

        assert "Unable to reach" in str(exc.value)

    def test_a_timeout_is_refused(self, monkeypatch):
        portal_unreachable(monkeypatch, socket.timeout("timed out"))

        with pytest.raises(InvalidTokenError) as exc:
            validate_token(LIVE_TOKEN)

        assert "Unable to reach" in str(exc.value)

    def test_a_dns_failure_is_refused(self, monkeypatch):
        portal_unreachable(
            monkeypatch, urllib.error.URLError(socket.gaierror("name resolution"))
        )

        with pytest.raises(InvalidTokenError):
            validate_token(LIVE_TOKEN)

    def test_a_server_error_is_refused(self, monkeypatch):
        portal_unreachable(
            monkeypatch, urllib.error.HTTPError(DEFAULT_VALIDATION_URL, 500, "boom", {}, io.BytesIO(b""))
        )

        with pytest.raises(InvalidTokenError) as exc:
            validate_token(LIVE_TOKEN)

        assert "500" in str(exc.value)

    def test_a_404_is_reported_as_a_status_not_a_network_failure(self, monkeypatch):
        # HTTPError subclasses URLError, so catching them in the wrong order
        # reports a 404 as "unable to reach the portal" — which sends the
        # reader looking at firewalls instead of at the URL.
        portal_unreachable(
            monkeypatch, urllib.error.HTTPError(DEFAULT_VALIDATION_URL, 404, "gone", {}, io.BytesIO(b""))
        )

        with pytest.raises(InvalidTokenError) as exc:
            validate_token(LIVE_TOKEN)

        assert "404" in str(exc.value)
        assert "Unable to reach" not in str(exc.value)

    def test_a_non_200_is_refused(self, monkeypatch):
        portal_returns(monkeypatch, json.dumps({"valid": True}), status=503)

        with pytest.raises(InvalidTokenError) as exc:
            validate_token(LIVE_TOKEN)

        assert "503" in str(exc.value)

    def test_an_html_body_is_refused(self, monkeypatch):
        # What a captive portal, a block page, or a misconfigured proxy
        # returns. It parses as no JSON at all.
        portal_returns(monkeypatch, "<html><body>Blocked</body></html>")

        with pytest.raises(InvalidTokenError) as exc:
            validate_token(LIVE_TOKEN)

        assert "parse" in str(exc.value)

    def test_a_json_array_is_refused(self, monkeypatch):
        # Valid JSON, wrong shape. `result["valid"]` on a list raises
        # TypeError, which would escape as an unhandled crash rather than a
        # refusal the caller can catch.
        portal_returns(monkeypatch, json.dumps([{"valid": True}]))

        with pytest.raises(InvalidTokenError) as exc:
            validate_token(LIVE_TOKEN)

        assert "parse" in str(exc.value)

    def test_a_json_null_is_refused(self, monkeypatch):
        portal_returns(monkeypatch, "null")

        with pytest.raises(InvalidTokenError):
            validate_token(LIVE_TOKEN)

    def test_a_body_without_a_valid_field_is_refused(self, monkeypatch):
        portal_returns(monkeypatch, json.dumps({"status": "ok"}))

        with pytest.raises(InvalidTokenError) as exc:
            validate_token(LIVE_TOKEN)

        assert "parse" in str(exc.value)

    def test_an_empty_body_is_refused(self, monkeypatch):
        portal_returns(monkeypatch, "")

        with pytest.raises(InvalidTokenError):
            validate_token(LIVE_TOKEN)


class TestTheEscapeHatches:
    """The two ways the portal call is skipped. Both are deliberate."""

    def test_the_demo_token_makes_no_http_request(self, monkeypatch):
        calls = portal_unreachable(monkeypatch, AssertionError("no request should be made"))

        validate_token(DEMO_TOKEN)  # must not raise, and must not call out

        assert calls == []

    def test_the_demo_token_is_even_valid_with_no_network(self, monkeypatch):
        # Belt and braces: patching urlopen to blow up is the assertion, and
        # this proves a developer with no route to the portal can still init.
        monkeypatch.setattr(
            "urllib.request.urlopen",
            lambda *a, **k: (_ for _ in ()).throw(AssertionError("called")),
        )
        validate_token(DEMO_TOKEN)

    def test_skip_online_validation_makes_no_http_request(self, monkeypatch):
        monkeypatch.setenv("PANDA_SKIP_ONLINE_VALIDATION", "1")
        calls = portal_unreachable(monkeypatch, AssertionError("no request should be made"))

        validate_token(LIVE_TOKEN)

        assert calls == []

    def test_skip_online_validation_is_not_the_default(self, monkeypatch):
        # If this ever passes by accident, the gate is off for everyone.
        monkeypatch.delenv("PANDA_SKIP_ONLINE_VALIDATION", raising=False)
        calls = portal_returns(monkeypatch, json.dumps({"valid": True}))

        validate_token(LIVE_TOKEN)

        assert len(calls) == 1

    def test_a_demo_token_that_is_not_the_static_one_goes_to_the_portal(self, monkeypatch):
        # `panda_demo_` is a prefix, not a pass. Only the published string
        # skips the portal, or anybody could mint one locally.
        calls = portal_returns(monkeypatch, json.dumps({"valid": True}))

        validate_token("panda_demo_" + "a" * 48)

        assert len(calls) == 1


class TestFailuresBeforeThePortal:
    """The portal is not called for a token that already failed."""

    def test_an_empty_token_never_reaches_the_portal(self, monkeypatch):
        calls = portal_unreachable(monkeypatch, AssertionError("no request should be made"))

        with pytest.raises(InvalidTokenError):
            validate_token("")

        assert calls == []

    def test_a_malformed_token_never_reaches_the_portal(self, monkeypatch):
        calls = portal_unreachable(monkeypatch, AssertionError("no request should be made"))

        with pytest.raises(InvalidTokenError):
            validate_token("panda_live_" + "A" * 48)  # uppercase

        assert calls == []

    def test_a_token_with_a_trailing_newline_never_reaches_the_portal(self, monkeypatch):
        calls = portal_unreachable(monkeypatch, AssertionError("no request should be made"))

        with pytest.raises(InvalidTokenError):
            validate_token(LIVE_TOKEN + "\n")

        assert calls == []

    def test_the_error_names_the_expected_format(self, monkeypatch):
        monkeypatch.setenv("PANDA_SKIP_ONLINE_VALIDATION", "1")

        with pytest.raises(InvalidTokenError) as exc:
            validate_token("nonsense")

        assert "48 or 64" in str(exc.value)
