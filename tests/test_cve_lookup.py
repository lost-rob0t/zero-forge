"""Tests for the CVE lookup tool."""

import json
from unittest.mock import MagicMock, patch

import pytest

from zero_forge.tools.cve_lookup import cve_lookup


def test_cve_lookup_formats_id():
    with patch("zero_forge.tools.cve_lookup.urllib.request.urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"vulnerabilities": []}'
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = cve_lookup("2021-44228")
        assert result["cve_id"] == "CVE-2021-44228"


def test_cve_lookup_rejects_malformed_id_before_network():
    with patch("zero_forge.tools.cve_lookup.urllib.request.urlopen") as mock_urlopen:
        with pytest.raises(ValueError, match="CVE ID must match"):
            cve_lookup("not-a-cve")
    mock_urlopen.assert_not_called()


def test_cve_lookup_network_failure():
    with patch("zero_forge.tools.cve_lookup.urllib.request.urlopen", side_effect=Exception("Network error")):
        result = cve_lookup("CVE-2021-44228")
        assert result["cve_id"] == "CVE-2021-44228"
        assert result["status"] == "permanent_failure"
        assert result["description"] == ""
        assert result["references"] == []


def test_cve_lookup_parses_response():
    mock_data = {
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2021-44228",
                "descriptions": [
                    {"lang": "en", "value": "Log4Shell RCE vulnerability"}
                ],
                "references": [
                    {"url": "https://example.com/advisory"}
                ],
                "metrics": {
                    "cvssMetricV31": [{
                        "cvssData": {"baseScore": 10.0}
                    }]
                },
                "published": "2021-12-10T00:00:00"
            }
        }]
    }
    with patch("zero_forge.tools.cve_lookup.urllib.request.urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(mock_data).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = cve_lookup("CVE-2021-44228")
        assert result["status"] == "success"
        assert result["description"] == "Log4Shell RCE vulnerability"
        assert result["references"] == ["https://example.com/advisory"]
        assert result["cvss"] == "10.0"
        assert result["published"] == "2021-12-10T00:00:00"


def test_cve_lookup_not_found():
    """Empty vulnerabilities list should return not_found status."""
    with patch("zero_forge.tools.cve_lookup.urllib.request.urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"vulnerabilities": []}'
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = cve_lookup("CVE-2021-44228")
        assert result["status"] == "not_found"
        assert result["description"] == ""


def test_cve_lookup_http_error_404():
    """HTTP 404 should return not_found status."""
    import urllib.error
    err = urllib.error.HTTPError("", 404, "Not Found", {}, None)
    with patch("zero_forge.tools.cve_lookup.urllib.request.urlopen", side_effect=err):
        result = cve_lookup("CVE-2021-44228")
        assert result["status"] == "not_found"
        assert result["error_category"] == "http_404"


def test_cve_lookup_http_error_429_rate_limit():
    """HTTP 429 should be retryable then permanent after exhausting retries."""
    import urllib.error
    err = urllib.error.HTTPError("", 429, "Too Many Requests", {}, None)
    with (
        patch("zero_forge.tools.cve_lookup.urllib.request.urlopen", side_effect=err),
        patch("zero_forge.tools.cve_lookup.time.sleep"),
    ):
        result = cve_lookup("CVE-2021-44228")
        assert result["status"] == "permanent_failure"
        assert result["error_category"] == "http_429_rate_limit"
        assert "exhausted" in result["error_message"]


def test_cve_lookup_http_error_500_server_error():
    """HTTP 500 should be retryable then permanent after exhausting retries."""
    import urllib.error
    err = urllib.error.HTTPError("", 500, "Internal Server Error", {}, None)
    with (
        patch("zero_forge.tools.cve_lookup.urllib.request.urlopen", side_effect=err),
        patch("zero_forge.tools.cve_lookup.time.sleep"),
    ):
        result = cve_lookup("CVE-2021-44228")
        assert result["status"] == "permanent_failure"
        assert result["error_category"] == "http_500_server_error"
        assert "exhausted" in result["error_message"]


def test_cve_lookup_http_error_403_permanent():
    """HTTP 403 should be a permanent failure (not retried)."""
    import urllib.error
    err = urllib.error.HTTPError("", 403, "Forbidden", {}, None)
    with patch("zero_forge.tools.cve_lookup.urllib.request.urlopen", side_effect=err):
        result = cve_lookup("CVE-2021-44228")
        assert result["status"] == "permanent_failure"
        assert result["error_category"] == "http_403"


def test_cve_lookup_url_error_network():
    """URLError should be retryable then permanent after exhausting retries."""
    import urllib.error
    err = urllib.error.URLError("Connection refused")
    with (
        patch("zero_forge.tools.cve_lookup.urllib.request.urlopen", side_effect=err),
        patch("zero_forge.tools.cve_lookup.time.sleep"),
    ):
        result = cve_lookup("CVE-2021-44228")
        assert result["status"] == "permanent_failure"
        assert result["error_category"] == "network_error"
        assert "exhausted" in result["error_message"]


def test_cve_lookup_timeout():
    """TimeoutError should be retryable then permanent after exhausting retries."""
    err = TimeoutError("Request timed out")
    with (
        patch("zero_forge.tools.cve_lookup.urllib.request.urlopen", side_effect=err),
        patch("zero_forge.tools.cve_lookup.time.sleep"),
    ):
        result = cve_lookup("CVE-2021-44228")
        assert result["status"] == "permanent_failure"
        assert result["error_category"] == "timeout"
        assert "exhausted" in result["error_message"]


def test_cve_lookup_malformed_json():
    """Malformed JSON response should be a permanent failure."""
    with patch("zero_forge.tools.cve_lookup.urllib.request.urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'not valid json {{{'
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = cve_lookup("CVE-2021-44228")
        assert result["status"] == "permanent_failure"
        assert result["error_category"] == "malformed_json"


def test_cve_lookup_retry_then_success():
    """A retryable failure followed by success should return success."""
    import urllib.error
    mock_data = {
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2021-44228",
                "descriptions": [
                    {"lang": "en", "value": "Log4Shell"}
                ],
                "references": [],
                "metrics": {},
                "published": "2021-12-10"
            }
        }]
    }
    err = urllib.error.URLError("Connection refused")
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(mock_data).encode()
    mock_resp.__enter__ = MagicMock(return_value=mock_resp)
    mock_resp.__exit__ = MagicMock(return_value=False)

    with (
        patch("zero_forge.tools.cve_lookup.urllib.request.urlopen", side_effect=[err, mock_resp]),
        patch("zero_forge.tools.cve_lookup.time.sleep"),
    ):
        result = cve_lookup("CVE-2021-44228")
        assert result["status"] == "success"
        assert result["description"] == "Log4Shell"


def test_cve_lookup_returns_dict_with_status_field():
    """The returned dict must include a status field for typed handling."""
    with patch("zero_forge.tools.cve_lookup.urllib.request.urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"vulnerabilities": []}'
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = cve_lookup("CVE-2021-44228")
        assert "status" in result
        assert "error_category" in result
        assert "error_message" in result
