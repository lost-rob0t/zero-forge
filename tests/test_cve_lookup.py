"""Tests for the CVE lookup tool."""

import json
from unittest.mock import MagicMock, patch

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


def test_cve_lookup_network_failure():
    with patch("zero_forge.tools.cve_lookup.urllib.request.urlopen", side_effect=Exception("Network error")):
        result = cve_lookup("CVE-2021-44228")
        assert result["cve_id"] == "CVE-2021-44228"
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
        assert result["description"] == "Log4Shell RCE vulnerability"
        assert result["references"] == ["https://example.com/advisory"]
        assert result["cvss"] == "10.0"
        assert result["published"] == "2021-12-10T00:00:00"
