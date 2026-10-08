import base64

import pytest
from fastapi import HTTPException

from release_trust.coordination import JOURNAL_KEY, _validate_request


def encoded(value: str) -> str:
    return base64.b64encode(value.encode()).decode()


def test_range_is_limited_to_authority_journal():
    _validate_request("kv/range", {"key": encoded(JOURNAL_KEY)})
    with pytest.raises(HTTPException) as failure:
        _validate_request("kv/range", {"key": encoded("release/metadata")})
    assert failure.value.status_code == 403


def test_transaction_rejects_unrelated_puts():
    payload = {
        "compare": [{"key": encoded(JOURNAL_KEY)}],
        "success": [
            {
                "request_put": {
                    "key": encoded("release/metadata"),
                    "value": encoded("{}"),
                }
            }
        ],
        "failure": [],
    }
    with pytest.raises(HTTPException) as failure:
        _validate_request("kv/txn", payload)
    assert failure.value.status_code == 403
