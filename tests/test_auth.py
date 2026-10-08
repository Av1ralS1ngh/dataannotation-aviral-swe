import pytest
from fastapi import HTTPException

from release_trust.auth import require_admin_token, require_publisher_token


def test_publisher_token_uses_dedicated_header(isolated_settings):
    require_publisher_token("test-publisher")
    with pytest.raises(HTTPException) as failure:
        require_publisher_token("wrong")
    assert failure.value.status_code == 401


def test_admin_token_requires_bearer_scheme(isolated_settings):
    require_admin_token("Bearer test-admin")
    with pytest.raises(HTTPException) as failure:
        require_admin_token("test-admin")
    assert failure.value.status_code == 401
