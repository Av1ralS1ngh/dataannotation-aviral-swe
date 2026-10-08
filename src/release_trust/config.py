"""Environment-backed configuration shared by the API services."""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    registry_url: str
    metadata_url: str
    coordination_url: str
    etcd_url: str
    database_url: str
    operator_dir: Path
    state_dir: Path
    online_keys_dir: Path
    root_keys_dir: Path
    publisher_token: str
    admin_token: str
    coordination_token: str
    replica_id: str
    log_level: str

    @classmethod
    def from_environment(cls) -> Settings:
        return cls(
            registry_url=os.getenv("REGISTRY_URL", "http://registry:5000"),
            metadata_url=os.getenv("METADATA_URL", "http://metadata:8080"),
            coordination_url=os.getenv(
                "COORDINATION_URL", "http://coordination:8090"
            ),
            etcd_url=os.getenv("ETCD_URL", "http://etcd:2379"),
            database_url=os.getenv(
                "DATABASE_URL",
                "sqlite+pysqlite:////tmp/release-trust-audit.db",
            ),
            operator_dir=Path(os.getenv("OPERATOR_DIR", "/operator")),
            state_dir=Path(os.getenv("STATE_DIR", "/state")),
            online_keys_dir=Path(
                os.getenv("ONLINE_KEYS_DIR", "/publisher-keys")
            ),
            root_keys_dir=Path(os.getenv("ROOT_KEYS_DIR", "/root-keys")),
            publisher_token=os.getenv("PUBLISHER_TOKEN", "local-publisher-token"),
            admin_token=os.getenv("ADMIN_TOKEN", "local-admin-token"),
            coordination_token=os.getenv(
                "COORDINATION_TOKEN", "local-coordination-token"
            ),
            replica_id=os.getenv("REPLICA_ID", "admission-local"),
            log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings.from_environment()
