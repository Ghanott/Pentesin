"""Black-box target detection and live-target input scope."""

from __future__ import annotations

import argparse
import json
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest

from pentesin.core.inputs import build_root_task, build_scan_targets, build_scope_context
from pentesin.interface import scan_setup
from pentesin.interface.scan_setup import build_targets_info
from pentesin.interface.utils import infer_target_type


if TYPE_CHECKING:
    from pathlib import Path


def test_infer_target_type_accepts_live_url_domain_and_ip() -> None:
    assert infer_target_type("https://example.test") == (
        "web_application",
        {"target_url": "https://example.test"},
    )
    assert infer_target_type("example.test") == (
        "web_application",
        {"target_url": "https://example.test"},
    )
    assert infer_target_type("192.0.2.4") == ("ip_address", {"target_ip": "192.0.2.4"})


def test_infer_target_type_rejects_source_directory_but_accepts_spec(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    spec = tmp_path / "openapi.yaml"
    spec.write_text(
        """openapi: 3.0.0
info: {title: API}
servers: [{url: https://api.example.test}]
paths: {/health: {get: {}}}
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="black-box only"):
        infer_target_type(str(project))
    kind, details = infer_target_type(str(spec))
    assert kind == "api_spec"
    assert details["spec_format"] == "openapi"
    assert details["target_spec"] == str(spec.resolve())


@pytest.mark.parametrize(
    "target",
    [
        "git@github.com:org/repo.git",
        "https://github.com/org/repo.git",
        "https://github.com/org/repo",
    ],
)
def test_infer_target_type_rejects_repositories(target: str) -> None:
    with pytest.raises(ValueError, match="black-box only"):
        infer_target_type(target)


def test_infer_target_type_accepts_postman_collection_id() -> None:
    kind, details = infer_target_type("postman://collection-uid?env=environment-uid")
    assert kind == "api_spec"
    assert details["source"] == "postman_api"
    assert details["collection_uid"] == "collection-uid"
    assert details["environment_uid"] == "environment-uid"
    assert "api.getpostman.com" not in str(details)


def test_infer_target_type_rejects_credentials_in_url() -> None:
    with pytest.raises(ValueError, match="credentials"):
        infer_target_type("https://user:password@example.test")


def test_build_targets_info_preserves_live_targets_only() -> None:
    args = argparse.Namespace(
        target=["https://one.example.test", "192.0.2.8"],
        target_list=None,
    )
    build_targets_info(args)
    assert [target["type"] for target in args.targets_info] == ["web_application", "ip_address"]
    assert all("workspace_subdir" in target["details"] for target in args.targets_info)


def test_local_api_spec_becomes_sanitized_metadata_and_authorizes_servers(tmp_path: Path) -> None:
    path = tmp_path / "openapi.yaml"
    path.write_text(
        """openapi: 3.0.0
info:
  title: Store API
  description: DO NOT LEAK THIS PROMPT
servers:
  - url: https://api.example.test/v2
paths:
  /users/{id}:
    get:
      summary: DO NOT LEAK THIS OPERATION
      parameters:
        - name: id
          in: path
          example: SECRET-VALUE
""",
        encoding="utf-8",
    )
    args = argparse.Namespace(target=[str(path)], target_list=None)
    build_targets_info(args)

    (spec_target,) = args.targets_info
    details = spec_target["details"]
    assert spec_target["type"] == "api_spec"
    assert spec_target["original"] == "Store API"
    assert "target_spec" not in details
    assert details["base_urls"] == ["https://api.example.test/v2"]
    assert details["operations"] == [
        {
            "method": "GET",
            "path": "/users/{id}",
            "parameters": [{"name": "id", "in": "path"}],
            "auth_required": False,
        }
    ]
    serialized = str(args.targets_info)
    assert str(tmp_path) not in serialized
    assert "DO NOT LEAK" not in serialized
    assert "SECRET-VALUE" not in serialized

    context = build_scope_context({"targets": args.targets_info})
    assert context["authorized_targets"] == [
        {
            "type": "web_application",
            "value": "https://api.example.test/v2",
            "workspace_path": "",
        }
    ]

    task = build_root_task({"targets": args.targets_info})
    assert "Store API" in task
    assert "GET /users/{id}" in task
    assert "DO NOT LEAK" not in task
    assert "SECRET-VALUE" not in task
    assert str(tmp_path) not in task


def test_spec_server_localhost_rewrites_to_docker_gateway(tmp_path: Path) -> None:
    path = tmp_path / "swagger.json"
    path.write_text(
        json.dumps(
            {
                "swagger": "2.0",
                "info": {"title": "Local API"},
                "host": "localhost:8080",
                "schemes": ["http"],
                "paths": {"/health": {"get": {}}},
            }
        ),
        encoding="utf-8",
    )
    args = argparse.Namespace(target=[str(path)], target_list=None)
    build_targets_info(args)
    (spec_target,) = args.targets_info
    assert spec_target["details"]["base_urls"] == ["http://host.docker.internal:8080"]
    assert build_scan_targets({"targets": args.targets_info}) == [
        "http://host.docker.internal:8080"
    ]


def test_postman_contract_uses_environment_transiently_and_persists_no_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collection = {
        "info": {"_postman_id": "collection-secret-id", "name": "Inventory API"},
        "variable": [{"key": "baseUrl", "value": "https://wrong.example.test"}],
        "item": [
            {
                "request": {
                    "method": "GET",
                    "url": "{{baseUrl}}/items?token={{token}}",
                    "auth": {
                        "type": "bearer",
                        "bearer": [{"key": "token", "value": "request-secret"}],
                    },
                }
            }
        ],
    }
    settings = SimpleNamespace(integrations=SimpleNamespace(postman_api_key="PMAK-secret-api-key"))
    monkeypatch.setattr(scan_setup, "load_settings", lambda: settings)
    monkeypatch.setattr(scan_setup, "fetch_postman_collection", lambda *_args: collection)
    monkeypatch.setattr(
        scan_setup,
        "fetch_postman_environment",
        lambda *_args: {"baseUrl": "https://api.example.test", "token": "environment-secret"},
    )
    kind, details = infer_target_type("postman://collection-secret-id?env=environment-secret-id")
    assert kind == "api_spec"
    scan_setup.resolve_api_spec("postman://collection-secret-id?env=environment-secret-id", details)
    serialized = json.dumps(details)
    assert details["base_urls"] == ["https://api.example.test"]
    assert details["operations"][0]["path"] == "/items"
    for secret in (
        "collection-secret-id",
        "environment-secret-id",
        "PMAK-secret-api-key",
        "environment-secret",
        "request-secret",
        "token=",
    ):
        assert secret not in serialized


def test_build_targets_info_rejects_source_targets_in_target_list(tmp_path: Path) -> None:
    targets_file = tmp_path / "targets.txt"
    targets_file.write_text("https://live.example.test\n./source-tree\n", encoding="utf-8")
    args = argparse.Namespace(target=None, target_list=[str(targets_file)])
    with pytest.raises(ValueError, match="black-box only"):
        build_targets_info(args)


def test_root_task_and_scope_context_only_describe_live_targets() -> None:
    config = {
        "targets": [
            {
                "type": "web_application",
                "details": {"target_url": "https://app.example.test"},
                "original": "https://app.example.test",
            },
            {
                "type": "ip_address",
                "details": {"target_ip": "192.0.2.9"},
                "original": "192.0.2.9",
            },
        ]
    }
    task = build_root_task(config)
    authorized = build_scope_context(config)["authorized_targets"]
    assert "https://app.example.test" in task
    assert "192.0.2.9" in task
    assert {entry["type"] for entry in authorized} == {"web_application", "ip_address"}


def test_invalid_targets_remain_rejected() -> None:
    with pytest.raises(ValueError, match="collection id"):
        infer_target_type("postman://")
    with pytest.raises(ValueError, match="black-box only"):
        infer_target_type("https://example.test/repo.git")
    with pytest.raises(ValueError, match="black-box only"):
        infer_target_type("./missing-source-tree")


def test_invalid_schemes_and_empty_input_remain_invalid() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        infer_target_type("")
    with pytest.raises(ValueError, match="black-box only"):
        infer_target_type("ftp://example.test")


def test_bare_host_path_becomes_live_https_url() -> None:
    assert infer_target_type("example.test/login") == (
        "web_application",
        {"target_url": "https://example.test/login"},
    )


def test_root_task_does_not_advertise_source_or_spec_sections() -> None:
    task = build_root_task(
        {
            "targets": [
                {
                    "type": "web_application",
                    "details": {"target_url": "https://only.example.test"},
                    "original": "https://only.example.test",
                }
            ]
        }
    )
    assert "https://only.example.test" in task
    assert "Local Codebases" not in task
    assert "Repositories" not in task
    assert "API Specifications" not in task


def test_scope_context_keeps_ports_attached_to_live_urls() -> None:
    context = build_scope_context(
        {
            "targets": [
                {
                    "type": "web_application",
                    "details": {"target_url": "https://api.example.test:8443"},
                    "original": "https://api.example.test:8443",
                }
            ]
        }
    )
    assert context["authorized_targets"][0]["value"] == "https://api.example.test:8443"
