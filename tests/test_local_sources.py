"""Tests for black-box target rejection and operational workspace mounts."""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from pentesin.interface.scan_setup import attach_workspace_mount
from pentesin.interface.utils import check_mountable_dir, infer_target_type, read_target_list_file
from pentesin.runtime.session_manager import build_bind_mounts


def test_blackbox_target_rejects_local_directory(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    with pytest.raises(ValueError, match="black-box only"):
        infer_target_type(str(project))


def test_blackbox_target_rejects_repository_targets() -> None:
    for target in ("git@github.com:org/repo.git", "https://github.com/org/repo.git"):
        with pytest.raises(ValueError, match="black-box only"):
            infer_target_type(target)


def test_blackbox_target_accepts_spec_but_rejects_other_files(tmp_path: Path) -> None:
    spec = tmp_path / "openapi.yaml"
    spec.write_text(
        """openapi: 3.0.0
info: {title: API}
servers: [{url: https://api.example.test}]
paths: {/health: {get: {}}}
""",
        encoding="utf-8",
    )
    assert infer_target_type(str(spec))[0] == "api_spec"
    postman_kind, postman = infer_target_type("postman://collection-id")
    assert postman_kind == "api_spec"
    assert postman["source"] == "postman_api"
    random_file = tmp_path / "secret.txt"
    random_file.write_text("not source", encoding="utf-8")
    with pytest.raises(ValueError, match="black-box-only"):
        infer_target_type(str(random_file))


def test_check_mountable_dir_accepts_an_operational_directory(tmp_path: Path) -> None:
    check_mountable_dir(tmp_path)


def test_check_mountable_dir_rejects_missing_path(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not an existing directory"):
        check_mountable_dir(tmp_path / "nope")


def test_check_mountable_dir_rejects_filesystem_root() -> None:
    with pytest.raises(ValueError, match="Refusing to mount"):
        check_mountable_dir(Path("/"))


def test_check_mountable_dir_rejects_credential_directory(tmp_path: Path) -> None:
    credential_dir = tmp_path / ".ssh"
    credential_dir.mkdir()
    with pytest.raises(ValueError, match="holds credentials"):
        check_mountable_dir(credential_dir)


def test_workspace_mount_is_mounted_without_becoming_a_target(tmp_path: Path) -> None:
    """Workspace data can be mounted operationally but never defines scan scope."""
    workspace = tmp_path / "working-copy"
    workspace.mkdir()
    args = argparse.Namespace(
        targets_info=[],
        local_sources=[],
        workspace_mount=str(workspace),
    )

    attach_workspace_mount(args)

    assert args.targets_info == []
    assert args.local_sources == [
        {
            "source_path": str(workspace),
            "workspace_subdir": args.workspace_subdir,
            "protect_metadata": True,
        }
    ]
    assert build_bind_mounts(args.local_sources)[0]["target"] == (
        f"/workspace/{args.workspace_subdir}"
    )


def test_workspace_mount_refuses_credential_directory(tmp_path: Path) -> None:
    credential_dir = tmp_path / ".aws"
    credential_dir.mkdir()
    args = argparse.Namespace(
        targets_info=[], local_sources=[], workspace_mount=str(credential_dir)
    )
    with pytest.raises(ValueError, match="holds credentials"):
        attach_workspace_mount(args)
    assert args.local_sources == []


def test_workspace_mount_absent_leaves_local_sources_alone() -> None:
    args = argparse.Namespace(targets_info=[], local_sources=[], workspace_mount=None)
    attach_workspace_mount(args)
    assert args.local_sources == []


def test_read_target_list_file_strips_blank_lines(tmp_path: Path) -> None:
    target_list = tmp_path / "targets.txt"
    target_list.write_text(
        "\n https://test1.com/ \n\nhttp://test2.com:5789/\n  \n", encoding="utf-8"
    )
    assert read_target_list_file(str(target_list)) == [
        "https://test1.com/",
        "http://test2.com:5789/",
    ]


def test_read_target_list_file_ignores_comment_lines(tmp_path: Path) -> None:
    target_list = tmp_path / "targets.txt"
    target_list.write_text(
        "# production targets\nhttps://test1.com/\n  # staging targets\nhttp://test2.com:5789/\n",
        encoding="utf-8",
    )
    assert read_target_list_file(str(target_list)) == [
        "https://test1.com/",
        "http://test2.com:5789/",
    ]


def test_read_target_list_file_rejects_empty_file(tmp_path: Path) -> None:
    target_list = tmp_path / "targets.txt"
    target_list.write_text(" \n# no targets yet\n\n", encoding="utf-8")
    with pytest.raises(ValueError, match="is empty"):
        read_target_list_file(str(target_list))


def test_read_target_list_file_rejects_missing_path(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not an existing file"):
        read_target_list_file(str(tmp_path / "missing.txt"))


def test_read_target_list_file_rejects_non_utf8_file(tmp_path: Path) -> None:
    target_list = tmp_path / "targets.txt"
    target_list.write_bytes(b"https://test1.com/\xff\n")
    with pytest.raises(ValueError, match="must be valid UTF-8 text"):
        read_target_list_file(str(target_list))


@pytest.mark.parametrize("empty", ["", "   "])
def test_read_target_list_file_rejects_empty_path(empty: str) -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        read_target_list_file(empty)
