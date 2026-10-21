"""Recognize API specifications and extract safe endpoint-map metadata.

Specifications are host-side inputs only. The sandbox receives a bounded,
sanitized method/path/parameter inventory, never the raw spec, examples, auth
values, environment secrets, or referenced local files.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, quote, urlsplit

import requests
import yaml


logger = logging.getLogger(__name__)

SPEC_EXTENSIONS = frozenset({".json", ".yaml", ".yml"})
_MAX_SPEC_BYTES = 5 * 1024 * 1024
_MAX_POSTMAN_DEPTH = 25
_MAX_OPERATIONS = 250
_MAX_PARAMETERS = 20
_MAX_FIELDS = 20
_MAX_TEXT = 120
_HTTP_METHODS = frozenset({"get", "put", "post", "delete", "options", "head", "patch", "trace"})


class SpecParseError(ValueError):
    """Raised when a spec cannot be read, recognized, or fetched."""


def _safe_yaml_load(text: str, name: str) -> Any:
    try:
        events = list(yaml.parse(text, Loader=yaml.SafeLoader))
    except (yaml.YAMLError, RecursionError) as exc:
        raise SpecParseError(f"{name} is not valid YAML: {exc}") from exc
    nesting = 0
    for event in events:
        if isinstance(event, yaml.events.AliasEvent):
            raise SpecParseError(f"YAML aliases are not accepted in API specs: {name}")
        if isinstance(event, (yaml.events.MappingStartEvent, yaml.events.SequenceStartEvent)):
            nesting += 1
            if nesting > 100:
                raise SpecParseError(f"YAML nesting limit exceeded: {name}")
        elif isinstance(event, (yaml.events.MappingEndEvent, yaml.events.SequenceEndEvent)):
            nesting -= 1
    try:
        return yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError) as exc:
        raise SpecParseError(f"{name} is not valid YAML: {exc}") from exc


def _check_spec_size(path: Path) -> None:
    if path.stat().st_size > _MAX_SPEC_BYTES:
        raise SpecParseError(f"Spec exceeds {_MAX_SPEC_BYTES} bytes: {path.name}")


def load_spec(path: str | Path) -> dict[str, Any]:
    """Load a JSON/YAML spec mapping on the host."""
    p = Path(path)
    try:
        _check_spec_size(p)
        text = p.read_text(encoding="utf-8")
    except SpecParseError:
        raise
    except (OSError, UnicodeError) as exc:
        raise SpecParseError(f"Cannot read spec {p.name}: {exc}") from exc
    try:
        data: Any = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        data = _safe_yaml_load(text, p.name)
    if not isinstance(data, dict):
        return _require_mapping(data, p.name)
    return data


def _require_mapping(data: Any, name: str) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise SpecParseError(f"{name} does not contain a mapping at the top level")
    return data


def classify_spec(raw: dict[str, Any]) -> str | None:
    """Return ``openapi`` / ``swagger`` / ``postman``, or ``None``."""
    if isinstance(raw.get("openapi"), str):
        return "openapi"
    if str(raw.get("swagger", "")).startswith("2"):
        return "swagger"
    info = raw.get("info")
    if isinstance(info, dict) and ("_postman_id" in info or "item" in raw):
        return "postman"
    return None


def detect_spec_format(path: Path) -> str | None:
    if path.suffix.lower() not in SPEC_EXTENSIONS:
        return None
    try:
        return classify_spec(load_spec(path))
    except SpecParseError:
        return None


def _safe_text(value: Any, max_chars: int = _MAX_TEXT) -> str:
    if not isinstance(value, str):
        return ""
    value = "".join(char for char in value if ord(char) >= 0x20 and ord(char) != 0x7F)
    return value[:max_chars]


def spec_title(raw: dict[str, Any]) -> str:
    info = raw.get("info")
    if not isinstance(info, dict):
        return "API"
    return _safe_text(info.get("title") or info.get("name") or "API").strip() or "API"


def _absolute_urls(candidates: list[str]) -> list[str]:
    """Normalize valid absolute HTTP(S) servers to origins; reject unresolved/credential URLs."""
    urls: list[str] = []
    for candidate in candidates:
        try:
            split = urlsplit(candidate.strip())
        except ValueError:
            continue
        if split.scheme.lower() not in ("http", "https") or not split.hostname:
            continue
        if split.username or split.password or any(char in split.netloc for char in "{}\r\n"):
            continue
        host_raw = split.hostname.rstrip(".")
        if "{" in host_raw or "}" in host_raw:
            continue
        try:
            host = host_raw.encode("idna").decode("ascii").lower()
            port = split.port
        except (UnicodeError, ValueError):
            continue
        if not host:
            continue
        default_port = 80 if split.scheme.lower() == "http" else 443
        authority = f"[{host}]" if ":" in host else host
        if port is not None and port != default_port:
            authority = f"{authority}:{port}"
        path = _safe_text(split.path).rstrip("/")
        urls.append(f"{split.scheme.lower()}://{authority}{path}")
    return list(dict.fromkeys(urls))


_SERVER_VAR_PATTERN = re.compile(r"\{([^{}/]+)\}")
_POSTMAN_VAR_PATTERN = re.compile(r"\{\{\s*([^}]+?)\s*\}\}")


def _resolve_server_url(url: str, variables: Any) -> str:
    """Resolve only host variables needed for authorization; keep path templates."""
    if "{" not in url or not isinstance(variables, dict):
        return url
    defaults = {
        str(name): str(value["default"])
        for name, value in variables.items()
        if isinstance(value, dict) and value.get("default") is not None
    }
    try:
        split = urlsplit(url)
    except ValueError:
        return url
    authority = _SERVER_VAR_PATTERN.sub(
        lambda match: defaults.get(match.group(1), match.group(0)),
        split.netloc,
    )
    # Server path variables can carry deployment tokens or tenant-specific
    # values. Keep them as templates; only host substitutions grant scope.
    return f"{split.scheme}://{authority}{split.path}"


def _server_urls(servers: Any) -> list[str]:
    if not isinstance(servers, list):
        return []
    return [
        _resolve_server_url(str(server["url"]), server.get("variables"))
        for server in servers
        if isinstance(server, dict) and server.get("url")
    ]


def _openapi_base_urls(raw: dict[str, Any]) -> list[str]:
    candidates = _server_urls(raw.get("servers"))
    paths = raw.get("paths")
    if isinstance(paths, dict):
        for path_item in paths.values():
            if not isinstance(path_item, dict):
                continue
            candidates.extend(_server_urls(path_item.get("servers")))
            for method, operation in path_item.items():
                if str(method).lower() in _HTTP_METHODS and isinstance(operation, dict):
                    candidates.extend(_server_urls(operation.get("servers")))
                    if len(candidates) >= _MAX_OPERATIONS:
                        return _absolute_urls(candidates[:_MAX_OPERATIONS])
    return _absolute_urls(candidates[:_MAX_OPERATIONS])


def _swagger_base_urls(raw: dict[str, Any]) -> list[str]:
    host = str(raw.get("host", "")).strip()
    if not host:
        return []
    base_path = str(raw.get("basePath", "")).strip()
    schemes = [scheme for scheme in (raw.get("schemes") or ["https"]) if isinstance(scheme, str)]
    return _absolute_urls([f"{scheme}://{host}{base_path}" for scheme in schemes])


def postman_variables(raw: dict[str, Any]) -> dict[str, str]:
    """Build a transient variable map; callers must not persist these values."""
    variables: dict[str, str] = {}
    entries = raw.get("variable")
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, dict) and entry.get("key") is not None:
                variables[str(entry["key"])] = str(entry.get("value", ""))
    return variables


def _resolve_postman_vars(text: str, variables: dict[str, str]) -> str:
    if not variables or "{{" not in text:
        return text
    return _POSTMAN_VAR_PATTERN.sub(
        lambda match: variables.get(match.group(1), match.group(0)), text
    )


def _postman_request_url(url: Any, variables: dict[str, str]) -> str:
    if isinstance(url, str):
        raw = url
    elif isinstance(url, dict):
        raw = str(url.get("raw", ""))
        if not raw:
            host = url.get("host")
            raw = (
                ".".join(str(part) for part in host) if isinstance(host, list) else str(host or "")
            )
    else:
        return ""
    return _resolve_postman_vars(raw, variables)


def _postman_hosts(items: Any, variables: dict[str, str], hosts: list[str], depth: int = 0) -> None:
    if depth > _MAX_POSTMAN_DEPTH or not isinstance(items, list):
        return
    for node in items:
        if not isinstance(node, dict):
            continue
        if isinstance(node.get("item"), list):
            _postman_hosts(node["item"], variables, hosts, depth + 1)
            continue
        request = node.get("request")
        if not isinstance(request, dict):
            continue
        split = urlsplit(_postman_request_url(request.get("url"), variables))
        if split.scheme and split.netloc:
            hosts.append(f"{split.scheme}://{split.netloc}")


_POSTMAN_SERVER_VARIABLES = frozenset(
    {"baseurl", "baseuri", "apiurl", "apiuri", "host", "server", "endpoint", "url"}
)


def _postman_base_urls(raw: dict[str, Any], extra_variables: dict[str, str] | None) -> list[str]:
    variables = postman_variables(raw)
    if extra_variables:
        variables.update(extra_variables)
    # Only resolve conventional server variable names into persisted scope.
    # Environment fields like token/password/secret can never become host data.
    scope_variables = {
        name: value
        for name, value in variables.items()
        if re.sub(r"[^a-z0-9]", "", name.lower()) in _POSTMAN_SERVER_VARIABLES
    }
    hosts: list[str] = []
    _postman_hosts(raw.get("item"), scope_variables, hosts)
    return _absolute_urls(hosts)


def spec_base_urls(
    raw: dict[str, Any], *, extra_variables: dict[str, str] | None = None
) -> list[str]:
    """Return the safe HTTP(S) origins declared by the API contract."""
    kind = classify_spec(raw)
    if kind == "openapi":
        return _openapi_base_urls(raw)
    if kind == "swagger":
        return _swagger_base_urls(raw)
    if kind == "postman":
        return _postman_base_urls(raw, extra_variables)
    raise SpecParseError("File is not a recognized OpenAPI, Swagger, or Postman spec")


def _resolve_internal_ref(raw: dict[str, Any], ref: str) -> Any:
    if not ref.startswith("#/"):
        return None
    current: Any = raw
    for segment in ref[2:].split("/"):
        key = segment.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            current = current.get(key)
        elif isinstance(current, list) and key.isdigit() and int(key) < len(current):
            current = current[int(key)]
        else:
            return None
    return current


def _schema_fields(
    schema: Any,
    raw: dict[str, Any],
    depth: int = 0,
    seen_refs: frozenset[str] = frozenset(),
) -> list[dict[str, str]]:
    if depth >= 2 or not isinstance(schema, dict):
        return []
    ref = schema.get("$ref")
    if isinstance(ref, str):
        if ref in seen_refs:
            return []
        resolved = _resolve_internal_ref(raw, ref)
        return _schema_fields(resolved, raw, depth, seen_refs | {ref})
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return []
    fields: list[dict[str, str]] = []
    for name, child in list(properties.items())[:_MAX_FIELDS]:
        safe_name = _safe_text(name).strip()
        if not safe_name or not isinstance(child, dict):
            continue
        item = {"name": safe_name, "type": _safe_text(child.get("type", "object"))}
        nested = _schema_fields(child, raw, depth + 1, seen_refs)
        if nested:
            item["fields"] = json.dumps(nested, ensure_ascii=True, separators=(",", ":"))
        fields.append(item)
    return fields


def _openapi_path_operations(  # noqa: PLR0912
    path: str, path_item: Any, raw: dict[str, Any]
) -> list[dict[str, Any]]:
    safe_path = _safe_text(path).strip()
    if not safe_path.startswith("/") or not isinstance(path_item, dict):
        return []
    path_params = path_item.get("parameters", [])
    operations: list[dict[str, Any]] = []
    for method_key, operation in path_item.items():
        method = str(method_key).lower()
        if method not in _HTTP_METHODS or not isinstance(operation, dict):
            continue
        params: list[dict[str, str]] = []
        op_params = operation.get("parameters", [])
        combined = (path_params if isinstance(path_params, list) else []) + (
            op_params if isinstance(op_params, list) else []
        )
        body_fields: list[dict[str, str]] = []
        form_names: list[str] = []
        for parameter in combined[:_MAX_PARAMETERS]:
            if not isinstance(parameter, dict) or "$ref" in parameter:
                continue
            name = _safe_text(parameter.get("name", "")).strip()
            location = _safe_text(parameter.get("in", "")).strip().lower()
            if name and location in {"path", "query", "header", "cookie"}:
                params.append({"name": name, "in": location})
            elif name and location == "formdata":
                form_names.append(name)
            elif location == "body":
                body_fields.extend(_schema_fields(parameter.get("schema"), raw))
        operation_info: dict[str, Any] = {
            "method": method.upper(),
            "path": safe_path,
            "parameters": params,
            "auth_required": bool(operation.get("security", raw.get("security", []))),
        }
        consumes = operation.get("consumes", raw.get("consumes", []))
        if isinstance(consumes, list) and consumes:
            operation_info["content_types"] = [_safe_text(media) for media in consumes[:10]]
        if form_names:
            body_fields.extend({"name": name, "type": "formData"} for name in form_names)
        body = operation.get("requestBody")
        content = body.get("content") if isinstance(body, dict) else None
        if isinstance(content, dict):
            operation_info["content_types"] = [
                _safe_text(media).strip() for media in list(content)[:10]
            ]
            fields: list[dict[str, str]] = []
            for media in list(content.values())[:3]:
                if isinstance(media, dict):
                    fields.extend(_schema_fields(media.get("schema"), raw))
            body_fields.extend(fields)
        if body_fields:
            operation_info["body_fields"] = body_fields[:_MAX_FIELDS]
        security = operation.get("security", raw.get("security", []))
        if isinstance(security, list):
            names = sorted(
                {
                    _safe_text(name).strip()
                    for requirement in security[:20]
                    if isinstance(requirement, dict)
                    for name in requirement
                    if _safe_text(name).strip()
                }
            )
            if names:
                operation_info["security_schemes"] = names[:20]
        operations.append(operation_info)
    return operations


def _openapi_operations(raw: dict[str, Any]) -> list[dict[str, Any]]:
    paths = raw.get("paths")
    if not isinstance(paths, dict):
        return []
    operations: list[dict[str, Any]] = []
    for path, path_item in paths.items():
        operations.extend(_openapi_path_operations(path, path_item, raw))
        if len(operations) > _MAX_OPERATIONS:
            return operations[: _MAX_OPERATIONS + 1]
    return operations[: _MAX_OPERATIONS + 1]


def _postman_operation(request: dict[str, Any], variables: dict[str, str]) -> dict[str, Any] | None:
    url_object = request.get("url")
    # Resolve variables for parsing, then replace their values before retaining
    # path text so tokens cannot be serialized into endpoint metadata.
    resolved_url = _postman_request_url(url_object, variables)
    split = urlsplit(resolved_url)
    raw_url = (
        str(url_object.get("raw", "")) if isinstance(url_object, dict) else str(url_object or "")
    )
    raw_path = urlsplit(raw_url).path
    if not raw_path and isinstance(url_object, dict) and isinstance(url_object.get("path"), list):
        raw_path = "/" + "/".join(str(part) for part in url_object["path"])
    path = _safe_text(raw_path or split.path or "/").strip()
    path = _POSTMAN_VAR_PATTERN.sub(lambda match: "{" + _safe_text(match.group(1)) + "}", path)
    if path.startswith("{") and "}" in path:
        _, separator, suffix = path.partition("}")
        if separator and suffix.startswith("/"):
            path = suffix
    for name, value in variables.items():
        safe_value = _safe_text(value)
        if safe_value:
            path = path.replace(safe_value, "{" + _safe_text(name) + "}")
    if not path.startswith("/"):
        return None

    query_items = url_object.get("query", []) if isinstance(url_object, dict) else []
    params = (
        [
            {"name": _safe_text(item.get("key")), "in": "query"}
            for item in query_items[:_MAX_PARAMETERS]
            if isinstance(item, dict) and item.get("key")
        ]
        if isinstance(query_items, list)
        else []
    )
    seen_param_names = {param["name"] for param in params}
    for query_key, _ in parse_qsl(urlsplit(raw_url).query, keep_blank_values=True):
        safe_key = _safe_text(query_key).strip()
        if safe_key and safe_key not in seen_param_names and len(params) < _MAX_PARAMETERS:
            params.append({"name": safe_key, "in": "query"})
            seen_param_names.add(safe_key)

    method = _safe_text(request.get("method", "GET")).upper()
    if method.lower() not in _HTTP_METHODS:
        return None
    operation: dict[str, Any] = {
        "method": method,
        "path": path,
        "parameters": params,
        "auth_required": isinstance(request.get("auth"), dict)
        and str(request["auth"].get("type", "noauth")).lower() != "noauth",
    }
    headers = request.get("header")
    if isinstance(headers, list):
        content_types = [
            _safe_text(header.get("value", ""))
            for header in headers[:20]
            if isinstance(header, dict)
            and str(header.get("key", "")).lower() == "content-type"
            and header.get("value")
        ]
        if content_types:
            operation["content_types"] = content_types[:10]
    return operation


def _visit_postman_items(
    items: Any,
    variables: dict[str, str],
    operations: list[dict[str, Any]],
    depth: int = 0,
) -> None:
    if depth > _MAX_POSTMAN_DEPTH or not isinstance(items, list):
        return
    for node in items:
        if len(operations) > _MAX_OPERATIONS or not isinstance(node, dict):
            continue
        if isinstance(node.get("item"), list):
            _visit_postman_items(node["item"], variables, operations, depth + 1)
            continue
        request = node.get("request")
        if isinstance(request, dict) and (operation := _postman_operation(request, variables)):
            operations.append(operation)


def _postman_operations(
    raw: dict[str, Any], extra_variables: dict[str, str] | None
) -> list[dict[str, Any]]:
    variables = postman_variables(raw)
    if extra_variables:
        variables.update(extra_variables)
    operations: list[dict[str, Any]] = []
    _visit_postman_items(raw.get("item"), variables, operations)
    return operations[: _MAX_OPERATIONS + 1]


def spec_operations(
    raw: dict[str, Any], *, extra_variables: dict[str, str] | None = None
) -> list[dict[str, Any]]:
    """Return a bounded, sanitized method/path/parameter map with no values."""
    kind = classify_spec(raw)
    if kind in {"openapi", "swagger"}:
        return _openapi_operations(raw)
    if kind == "postman":
        return _postman_operations(raw, extra_variables)
    raise SpecParseError("File is not a recognized OpenAPI, Swagger, or Postman spec")


POSTMAN_API_BASE = "https://api.getpostman.com"
_POSTMAN_FETCH_TIMEOUT = 30


def _postman_api_json(url: str, api_key: str, label: str) -> dict[str, Any]:
    if not api_key:
        raise SpecParseError(
            "POSTMAN_API_KEY is not set. Export a Postman API key (PMAK-…) to fetch "
            "from the Postman API, or pass a local collection file instead."
        )
    try:
        response = requests.get(
            url,
            headers={"X-Api-Key": api_key, "Accept": "application/json"},
            timeout=_POSTMAN_FETCH_TIMEOUT,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        raise SpecParseError(f"Failed to reach the Postman API: {exc}") from exc
    if response.status_code == 401:
        raise SpecParseError("Postman API rejected the key (401). Check POSTMAN_API_KEY.")
    if response.status_code == 404:
        raise SpecParseError(f"Postman {label} not found (404). Check the id and access.")
    if response.status_code != 200:
        raise SpecParseError(f"Postman API returned HTTP {response.status_code} for {label}.")
    try:
        payload = response.json()
    except ValueError as exc:
        raise SpecParseError(f"Postman API returned non-JSON for {label}") from exc
    if not isinstance(payload, dict):
        raise SpecParseError(f"Unexpected Postman API response shape for {label}")
    return payload


def fetch_postman_collection(collection_uid: str, api_key: str) -> dict[str, Any]:
    payload = _postman_api_json(
        f"{POSTMAN_API_BASE}/collections/{quote(collection_uid, safe='')}",
        api_key,
        "collection",
    )
    collection = payload.get("collection", payload)
    if not isinstance(collection, dict) or not collection:
        raise SpecParseError(f"Postman collection {collection_uid} came back empty")
    return collection


def fetch_postman_environment(environment_uid: str, api_key: str) -> dict[str, str]:
    payload = _postman_api_json(
        f"{POSTMAN_API_BASE}/environments/{quote(environment_uid, safe='')}",
        api_key,
        f"environment {environment_uid}",
    )
    environment = payload.get("environment", payload)
    values = environment.get("values") if isinstance(environment, dict) else None
    if not isinstance(values, list):
        return {}
    return {
        str(value["key"]): str(value.get("value", ""))
        for value in values
        if isinstance(value, dict) and value.get("key") and value.get("enabled", True)
    }
