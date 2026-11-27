"""Service configuration and fixed component command lines; no effects at import."""
from dataclasses import dataclass
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = ROOT / "config/service.json"
RUNTIME = Path("/run/portwatchman-service")


class ServiceError(RuntimeError):
    pass


def unique(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ServiceError(f"Duplicate JSON key: {key}")
        out[key] = value
    return out


def parse(raw):
    def reject(value):
        raise ServiceError(f"Non-finite JSON number: {value}")
    try:
        return json.loads(raw, object_pairs_hook=unique, parse_constant=reject)
    except (ValueError, UnicodeError) as error:
        raise ServiceError(f"Invalid JSON: {error}") from error


@dataclass(frozen=True)
class Config:
    policy: Path
    enforcement: Path
    responses: Path
    lsm: Path | None = None
    apply_responses: bool = False
    startup_timeout: float = 90
    shutdown_timeout: float = 30
    command_timeout: float = 60
    local_lsm: Path | None = None

    @property
    def lsm_enabled(self):
        return self.lsm is not None or self.local_lsm is not None

    @property
    def lsm_scope(self):
        return "vm-files" if self.local_lsm else "usb-files" if self.lsm else "disabled"


def load_config(path):
    raw = Path(path).read_bytes()
    if len(raw) > 65536:
        raise ServiceError("Service configuration exceeds 64 KiB")
    doc = parse(raw)
    fields = {"schema_version", "policy", "enforcement", "responses", "lsm",
              "apply_responses", "startup_timeout", "shutdown_timeout", "command_timeout", "local_lsm"}
    if not isinstance(doc, dict) or set(doc) - fields:
        raise ServiceError("Service configuration must be an object with known fields")
    if type(doc.get("schema_version")) is not int or doc["schema_version"] != 1:
        raise ServiceError("Service schema_version must be integer 1")
    def filename(name, default):
        value = doc.get(name, default)
        if not isinstance(value, str) or not value or any(ord(c) < 32 for c in value):
            raise ServiceError(f"{name} must be a nonempty path without control characters")
        p = Path(value)
        return p.resolve() if p.is_absolute() else (ROOT / p).resolve()
    apply = doc.get("apply_responses", False)
    if type(apply) is not bool:
        raise ServiceError("apply_responses must be true or false")
    if doc.get("lsm") is not None and doc.get("local_lsm") is not None:
        raise ServiceError("Choose local_lsm for VM files or legacy lsm for USB files, not both")
    times = {}
    for name, default, maximum in (("startup_timeout", 90, 120),
                                   ("shutdown_timeout", 30, 60), ("command_timeout", 60, 60)):
        value = doc.get(name, default)
        if type(value) not in (int, float) or not 1 <= value <= maximum:
            raise ServiceError(f"{name} must be between 1 and {maximum} seconds")
        times[name] = float(value)
    return Config(filename("policy", "config/allowlist.json"),
                  filename("enforcement", "config/enforcement.json"),
                  filename("responses", "config/responses.json"),
                  filename("lsm", None) if doc.get("lsm") is not None else None,
                  apply, local_lsm=filename("local_lsm", None) if doc.get("local_lsm") is not None else None,
                  **times)


def commands(config):
    py = [sys.executable, "-u"]
    enforce = [*py, str(ROOT / "src/enforcement/usb_authorization.py"),
               "--config", str(config.enforcement), "--policy", str(config.policy), "enforce"]
    if config.lsm:
        enforce += ["--lsm-config", str(config.lsm)]
    respond = [*py, str(ROOT / "src/responses/responses.py"),
               "--config", str(config.responses), "watch"]
    if config.apply_responses:
        respond += ["--apply"]
    return {"monitor": [*py, str(ROOT / "src/monitor/usb_monitor.py")],
            "policy": [*py, str(ROOT / "src/policy/device_policy.py"),
                       "--policy", str(config.policy), "watch"],
            "enforcement": enforce, "responses": respond}


def components(config):
    # Existing components remain the authority for their own configuration formats.
    for folder in ("policy", "enforcement", "responses"):
        directory = str(ROOT / "src" / folder)
        if directory not in sys.path:
            sys.path.insert(0, directory)
    from device_policy import load_policy
    from usb_authorization import load_config as load_enforcement
    from responses import load_config as load_responses
    policy = load_policy(config.policy)
    enforcement = load_enforcement(config.enforcement)
    response = load_responses(config.responses)
    if config.local_lsm:
        if config.lsm:
            raise ServiceError("Choose local_lsm or legacy lsm, not both")
        from lsm_local import load_local_config, check_response_overlap
        check_response_overlap(load_local_config(config.local_lsm), response)
    bridge = None
    if config.lsm:
        from lsm_bridge import load_bridge_config
        bridge = load_bridge_config(config.lsm)
        missing = set(bridge.rules) - {rule["name"] for rule in policy.document["allowlist"]}
        if missing:
            raise ServiceError(f"LSM rules missing from allowlist: {sorted(missing)}")
    return policy, enforcement, response, bridge
