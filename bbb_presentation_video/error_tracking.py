# SPDX-FileCopyrightText: 2026 BigBlueButton Inc. and by respective authors
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Optional error reporting to a Sentry-compatible server: call init() at start.

BBB_SENTRY_* settings: environment, else bigbluebutton.env, else recording settings."""

import inspect
import logging
import os
import re
from enum import Enum
from typing import Any, Dict, Mapping, Match, Optional, Sequence
from urllib.parse import urlsplit

COMPONENT = "bbb-presentation-video"
ENV_FILE = "/etc/bigbluebutton/bigbluebutton.env"
# Shipped, then overridden, like the recording scripts read them.
RECORDING_FILES = (
    "/usr/local/bigbluebutton/core/scripts/bigbluebutton.yml",
    "/etc/bigbluebutton/recording/recording.yml",
)
RELEASE_FILE = "/etc/bigbluebutton/bigbluebutton-release"
SHUTDOWN_TIMEOUT = 2.0

log = logging.getLogger(__name__)


class Mode(Enum):
    MASK = "mask"
    OFF = "off"

    @classmethod
    def parse(cls, value: Optional[str]) -> "Mode":
        if value is not None and value.strip().lower() == "off":
            return cls.OFF
        return cls.MASK


class Anonymiser:
    """Filters secrets and masks personal data, by the name of each pair."""

    FILTERED = "[Filtered]"

    SECRET_NAME = re.compile(
        r"pass|secret|token|checksum|salt|api[_-]?key|authori[sz]ation|cookie|pw$",
        re.IGNORECASE | re.ASCII,
    )
    PERSONAL_NAME = re.compile(
        r"name$|e-?mail|address$|^ip$|^message$|^text$|^msg$",
        re.IGNORECASE | re.ASCII,
    )
    # The bounded name keeps the scan linear. A value stops at '?' and '=' so a URL
    # value (url=https://h/p?token=x) leaves its own query pairs to be matched.
    QUERY_PAIR = re.compile(r"([\w.\-\[\]]{1,256})=([^&\s\"'<>,;?=]*)", re.ASCII)
    JSON_PAIR = re.compile(r'"([\w.\-]{1,256})"(\s*:\s*)"((?:[^"\\]|\\.)*)"', re.ASCII)
    IPV4 = re.compile(
        r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])",
        re.ASCII,
    )

    def __init__(self, mode: Mode) -> None:
        self.mode = mode

    def _is_secret(self, name: str) -> bool:
        return self.SECRET_NAME.search(name) is not None

    def _is_personal(self, name: str) -> bool:
        return self.mode != Mode.OFF and self.PERSONAL_NAME.search(name) is not None

    def _is_filtered(self, name: str) -> bool:
        return self._is_secret(name) or self._is_personal(name)

    def anonymise_text(self, text: Optional[str]) -> Optional[str]:
        if not text:
            return text

        def query_pair(m: Match[str]) -> str:
            if not self._is_filtered(m.group(1)):
                return m.group(0)
            return f"{m.group(1)}={self.FILTERED}"

        def json_pair(m: Match[str]) -> str:
            if not self._is_filtered(m.group(1)):
                return m.group(0)
            return f'"{m.group(1)}"{m.group(2)}"{self.FILTERED}"'

        result = self.QUERY_PAIR.sub(query_pair, text)
        result = self.JSON_PAIR.sub(json_pair, result)
        if self.mode != Mode.OFF:
            result = self.IPV4.sub(self.FILTERED, result)
        return result

    def anonymise_value(self, name: Optional[str], value: Any) -> Any:
        if name is not None and value is not None and self._is_filtered(name):
            return self.FILTERED
        if isinstance(value, str):
            return self.anonymise_text(value)
        if isinstance(value, Mapping):
            return {str(k): self.anonymise_value(str(k), v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.anonymise_value(None, item) for item in value]
        return value

    def anonymise_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        if isinstance(event.get("message"), str):
            event["message"] = self.anonymise_text(event["message"])
        logentry = event.get("logentry")
        if isinstance(logentry, dict):
            for key in ("message", "formatted"):
                if isinstance(logentry.get(key), str):
                    logentry[key] = self.anonymise_text(logentry[key])
            # The raw arguments of a log call are often names; the text is enough.
            logentry.pop("params", None)
        for exception in (event.get("exception") or {}).get("values") or []:
            if isinstance(exception.get("value"), str):
                exception["value"] = self.anonymise_text(exception["value"])
        # Breadcrumbs were anonymised when they were recorded.
        if isinstance(event.get("extra"), dict):
            event["extra"] = self.anonymise_value(None, event["extra"])
        request = event.get("request")
        if isinstance(request, dict):
            for key in ("url", "query_string"):
                if isinstance(request.get(key), str):
                    request[key] = self.anonymise_text(request[key])
            for key in ("headers", "cookies", "data", "env"):
                if key in request:
                    request[key] = self.anonymise_value(None, request[key])
        return event

    def anonymise_breadcrumb(self, breadcrumb: Dict[str, Any]) -> Dict[str, Any]:
        if isinstance(breadcrumb.get("message"), str):
            breadcrumb["message"] = self.anonymise_text(breadcrumb["message"])
        if isinstance(breadcrumb.get("data"), dict):
            breadcrumb["data"] = self.anonymise_value(None, breadcrumb["data"])
        return breadcrumb

    def anonymise_log(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Drops the raw arguments of the log call; the body is enough."""
        if isinstance(entry.get("body"), str):
            entry["body"] = self.anonymise_text(entry["body"])
        attributes = entry.get("attributes")
        if isinstance(attributes, dict):
            entry["attributes"] = {
                name: self.anonymise_text(value) if isinstance(value, str) else value
                for name, value in attributes.items()
                if not str(name).startswith("sentry.message.parameter")
            }
        return entry


def init(
    component: str = COMPONENT,
    env: Optional[Mapping[str, str]] = None,
    settings: Optional[Mapping[str, Any]] = None,
) -> bool:
    """Returns whether reporting started; never raises."""
    if env is None:
        env = environment()
    if settings is None:
        settings = recording_settings()
    try:
        dsn = dsn_for(component, env, settings)
        if dsn is None:
            return False

        import sentry_sdk
        from sentry_sdk.consts import DEFAULT_OPTIONS
        from sentry_sdk.integrations.atexit import AtexitIntegration
        from sentry_sdk.integrations.dedupe import DedupeIntegration
        from sentry_sdk.integrations.excepthook import ExcepthookIntegration
        from sentry_sdk.integrations.logging import LoggingIntegration
        from sentry_sdk.integrations.threading import ThreadingIntegration

        issues = level(setting(component, "LEVEL", env, settings), logging.ERROR)
        breadcrumbs = level(
            setting(component, "BREADCRUMB_LEVEL", env, settings), logging.INFO
        )
        anonymise = Mode.parse(setting(component, "ANONYMISE", env, settings))
        anonymiser = Anonymiser(anonymise)

        def before_send(event: Dict[str, Any], hint: Any) -> Dict[str, Any]:
            event.setdefault("tags", {})["component"] = component
            return anonymiser.anonymise_event(event)

        def before_breadcrumb(crumb: Dict[str, Any], hint: Any) -> Dict[str, Any]:
            return anonymiser.anonymise_breadcrumb(crumb)

        def before_send_log(entry: Dict[str, Any], hint: Any) -> Dict[str, Any]:
            entry = anonymiser.anonymise_log(entry)
            entry.setdefault("attributes", {})["component"] = component
            return entry

        logs = sends_logs(DEFAULT_OPTIONS, LoggingIntegration)
        if logs:
            # Records from LEVEL up are log entries too, lower ones never are.
            logging_integration = LoggingIntegration(
                level=breadcrumbs, event_level=issues, sentry_logs_level=issues
            )
        else:
            logging_integration = LoggingIntegration(
                level=breadcrumbs, event_level=issues
            )

        options: Dict[str, Any] = {
            "dsn": dsn,
            "environment": setting(component, "ENVIRONMENT", env, settings)
            or "production",
            "release": f"{component}@{bbb_release()}",
            "sample_rate": sample_rate(
                setting(component, "SAMPLE_RATE", env, settings)
            ),
            "before_send": before_send,
            "before_breadcrumb": before_breadcrumb,
            # Errors and log entries only: no tracing, profiling or sessions.
            "traces_sample_rate": None,
            "auto_session_tracking": False,
            "send_default_pii": False,
            "shutdown_timeout": SHUTDOWN_TIMEOUT,
            "default_integrations": False,
            "auto_enabling_integrations": False,
            "integrations": [
                logging_integration,
                ExcepthookIntegration(),
                ThreadingIntegration(),
                DedupeIntegration(),
                # Sends what is pending at exit, without printing about it.
                AtexitIntegration(callback=lambda pending, timeout: None),
            ],
        }
        if logs:
            options["enable_logs"] = True
            options["before_send_log"] = before_send_log
        # Local variables of the stack frames may hold anything.
        if "include_local_variables" in DEFAULT_OPTIONS:
            options["include_local_variables"] = False
        else:
            options["with_locals"] = False
        name = server_name(env.get("BBB_URL"))
        if name is not None:
            options["server_name"] = name
        # sentry_sdk.init is a class in old versions (Ubuntu 22.04 has 1.4.3).
        start: Any = sentry_sdk.init
        start(**options)

        # The command does not configure logging, which only shows warnings;
        # let lower records of this package reach the breadcrumbs.
        package_log = logging.getLogger(__package__)
        if package_log.getEffectiveLevel() > breadcrumbs:
            package_log.setLevel(breadcrumbs)

        message = (
            f"Error reporting to {urlsplit(dsn).hostname} enabled for {component}"
            f" (issues from {logging.getLevelName(issues)},"
            f" breadcrumbs from {logging.getLevelName(breadcrumbs)},"
            f" personal data: {anonymise.value})"
        )
        print(message)
        log.info(message)
        return True
    except Exception as e:
        print(f"Error reporting not started for {component}: {e!r}")
        return False


def sends_logs(default_options: Mapping[str, Any], logging_integration: Any) -> bool:
    """Whether the installed SDK sends log entries: recent 2.x does, 1.x does not."""
    try:
        parameters = inspect.signature(logging_integration.__init__).parameters
    except (TypeError, ValueError):
        return False
    return (
        "enable_logs" in default_options
        and "before_send_log" in default_options
        and "sentry_logs_level" in parameters
    )


def setting(
    component: str,
    name: str,
    env: Mapping[str, str],
    settings: Optional[Mapping[str, Any]] = None,
) -> Optional[str]:
    suffix = re.sub(r"[^A-Z0-9]", "_", component.upper())
    value = _trimmed(env.get(f"BBB_SENTRY_{name}_{suffix}"))
    if value is None:
        value = _trimmed(env.get(f"BBB_SENTRY_{name}"))
    if value is None and settings is not None:
        key = re.sub(r"_([a-z])", lambda m: m.group(1).upper(), name.lower())
        configured = settings.get(key)
        # YAML reads an unquoted off as false.
        if configured is False:
            configured = "off"
        if configured is not None:
            value = _trimmed(str(configured))
    return value


def dsn_for(
    component: str,
    env: Mapping[str, str],
    settings: Optional[Mapping[str, Any]] = None,
) -> Optional[str]:
    dsn = setting(component, "DSN", env, settings)
    if dsn is None or dsn.lower() == "off":
        return None
    return dsn


def level(value: Optional[str], fallback: int) -> int:
    name = (_trimmed(value) or "").lower()
    return {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warn": logging.WARNING,
        "warning": logging.WARNING,
        "error": logging.ERROR,
        "fatal": logging.CRITICAL,
    }.get(name, fallback)


def sample_rate(value: Optional[str]) -> float:
    try:
        rate = float(value or "")
    except ValueError:
        return 1.0
    return rate if 0.0 <= rate <= 1.0 else 1.0


def server_name(bbb_url: Optional[str]) -> Optional[str]:
    url = _trimmed(bbb_url)
    if url is None:
        return None
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def bbb_release(path: str = RELEASE_FILE) -> str:
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                if line.startswith("BIGBLUEBUTTON_RELEASE="):
                    release = line[len("BIGBLUEBUTTON_RELEASE=") :].strip()
                    if release:
                        return release
    except OSError:
        # A development checkout has no release file.
        pass
    return "unknown"


ENV_LINE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=(.*)")


def read_env_file(path: str = ENV_FILE) -> Dict[str, str]:
    """The BBB_* variables of a file of KEY=value lines, which is never executed."""
    values: Dict[str, str] = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                m = ENV_LINE.fullmatch(line.rstrip("\r\n"))
                if m is not None and m.group(1).startswith("BBB_"):
                    values[m.group(1)] = m.group(2)
    except (OSError, ValueError):
        pass
    return values


def environment(
    env: Optional[Mapping[str, str]] = None, path: str = ENV_FILE
) -> Dict[str, str]:
    """The environment, plus the env file's variables it lacks (in a manual run)."""
    result = dict(os.environ if env is None else env)
    for key, value in read_env_file(path).items():
        result.setdefault(key, value)
    return result


def recording_settings(paths: Sequence[str] = RECORDING_FILES) -> Dict[str, Any]:
    """The ``sentry`` map of the recording settings; a later file replaces it whole."""
    try:
        import yaml
    except ImportError:
        return {}
    result: Dict[str, Any] = {}
    for path in paths:
        try:
            with open(path, encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
        except (OSError, ValueError, yaml.YAMLError):
            continue
        if isinstance(loaded, dict) and "sentry" in loaded:
            sentry = loaded["sentry"]
            result = dict(sentry) if isinstance(sentry, dict) else {}
    return result


def _trimmed(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    value = value.strip()
    return value or None
