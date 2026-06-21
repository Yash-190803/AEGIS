import ipaddress
import re
from datetime import datetime


class LogVectorizer:
    SQL_PATTERNS = [
        re.compile(r"(?i)UNION\s+SELECT"),
        re.compile(r"(?i)DROP\s+TABLE"),
        re.compile(r"1\s*=\s*1"),
        re.compile(r"(?i)--\s*$"),
        re.compile(r"(?i)'\s*OR\s*'"),
    ]
    SHELL_PATTERNS = [
        re.compile(r"/bin/sh"),
        re.compile(r"/bin/bash"),
        re.compile(r"cmd\.exe"),
        re.compile(r"(?i)powershell"),
        re.compile(r"wget\s+http"),
        re.compile(r"curl\s+http"),
    ]
    FAILED_AUTH = re.compile(r"(?i)(Failed password|authentication failure|invalid user|login failed)")
    SUCCESS_AUTH = re.compile(r"(?i)(Accepted password|session opened|login successful)")
    IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    PORT_PATTERN = re.compile(r"\b(?:port|dpt|spt)[=:\s]+(\d{1,5})\b", re.IGNORECASE)
    SYSLOG_TIME = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+(\d{2}):(\d{2}):(\d{2})")
    UNUSUAL_PORTS = {22, 80, 443, 3306, 5432, 3389, 8080, 8443, 25, 587, 993}
    FEATURE_ORDER = [
        "failed_auth_flag",
        "success_auth_flag",
        "sql_injection_flag",
        "shell_command_flag",
        "has_external_ip",
        "unusual_port_flag",
        "unusual_hour_flag",
        "line_length_normalized",
        "known_bad_ip_flag",
    ]
    KNOWN_BAD_IPS = {"203.0.113.45", "198.51.100.77", "192.0.2.24", "203.0.113.99"}

    def extract_features(self, log_lines: list, log_type: str) -> list:
        """Returns one feature dict per log line."""
        if not isinstance(log_lines, list) or any(not isinstance(line, str) for line in log_lines):
            raise ValueError("log_lines must be a list of strings")
        if not isinstance(log_type, str) or not log_type:
            raise ValueError("log_type must be a non-empty string")
        return [self._features_for_line(line) for line in log_lines]

    def extract_batch_features(self, log_lines: list, log_type: str) -> dict:
        """Returns aggregate features for the entire batch."""
        line_features = self.extract_features(log_lines, log_type)
        total_lines = len(log_lines)
        failed_auth_count = sum(item["failed_auth_flag"] for item in line_features)
        success_auth_count = sum(item["success_auth_flag"] for item in line_features)
        sql_pattern_count = sum(item["sql_injection_flag"] for item in line_features)
        shell_pattern_count = sum(item["shell_command_flag"] for item in line_features)
        unique_source_ips = len({ip for line in log_lines for ip in self.IP_PATTERN.findall(line)})
        unusual_hour_fraction = (
            sum(item["unusual_hour_flag"] for item in line_features) / total_lines if total_lines else 0
        )
        return {
            "total_lines": total_lines,
            "failed_auth_count": failed_auth_count,
            "success_auth_count": success_auth_count,
            "ratio_failed_to_total": failed_auth_count / total_lines if total_lines else 0,
            "unique_source_ips": unique_source_ips,
            "sql_pattern_count": sql_pattern_count,
            "shell_pattern_count": shell_pattern_count,
            "requests_per_minute_estimate": self._requests_per_minute(log_lines),
            "unusual_hour_fraction": unusual_hour_fraction,
        }

    def to_numeric_vectors(self, log_lines: list, log_type: str) -> list:
        """Converts line feature dictionaries into numeric vectors for scikit-learn."""
        return [[features[key] for key in self.FEATURE_ORDER] for features in self.extract_features(log_lines, log_type)]

    def batch_to_numeric_vector(self, log_lines: list, log_type: str) -> list:
        """Converts aggregate batch features into a stable numeric vector."""
        features = self.extract_batch_features(log_lines, log_type)
        return [
            features["total_lines"],
            features["failed_auth_count"],
            features["success_auth_count"],
            features["ratio_failed_to_total"],
            features["unique_source_ips"],
            features["sql_pattern_count"],
            features["shell_pattern_count"],
            features["requests_per_minute_estimate"],
            features["unusual_hour_fraction"],
        ]

    def _features_for_line(self, line: str) -> dict:
        ips = self.IP_PATTERN.findall(line)
        ports = [int(match) for match in self.PORT_PATTERN.findall(line) if int(match) <= 65535]
        return {
            "failed_auth_flag": int(bool(self.FAILED_AUTH.search(line))),
            "success_auth_flag": int(bool(self.SUCCESS_AUTH.search(line))),
            "sql_injection_flag": int(any(pattern.search(line) for pattern in self.SQL_PATTERNS)),
            "shell_command_flag": int(any(pattern.search(line) for pattern in self.SHELL_PATTERNS)),
            "has_external_ip": int(any(self._is_external_ip(ip) for ip in ips)),
            "unusual_port_flag": int(any(port not in self.UNUSUAL_PORTS for port in ports)),
            "unusual_hour_flag": int(self._is_unusual_hour(line)),
            "line_length_normalized": min(len(line) / 500.0, 1.0),
            "known_bad_ip_flag": int(any(ip in self.KNOWN_BAD_IPS for ip in ips)),
        }

    def _requests_per_minute(self, log_lines: list) -> float:
        timestamps = [self._seconds_from_syslog(line) for line in log_lines]
        timestamps = [item for item in timestamps if item is not None]
        if len(timestamps) < 2:
            return float(len(log_lines))
        duration_seconds = max(timestamps) - min(timestamps)
        if duration_seconds <= 0:
            return float(len(log_lines))
        return round(len(log_lines) / (duration_seconds / 60.0), 3)

    def _is_external_ip(self, ip: str) -> bool:
        try:
            parsed = ipaddress.ip_address(ip)
            return not parsed.is_private and not parsed.is_loopback
        except ValueError:
            return False

    def _is_unusual_hour(self, line: str) -> bool:
        hour = self._hour_from_line(line)
        return hour is not None and (hour < 6 or hour > 20)

    def _hour_from_line(self, line: str):
        syslog = self.SYSLOG_TIME.search(line)
        if syslog:
            return int(syslog.group(1))
        iso_match = re.search(r"\d{4}-\d{2}-\d{2}T(\d{2}):\d{2}:\d{2}", line)
        if iso_match:
            return int(iso_match.group(1))
        return None

    def _seconds_from_syslog(self, line: str):
        match = self.SYSLOG_TIME.search(line)
        if not match:
            return None
        parsed = datetime.strptime(":".join(match.groups()), "%H:%M:%S")
        return parsed.hour * 3600 + parsed.minute * 60 + parsed.second