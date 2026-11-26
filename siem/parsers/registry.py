"""Parser registry and automatic log-format detection."""

from __future__ import annotations

from pathlib import Path

from .apache_parser import ApacheAccessParser, ApacheErrorParser
from .auth_parser import AuthParser
from .base_parser import BaseParser, ParseResult
from .evtx_parser import EvtxParser
from .generic_parser import GenericParser
from .nginx_parser import NginxAccessParser, NginxErrorParser
from .ssh_parser import SSHParser
from .windows_csv_parser import WindowsCsvParser
from .windows_json_parser import WindowsJsonParser
from .windows_xml_parser import WindowsXmlParser

FORMAT_ALIASES = {
    "auth": "auth",
    "linux_auth": "auth",
    "auth.log": "auth",
    "secure": "auth",
    "ssh": "ssh",
    "apache": "apache_access",
    "apache_access": "apache_access",
    "apache_error": "apache_error",
    "nginx": "nginx_access",
    "nginx_access": "nginx_access",
    "nginx_error": "nginx_error",
    "evtx": "evtx",
    "windows_evtx": "evtx",
    "windows_xml": "windows_xml",
    "xml": "windows_xml",
    "windows_csv": "windows_csv",
    "csv": "windows_csv",
    "windows_json": "windows_json",
    "json": "windows_json",
    "jsonl": "windows_json",
    "ndjson": "windows_json",
    "generic": "generic",
    "auto": None,
}


class ParserRegistry:
    def __init__(self) -> None:
        self._parsers: list[BaseParser] = [
            EvtxParser(),
            WindowsXmlParser(),
            WindowsCsvParser(),
            WindowsJsonParser(),
            SSHParser(),
            AuthParser(),
            NginxErrorParser(),
            NginxAccessParser(),
            ApacheErrorParser(),
            ApacheAccessParser(),
            GenericParser(),
        ]
        self._by_name = {parser.name: parser for parser in self._parsers}
        # Alias names map onto concrete parser names.
        for alias, target in FORMAT_ALIASES.items():
            if target and target in self._by_name:
                self._by_name[alias] = self._by_name[target]

    @property
    def parsers(self) -> list[BaseParser]:
        return list(self._parsers)

    @property
    def available_formats(self) -> list[str]:
        return sorted({parser.name for parser in self._parsers} | {"auto"})

    def get_parser(self, name: str | None) -> BaseParser:
        if not name:
            raise ValueError("Parser name required")
        key = name.strip().lower()
        if key not in self._by_name:
            raise ValueError(
                f"Unknown format '{name}'. Available: {', '.join(self.available_formats)}"
            )
        return self._by_name[key]

    @staticmethod
    def _read_sample(path: Path, size: int = 8192) -> str:
        try:
            with path.open("rb") as handle:
                return handle.read(size).decode("utf-8", errors="replace")
        except OSError:
            return ""

    def detect(self, path: str | Path, sample: str | None = None) -> BaseParser:
        path = Path(path)
        filename = path.name.lower()
        suffix = path.suffix.lower()

        if suffix == ".evtx":
            return self._by_name["evtx"]

        if sample is None:
            sample = self._read_sample(path)

        windows_xml = self._by_name["windows_xml"]
        if windows_xml.can_parse(sample, filename):
            return windows_xml

        windows_csv = self._by_name["windows_csv"]
        if suffix == ".csv" or windows_csv.can_parse(sample, filename):
            return windows_csv

        windows_json = self._by_name["windows_json"]
        if windows_json.can_parse(sample, filename):
            return windows_json

        for name in (
            "ssh",
            "auth",
            "nginx_error",
            "nginx_access",
            "apache_error",
            "apache_access",
        ):
            parser = self._by_name[name]
            if parser.can_parse(sample, filename):
                return parser

        return self._by_name["generic"]

    def detect_format_name(self, path: str | Path, sample: str | None = None) -> str:
        return self.detect(path, sample).name

    def parse_file(self, path: str | Path, fmt: str | None = None) -> ParseResult:
        path = Path(path)
        if fmt and fmt.strip().lower() not in {"auto", ""}:
            parser = self.get_parser(fmt)
        else:
            parser = self.detect(path)
        result = parser.parse_file(path)
        if not result.parser_name:
            result.parser_name = parser.name
        return result


DEFAULT_REGISTRY = ParserRegistry()


def parse_file(path: str | Path, fmt: str | None = None) -> ParseResult:
    """Convenience wrapper using a module-level registry."""
    return DEFAULT_REGISTRY.parse_file(path, fmt)
