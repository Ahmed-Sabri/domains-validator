#!/usr/bin/env python3
"""
Robust domain validator with a tidy, styled Excel report.

- Reads domains from XLSX/XLS/CSV (header optional).
- DNS A/NS validation with retries, timeouts, parallel workers.
- WHOIS fallback (python-whois or system whois CLI).
- Filters registrar placeholder/parking nameservers (e.g. *.hydrapiglephant.com)
  so only EFFECTIVE nameservers are reported.
- Output workbook: Summary (clean) + DNS Details + WHOIS Details, styled.
"""

import argparse
import logging
import re
import shutil
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import dns.exception
import dns.resolver

try:
    import whois
    WHOIS_LIBRARY_AVAILABLE = True
except Exception:
    WHOIS_LIBRARY_AVAILABLE = False


LOG = logging.getLogger("domains-validator")

DEFAULT_EXPECTED_IP = "37.27.108.238"
DEFAULT_EXPECTED_NS_SUBSTRING = "hosterz.net"

# Registrar placeholder / parking nameserver patterns. These are NOT real
# delegations and are filtered out of the reported nameservers.
DEFAULT_IGNORE_NS_PATTERNS = [
    "hydrapiglephant.com",
    "sedoparking.com",
    "parkingcrew.net",
    "parklogic.com",
    "bodis.com",
    "above.com",
    "skenzo.com",
]

SUMMARY_COLUMNS = [
    "DOMAIN", "A RECORD", "NAME SERVERS", "NS SOURCE",
    "STATUS", "REGISTRAR", "EXPIRES", "NOTES",
]
DNS_COLUMNS = ["DOMAIN", "A RECORD", "NS RECORD", "DNS ERROR", "HTTP RESULT"]
WHOIS_COLUMNS = [
    "DOMAIN", "REGISTRAR", "STATUS", "CREATED", "EXPIRES",
    "EFFECTIVE NAME SERVERS", "RAW WHOIS NAME SERVERS", "SOURCE", "ERROR",
]

HEADER_CANDIDATES = {
    "domain", "domains", "domain name", "domain_name", "domainname",
    "hostname", "host", "url", "website", "website address", "site",
}

_thread_local = threading.local()
_URL_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate domains from Excel/CSV with DNS + WHOIS fallback "
                    "and produce a tidy styled report.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--input", "-i", required=True, type=Path,
                        help="Input file: .xlsx, .xlsm, .xls, or .csv")
    parser.add_argument("--output", "-o", type=Path,
                        help="Output file. Default: <input>_report.xlsx")
    parser.add_argument("--domain-column", default="0",
                        help="Domain column index (0-based) or name if --header used")
    parser.add_argument("--header", action="store_true",
                        help="First row is a header (common headers auto-skipped anyway)")
    parser.add_argument("--delimiter", default=",", help="CSV delimiter")
    parser.add_argument("--encoding", default="utf-8-sig", help="CSV encoding")
    parser.add_argument("--expected-ip", default=DEFAULT_EXPECTED_IP,
                        help="Expected A record IP(s), comma-separated")
    parser.add_argument("--expected-ns-substring", default=DEFAULT_EXPECTED_NS_SUBSTRING,
                        help="Expected NS substring(s), comma-separated")
    parser.add_argument("--ignore-ns-substring",
                        default=",".join(DEFAULT_IGNORE_NS_PATTERNS),
                        help="Nameserver substrings to treat as registrar placeholders")
    parser.add_argument("--nameservers", help="Optional comma-separated DNS servers")
    parser.add_argument("--timeout", type=float, default=5.0, help="DNS timeout (s)")
    parser.add_argument("--retries", type=int, default=2, help="DNS retries")
    parser.add_argument("--workers", type=int, default=8, help="Parallel workers")
    parser.add_argument("--whois-timeout", type=float, default=15.0, help="WHOIS CLI timeout (s)")
    parser.add_argument("--no-whois", dest="whois_fallback", action="store_false",
                        help="Disable WHOIS fallback")
    parser.add_argument("--always-whois", action="store_true",
                        help="Query WHOIS for every domain")
    parser.add_argument("--http-check", action="store_true",
                        help="Also check HTTP/HTTPS reachability")
    parser.add_argument("--http-timeout", type=float, default=8.0, help="HTTP timeout (s)")
    parser.add_argument("--debug", action="store_true", help="Debug logging")

    args = parser.parse_args()

    args.nameservers = (
        [x.strip() for x in args.nameservers.split(",") if x.strip()]
        if args.nameservers else None
    )
    args.ignore_patterns = [
        p.strip().lower()
        for p in args.ignore_ns_substring.split(",") if p.strip()
    ]
    args.expected_ips = {
        x.strip() for x in args.expected_ip.split(",") if x.strip()
    }
    args.expected_ns_parts = [
        x.strip().lower()
        for x in args.expected_ns_substring.split(",") if x.strip()
    ]
    if args.always_whois:
        args.whois_fallback = True

    return args


# --------------------------------------------------------------------------
# DNS
# --------------------------------------------------------------------------
def get_resolver(timeout: float,
                 nameservers: Optional[List[str]] = None) -> dns.resolver.Resolver:
    resolver = getattr(_thread_local, "resolver", None)
    if resolver is None:
        resolver = dns.resolver.Resolver()
        _thread_local.resolver = resolver
    resolver.timeout = timeout
    resolver.lifetime = timeout
    if nameservers:
        resolver.nameservers = nameservers
    return resolver


def resolve_record(domain: str, rdtype: str,
                   settings: argparse.Namespace) -> Tuple[Optional[List[str]], Optional[str]]:
    """Resolve one record type. Returns (records, short_error_code)."""
    last_error = None
    for attempt in range(settings.retries + 1):
        try:
            answers = get_resolver(settings.timeout, settings.nameservers).resolve(domain, rdtype)
            return [str(r).rstrip(".").lower() for r in answers], None
        except dns.resolver.NXDOMAIN:
            return None, "NXDOMAIN"
        except dns.resolver.NoAnswer:
            return [], None
        except dns.resolver.NoNameservers as exc:
            last_error = "SERVFAIL" if "SERVFAIL" in str(exc) else "NO_NAMESERVERS"
        except dns.exception.Timeout:
            last_error = "TIMEOUT"
        except dns.exception.DNSException:
            last_error = "DNS_ERROR"
        if attempt < settings.retries:
            time.sleep(0.4 * (attempt + 1))
    return None, last_error


def normalize_domain(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip().lower()
    if text in {"", "nan", "none"}:
        return ""
    text = _URL_RE.sub("", text)
    text = text.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    text = text.split(":", 1)[0].strip(".")
    return text


# --------------------------------------------------------------------------
# Input reading
# --------------------------------------------------------------------------
def read_table(path: Path, has_header: bool, delimiter: str, encoding: str) -> pd.DataFrame:
    ext = path.suffix.lower()
    header = 0 if has_header else None
    try:
        if ext in {".xlsx", ".xlsm"}:
            df = pd.read_excel(path, header=header, dtype=str, engine="openpyxl")
        elif ext == ".xls":
            df = pd.read_excel(path, header=header, dtype=str, engine="xlrd")
        elif ext == ".csv":
            df = pd.read_csv(path, header=header, dtype=str, keep_default_na=False,
                             delimiter=delimiter, encoding=encoding)
        else:
            raise ValueError(f"Unsupported extension '{ext}'. Use .xlsx, .xlsm, .xls, .csv.")
    except Exception as exc:
        raise SystemExit(f"Failed to read '{path}': {exc}")
    return df.fillna("")


def select_domain_series(df: pd.DataFrame, column: str) -> pd.Series:
    if df.empty:
        return pd.Series(dtype=str)
    if column.isdigit():
        idx = int(column)
        if idx < 0 or idx >= len(df.columns):
            raise ValueError(f"Column index {idx} out of range: {list(df.columns)}")
        return df.iloc[:, idx]
    if column in df.columns:
        return df[column]
    for col in df.columns:
        if str(col).strip().lower() == column.strip().lower():
            return df[col]
    raise ValueError(f"Column '{column}' not found. Available: {list(df.columns)}")


def maybe_drop_header_row(df: pd.DataFrame, column: str, has_header: bool) -> pd.DataFrame:
    if has_header or df.empty:
        return df
    try:
        series = select_domain_series(df, column)
    except ValueError:
        return df
    if series.empty:
        return df
    first = str(series.iloc[0]).strip().lower()
    if first in HEADER_CANDIDATES:
        LOG.info("Skipping header-like first row '%s'.", first)
        return df.iloc[1:].reset_index(drop=True)
    return df


# --------------------------------------------------------------------------
# Value cleaning helpers (tidy report)
# --------------------------------------------------------------------------
def _to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "ignore")
    return str(value)


def _first_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return _to_text(value[0]) if value else ""
    return _to_text(value)


def _list_values(value: Any) -> List[str]:
    """Normalized, de-duplicated, sorted list from scalar/list WHOIS values."""
    if value is None:
        return []
    items = list(value) if isinstance(value, (list, tuple, set)) else [value]
    cleaned = {
        _to_text(i).strip().lower().rstrip(".")
        for i in items if _to_text(i).strip()
    }
    return sorted(cleaned)


def clean_epp_status(raw: str) -> str:
    """'clienttransferprohibited https://icann.org/epp#..., clienttransferprohibited ...'
    -> 'clienttransferprohibited' (de-duplicated, URLs stripped)."""
    if not raw:
        return ""
    codes: List[str] = []
    for part in raw.split(","):
        tokens = part.strip().split()
        if not tokens:
            continue
        code = tokens[0].strip().lower()
        if code.startswith("http"):
            continue
        if code and code not in codes:
            codes.append(code)
    return ", ".join(codes)


def clean_date(value: str) -> str:
    """'2027-04-20 08:02:52+00:00' -> '2027-04-20'."""
    if not value:
        return ""
    try:
        dt = pd.to_datetime(value, utc=True, errors="coerce")
        if pd.isna(dt):
            return value
        return dt.strftime("%Y-%m-%d")
    except Exception:
        return value


# --------------------------------------------------------------------------
# WHOIS
# --------------------------------------------------------------------------
def parse_whois_text(text: str) -> Dict[str, Any]:
    def search(pattern: str) -> str:
        m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        return m.group(1).strip() if m else ""

    return {
        "domain_name": search(r"^Domain Name:\s*(\S+)"),
        "registrar": search(r"^Registrar:\s*(.+)"),
        "status": ", ".join(
            s.strip().lower() for s in
            re.findall(r"^Domain Status:\s*(.+)$", text, re.IGNORECASE | re.MULTILINE)
            if s.strip()
        ),
        "creation_date": search(r"^Creation Date:\s*(.+)") or search(r"^Created:\s*(.+)"),
        "expiration_date": search(
            r"^(?:Registry Expiry Date|Expiry Date|Expiration Date|"
            r"Registrar Registration Expiration Date):\s*(.+)"
        ),
        "name_servers": _list_values(
            re.findall(r"^Name Server:\s*(\S+)", text, re.IGNORECASE | re.MULTILINE)
        ),
        "source": "whois-cli",
    }


def parse_whois_object(w: Any) -> Dict[str, Any]:
    info = {
        "domain_name": _first_value(getattr(w, "domain_name", None)),
        "registrar": _first_value(getattr(w, "registrar", None)),
        "status": ", ".join(_list_values(getattr(w, "status", None))),
        "creation_date": _first_value(getattr(w, "creation_date", None)),
        "expiration_date": _first_value(
            getattr(w, "expiration_date", None) or getattr(w, "expiry_date", None)
        ),
        "name_servers": _list_values(getattr(w, "name_servers", None)),
        "source": "python-whois",
    }
    text = _to_text(getattr(w, "text", None) or getattr(w, "raw", None) or "")
    if text and not any([info["domain_name"], info["registrar"],
                         info["name_servers"], info["status"]]):
        merged = parse_whois_text(text)
        for key, val in merged.items():
            if not info.get(key) and val:
                info[key] = val
        info["source"] = "python-whois+raw-text"
    return info


def get_whois_info(domain: str,
                   timeout: float) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    candidates = [domain]
    if domain.startswith("www."):
        candidates.append(domain[4:])

    last_error = "WHOIS lookup failed"
    whois_cli = shutil.which("whois")

    for candidate in candidates:
        if WHOIS_LIBRARY_AVAILABLE:
            try:
                w = whois.whois(candidate)
                if w:
                    info = parse_whois_object(w)
                    if any([info.get("domain_name"), info.get("registrar"),
                            info.get("name_servers"), info.get("status")]):
                        info["queried_domain"] = candidate
                        return info, None
                    last_error = "Empty WHOIS result"
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {exc}"

        if whois_cli:
            try:
                completed = subprocess.run(["whois", candidate], capture_output=True,
                                           text=True, timeout=timeout)
                if completed.stdout.strip():
                    info = parse_whois_text(completed.stdout)
                    info["source"] = "whois-cli"
                    info["queried_domain"] = candidate
                    if any([info.get("domain_name"), info.get("registrar"),
                            info.get("name_servers"), info.get("status")]):
                        return info, None
                    last_error = "WHOIS CLI output could not be parsed"
                else:
                    last_error = completed.stderr.strip() or f"whois exit {completed.returncode}"
            except subprocess.TimeoutExpired:
                last_error = "WHOIS CLI timeout"
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {exc}"
        elif not WHOIS_LIBRARY_AVAILABLE:
            last_error = "python-whois not installed and no whois CLI found"

    return None, last_error


# --------------------------------------------------------------------------
# Optional HTTP check
# --------------------------------------------------------------------------
def check_website(domain: str, timeout: float) -> Tuple[bool, str]:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    last_error = "Unreachable"
    for url in (f"https://{domain}", f"http://{domain}"):
        for method in ("HEAD", "GET"):
            try:
                req = urllib.request.Request(
                    url, method=method,
                    headers={"User-Agent": "Mozilla/5.0 (compatible; domains-validator)"})
                with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
                    return True, f"HTTP {resp.status} {url}"
            except urllib.error.HTTPError as exc:
                return True, f"HTTP {exc.code} {url}"
            except urllib.error.URLError as exc:
                last_error = f"{url}: {exc.reason}"
            except Exception as exc:
                last_error = f"{url}: {type(exc).__name__}"
    return False, last_error


# --------------------------------------------------------------------------
# Core logic
# --------------------------------------------------------------------------
def effective_name_servers(dns_ns: List[str], whois_ns: List[str],
                           ignore_patterns: List[str]) -> Tuple[List[str], str, bool]:
    """
    Return (nameservers, source, parked_flag).
    Live DNS wins. Otherwise WHOIS minus registrar placeholders.
    If WHOIS only lists placeholders -> parked/hold.
    """
    if dns_ns:
        return list(dns_ns), "DNS", False
    filtered = [ns for ns in whois_ns
                if not any(p in ns for p in ignore_patterns)]
    if filtered:
        return filtered, "WHOIS", False
    if whois_ns:
        return [], "parked/hold", True
    return [], "", False


def ns_match_expected(ns_list: List[str], expected_parts: List[str]) -> bool:
    return any(part in ns for ns in ns_list for part in expected_parts)


def process_domain(raw_domain: Any, settings: argparse.Namespace) -> Dict[str, Any]:
    row: Dict[str, Any] = {col: "" for col in
                           set(SUMMARY_COLUMNS) | set(DNS_COLUMNS) | set(WHOIS_COLUMNS)}
    domain = normalize_domain(raw_domain)
    row["DOMAIN"] = domain
    if not domain:
        row["STATUS"] = "Empty"
        return row

    a_records, a_error = resolve_record(domain, "A", settings)
    ns_records, ns_error = resolve_record(domain, "NS", settings)
    a_records = a_records or []
    ns_records = ns_records or []

    row["A RECORD"] = ", ".join(a_records)
    row["NS RECORD"] = ", ".join(ns_records)

    dns_errors = []
    if a_error and a_error != "NXDOMAIN":
        dns_errors.append(f"A: {a_error}")
    if ns_error and ns_error != "NXDOMAIN":
        dns_errors.append(f"NS: {ns_error}")
    row["DNS ERROR"] = "; ".join(dns_errors)

    http_ok: Optional[bool] = None
    if settings.http_check:
        if a_records:
            http_ok, row["HTTP RESULT"] = check_website(domain, settings.http_timeout)
        else:
            row["HTTP RESULT"] = "Skipped - no A record"

    valid_dns = (
        (bool(settings.expected_ips) and any(r in settings.expected_ips for r in a_records))
        or (bool(settings.expected_ns_parts) and ns_match_expected(ns_records, settings.expected_ns_parts))
    )

    # ---------------- WHOIS fallback ----------------
    whois_ns: List[str] = []
    whois_status_clean = ""
    has_whois = False
    whois_error = ""
    need_whois = settings.whois_fallback and (
        settings.always_whois
        or not valid_dns
        or (settings.http_check and http_ok is False)
    )
    if need_whois:
        info, err = get_whois_info(domain, settings.whois_timeout)
        if info:
            has_whois = True
            whois_ns = info.get("name_servers") or []
            whois_status_clean = clean_epp_status(info.get("status", ""))
            row["REGISTRAR"] = (info.get("registrar") or "").strip()
            row["STATUS_W"] = whois_status_clean
            row["CREATED"] = clean_date(info.get("creation_date", ""))
            row["EXPIRES"] = clean_date(info.get("expiration_date", ""))
            row["RAW WHOIS NAME SERVERS"] = ", ".join(whois_ns)
            row["SOURCE"] = info.get("source", "")
        else:
            whois_error = err or "WHOIS lookup failed"
            row["ERROR"] = whois_error

    # ---------------- effective NS + status ----------------
    eff_ns, ns_source, parked = effective_name_servers(
        ns_records, whois_ns, settings.ignore_patterns)
    row["NAME SERVERS"] = ", ".join(eff_ns)
    row["EFFECTIVE NAME SERVERS"] = ", ".join(eff_ns)
    row["NS SOURCE"] = ns_source if ns_source != "parked/hold" else ""

    valid_whois = (not valid_dns) and ns_match_expected(eff_ns, settings.expected_ns_parts)

    pending_delete = any(s in whois_status_clean
                         for s in ("pendingdelete", "redemptionperiod", "pendingrestore"))
    on_hold = any(s in whois_status_clean for s in ("serverhold", "clienthold"))

    if valid_dns:
        status = "Valid"
    elif valid_whois:
        status = "Valid (WHOIS NS)"
    elif parked:
        status = "Parked / registrar hold"
    elif pending_delete:
        status = "Registered - pendingDelete"
    elif has_whois:
        status = "Registered - wrong DNS"
    else:
        status = "Not found"
    row["STATUS"] = status

    notes: List[str] = []
    if parked:
        notes.append("WHOIS lists only registrar placeholder NS (parked/hold)")
    if pending_delete:
        notes.append("Domain in deletion period")
    elif on_hold:
        notes.append("Domain on registry/registrar hold")
    if valid_whois:
        notes.append("DNS not serving; NS confirmed via WHOIS")
    if whois_error:
        notes.append(f"WHOIS unavailable: {whois_error}")
    if http_ok is False:
        notes.append("Website unreachable")
    row["NOTES"] = "; ".join(notes)

    return row


# --------------------------------------------------------------------------
# Report writing + styling
# --------------------------------------------------------------------------
def style_workbook(path: Path) -> None:
    try:
        from openpyxl import load_workbook
        from openpyxl.styles import Alignment, Font, PatternFill
        from openpyxl.utils import get_column_letter
    except Exception:
        return

    wb = load_workbook(path)
    header_fill = PatternFill("solid", fgColor="1F4E78")
    header_font = Font(bold=True, color="FFFFFF")
    status_fills = {
        "Valid": PatternFill("solid", fgColor="C6EFCE"),
        "Valid (WHOIS NS)": PatternFill("solid", fgColor="DDEBF7"),
        "Registered - wrong DNS": PatternFill("solid", fgColor="FFEB9C"),
        "Parked / registrar hold": PatternFill("solid", fgColor="FFEB9C"),
        "Registered - pendingDelete": PatternFill("solid", fgColor="F8CBAD"),
        "Not found": PatternFill("solid", fgColor="FFC7CE"),
    }

    for ws in wb.worksheets:
        ws.freeze_panes = "A2"
        ws.auto_filter.ref = ws.dimensions
        for cell in ws[1]:
            cell.fill = header_fill
            cell.font = header_font
            cell.alignment = Alignment(vertical="center", horizontal="center")
        for column_cells in ws.columns:
            letter = get_column_letter(column_cells[0].column)
            width = max((len(str(c.value)) if c.value is not None else 0)
                        for c in column_cells)
            ws.column_dimensions[letter].width = min(max(width + 2, 10), 55)

        if ws.title == "Summary":
            header = {c.value: c.column for c in ws[1]}
            status_col = header.get("STATUS")
            if status_col:
                for row_cells in ws.iter_rows(min_row=2):
                    cell = row_cells[status_col - 1]
                    fill = status_fills.get(str(cell.value))
                    if fill:
                        cell.fill = fill
    wb.save(path)


def write_report(results: List[Dict[str, Any]], path: Path, http_check: bool) -> Path:
    path = Path(path)
    if not path.suffix:
        path = path.with_suffix(".xlsx")

    all_df = pd.DataFrame.from_records(results)

    summary_df = all_df[SUMMARY_COLUMNS].copy()
    dns_cols = [c for c in DNS_COLUMNS if http_check or c != "HTTP RESULT"]
    dns_df = all_df[dns_cols].copy()
    whois_df = all_df[WHOIS_COLUMNS].copy()
    whois_df = whois_df[(whois_df["SOURCE"] != "") | (whois_df["ERROR"] != "")]

    if path.suffix.lower() == ".csv":
        LOG.warning("CSV output keeps only the Summary sheet.")
        summary_df.to_csv(path, index=False)
        return path

    if path.suffix.lower() == ".xls":
        LOG.warning(".xls not supported for output; writing .xlsx")
        path = path.with_suffix(".xlsx")

    path.parent.mkdir(parents=True, exist_ok=True)
    with pd.ExcelWriter(path, engine="openpyxl") as writer:
        summary_df.to_excel(writer, sheet_name="Summary", index=False)
        dns_df.to_excel(writer, sheet_name="DNS Details", index=False)
        whois_df.to_excel(writer, sheet_name="WHOIS Details", index=False)
    style_workbook(path)
    return path


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main() -> None:
    args = parse_args()
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    if args.workers < 1:
        args.workers = 1
    if not args.input.is_file():
        raise SystemExit(f"Input file not found: {args.input}")

    df = read_table(args.input, args.header, args.delimiter, args.encoding)
    df = maybe_drop_header_row(df, args.domain_column, args.header)
    if df.empty:
        raise SystemExit("Input file contains no rows.")

    try:
        domains = select_domain_series(df, args.domain_column)
    except ValueError as exc:
        raise SystemExit(str(exc))

    total = len(domains)
    results: List[Optional[Dict[str, Any]]] = [None] * total
    LOG.info("Processing %d domains with %d workers...", total, args.workers)

    try:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            future_map = {
                executor.submit(process_domain, domains.iloc[i], args): i
                for i in range(total)
            }
            done = 0
            for future in as_completed(future_map):
                idx = future_map[future]
                try:
                    results[idx] = future.result()
                except Exception as exc:
                    err_row = {"DOMAIN": domains.iloc[idx],
                               "STATUS": "Error",
                               "NOTES": f"{type(exc).__name__}: {exc}"}
                    results[idx] = err_row
                done += 1
                if done % 25 == 0 or done == total:
                    LOG.info("Processed %d/%d", done, total)
    except KeyboardInterrupt:
        raise SystemExit("Interrupted by user.")

    filled = [{**{c: "" for c in set(SUMMARY_COLUMNS) | set(DNS_COLUMNS) | set(WHOIS_COLUMNS)},
               **r} for r in results if r is not None]

    output_path = args.output or args.input.with_name(f"{args.input.stem}_report.xlsx")
    try:
        saved = write_report(filled, output_path, args.http_check)
    except Exception as exc:
        raise SystemExit(f"Failed saving report: {exc}")
    LOG.info("Report saved to: %s", saved)

    summary = pd.DataFrame.from_records(filled)["STATUS"].value_counts()
    LOG.info("Summary:")
    for status, count in summary.items():
        LOG.info("  %-28s %d", status, count)


if __name__ == "__main__":
    main()#!/usr/bin/env python3
"""
Robust domain validator using Live DNS + ICANN RDAP.
Produces a tidy, styled 3-sheet Excel report.
"""

import argparse
import logging
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import requests
import dns.exception
import dns.resolver

LOG = logging.getLogger("domains-validator")

DEFAULT_EXPECTED_IP = "37.27.108.238"
DEFAULT_EXPECTED_NS_SUBSTRING = "hosterz.net"

# Registrar placeholder / parking nameserver patterns
DEFAULT_IGNORE_NS_PATTERNS = [
    "hydrapiglephant.com",
    "sedoparking.com",
    "parkingcrew.net",
    "parklogic.com",
    "bodis.com",
]

SUMMARY_COLUMNS = [
    "DOMAIN", "A RECORD", "EFFECTIVE NAME SERVERS", "NS SOURCE",
    "STATUS", "REGISTRAR", "EXPIRES", "NOTES",
]
DNS_COLUMNS = ["DOMAIN", "A RECORD", "LIVE NS RECORD", "DNS ERROR"]
RDAP_COLUMNS = [
    "DOMAIN", "REGISTRAR", "EPP STATUS", "CREATED", "EXPIRES",
    "RDAP NAME SERVERS", "SOURCE", "ERROR",
]

HEADER_CANDIDATES = {
    "domain", "domains", "domain name", "domain_name", "domainname",
    "hostname", "host", "url", "website", "website address", "site",
}

_thread_local = threading.local()
_URL_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate domains using Live DNS + ICANN RDAP fallback.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--input", "-i", required=True, type=Path)
    parser.add_argument("--output", "-o", type=Path)
    parser.add_argument("--domain-column", default="0")
    parser.add_argument("--header", action="store_true")
    parser.add_argument("--delimiter", default=",")
    parser.add_argument("--encoding", default="utf-8-sig")
    parser.add_argument("--expected-ip", default=DEFAULT_EXPECTED_IP)
    parser.add_argument("--expected-ns-substring", default=DEFAULT_EXPECTED_NS_SUBSTRING)
    parser.add_argument("--ignore-ns-substring", default=",".join(DEFAULT_IGNORE_NS_PATTERNS))
    parser.add_argument("--nameservers", help="Comma-separated DNS servers")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--rdap-timeout", type=float, default=10.0)
    parser.add_argument("--no-rdap", dest="rdap_fallback", action="store_false")
    parser.add_argument("--always-rdap", action="store_true")
    parser.add_argument("--http-check", action="store_true")
    parser.add_argument("--http-timeout", type=float, default=8.0)
    parser.add_argument("--debug", action="store_true")

    args = parser.parse_args()
    args.nameservers = [x.strip() for x in args.nameservers.split(",") if x.strip()] if args.nameservers else None
    args.ignore_patterns = [p.strip().lower() for p in args.ignore_ns_substring.split(",") if p.strip()]
    args.expected_ips = {x.strip() for x in args.expected_ip.split(",") if x.strip()}
    args.expected_ns_parts = [x.strip().lower() for x in args.expected_ns_substring.split(",") if x.strip()]
    if args.always_rdap: args.rdap_fallback = True
    return args


# --------------------------------------------------------------------------
# DNS
# --------------------------------------------------------------------------
def get_resolver(timeout: float, nameservers: Optional[List[str]] = None) -> dns.resolver.Resolver:
    resolver = getattr(_thread_local, "resolver", None)
    if resolver is None:
        resolver = dns.resolver.Resolver()
        _thread_local.resolver = resolver
    resolver.timeout = timeout
    resolver.lifetime = timeout
    if nameservers: resolver.nameservers = nameservers
    return resolver

def resolve_record(domain: str, rdtype: str, settings: argparse.Namespace) -> Tuple[Optional[List[str]], Optional[str]]:
    last_error = None
    for attempt in range(settings.retries + 1):
        try:
            answers = get_resolver(settings.timeout, settings.nameservers).resolve(domain, rdtype)
            return [str(r).rstrip(".").lower() for r in answers], None
        except dns.resolver.NXDOMAIN: return None, "NXDOMAIN"
        except dns.resolver.NoAnswer: return [], None
        except dns.resolver.NoNameservers: last_error = "SERVFAIL"
        except dns.exception.Timeout: last_error = "TIMEOUT"
        except dns.exception.DNSException: last_error = "DNS_ERROR"
        if attempt < settings.retries: time.sleep(0.4 * (attempt + 1))
    return None, last_error

def normalize_domain(value: Any) -> str:
    if value is None: return ""
    text = str(value).strip().lower()
    if text in {"", "nan", "none"}: return ""
    text = _URL_RE.sub("", text)
    text = text.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].split(":", 1)[0].strip(".")
    return text


# --------------------------------------------------------------------------
# RDAP (The ICANN Way)
# --------------------------------------------------------------------------
def get_rdap_info(domain: str, timeout: float) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Fetch structured domain data via RDAP (JSON)."""
    # rdap.org is a public proxy that auto-routes to the correct registry RDAP server
    url = f"https://rdap.org/domain/{domain}"
    headers = {"Accept": "application/rdap+json, application/json"}
    
    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
        if resp.status_code == 404:
            return None, "RDAP not supported for this TLD"
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.RequestException as e:
        return None, f"RDAP request failed: {e}"
    except ValueError:
        return None, "Invalid JSON from RDAP"

    # 1. Nameservers (Clean and effective)
    ns_list = sorted(list(set(
        ns.get('ldhName', '').lower().rstrip('.')
        for ns in data.get('nameservers', []) if ns.get('ldhName')
    )))

    # 2. Events (Dates)
    events = {e.get('eventAction'): e.get('eventDate') for e in data.get('events', [])}
    
    # 3. Statuses (EPP)
    statuses = [s.replace(' ', '').lower() for s in data.get('status', [])]

    # 4. Registrar (Extract from vcardArray)
    registrar = ""
    def find_registrar(entities):
        for ent in entities:
            if 'registrar' in ent.get('roles', []):
                vcard = ent.get('vcardArray', [])
                if len(vcard) > 1 and isinstance(vcard[1], list):
                    for item in vcard[1]:
                        if isinstance(item, list) and len(item) >= 4 and item[0] == 'fn':
                            return item[3]
            if 'entities' in ent:
                res = find_registrar(ent['entities'])
                if res: return res
        return ""
    
    registrar = find_registrar(data.get('entities', []))

    return {
        "domain_name": data.get('ldhName', domain),
        "name_servers": ns_list,
        "status": statuses,
        "creation_date": events.get('registration', ''),
        "expiration_date": events.get('expiration', ''),
        "registrar": registrar,
        "source": "RDAP (ICANN)"
    }, None


# --------------------------------------------------------------------------
# Helpers & Input
# --------------------------------------------------------------------------
def read_table(path: Path, has_header: bool, delimiter: str, encoding: str) -> pd.DataFrame:
    ext = path.suffix.lower()
    header = 0 if has_header else None
    try:
        if ext in {".xlsx", ".xlsm"}: df = pd.read_excel(path, header=header, dtype=str, engine="openpyxl")
        elif ext == ".xls": df = pd.read_excel(path, header=header, dtype=str, engine="xlrd")
        elif ext == ".csv": df = pd.read_csv(path, header=header, dtype=str, keep_default_na=False, delimiter=delimiter, encoding=encoding)
        else: raise ValueError(f"Unsupported extension '{ext}'")
    except Exception as exc: raise SystemExit(f"Failed to read '{path}': {exc}")
    return df.fillna("")

def select_domain_series(df: pd.DataFrame, column: str) -> pd.Series:
    if df.empty: return pd.Series(dtype=str)
    if column.isdigit():
        idx = int(column)
        if idx < 0 or idx >= len(df.columns): raise ValueError(f"Column index {idx} out of range")
        return df.iloc[:, idx]
    if column in df.columns: return df[column]
    for col in df.columns:
        if str(col).strip().lower() == column.strip().lower(): return df[col]
    raise ValueError(f"Column '{column}' not found")

def maybe_drop_header_row(df: pd.DataFrame, column: str, has_header: bool) -> pd.DataFrame:
    if has_header or df.empty: return df
    try: series = select_domain_series(df, column)
    except ValueError: return df
    if series.empty: return df
    first = str(series.iloc[0]).strip().lower()
    if first in HEADER_CANDIDATES: return df.iloc[1:].reset_index(drop=True)
    return df

def clean_iso_date(date_str: str) -> str:
    if not date_str: return ""
    try:
        dt = pd.to_datetime(date_str, utc=True, errors="coerce")
        return dt.strftime("%Y-%m-%d") if not pd.isna(dt) else date_str[:10]
    except Exception: return date_str[:10]

def effective_name_servers(dns_ns: List[str], rdap_ns: List[str], ignore_patterns: List[str]) -> Tuple[List[str], str, bool]:
    if dns_ns: return list(dns_ns), "Live DNS", False
    filtered = [ns for ns in rdap_ns if not any(p in ns for p in ignore_patterns)]
    if filtered: return filtered, "RDAP", False
    if rdap_ns: return [], "Parked/Placeholder", True
    return [], "", False

def ns_match_expected(ns_list: List[str], expected_parts: List[str]) -> bool:
    return any(part in ns for ns in ns_list for part in expected_parts)


# --------------------------------------------------------------------------
# Core Logic
# --------------------------------------------------------------------------
def process_domain(raw_domain: Any, settings: argparse.Namespace) -> Dict[str, Any]:
    row = {col: "" for col in set(SUMMARY_COLUMNS) | set(DNS_COLUMNS) | set(RDAP_COLUMNS)}
    domain = normalize_domain(raw_domain)
    row["DOMAIN"] = domain
    if not domain:
        row["STATUS"] = "Empty"
        return row

    a_records, a_error = resolve_record(domain, "A", settings)
    ns_records, ns_error = resolve_record(domain, "NS", settings)
    a_records, ns_records = a_records or [], ns_records or []

    row["A RECORD"] = ", ".join(a_records)
    row["LIVE NS RECORD"] = ", ".join(ns_records)
    
    dns_errors = []
    if a_error and a_error != "NXDOMAIN": dns_errors.append(f"A: {a_error}")
    if ns_error and ns_error != "NXDOMAIN": dns_errors.append(f"NS: {ns_error}")
    row["DNS ERROR"] = "; ".join(dns_errors)

    valid_dns = (bool(settings.expected_ips) and any(r in settings.expected_ips for r in a_records)) or \
                (bool(settings.expected_ns_parts) and ns_match_expected(ns_records, settings.expected_ns_parts))

    # RDAP Fallback
    rdap_ns, rdap_status, has_rdap, rdap_error = [], [], False, ""
    need_rdap = settings.rdap_fallback and (settings.always_rdap or not valid_dns)
    
    if need_rdap:
        info, err = get_rdap_info(domain, settings.rdap_timeout)
        if info:
            has_rdap = True
            rdap_ns = info.get("name_servers", [])
            rdap_status = info.get("status", [])
            row["REGISTRAR"] = info.get("registrar", "")
            row["EPP STATUS"] = ", ".join(rdap_status)
            row["CREATED"] = clean_iso_date(info.get("creation_date", ""))
            row["EXPIRES"] = clean_iso_date(info.get("expiration_date", ""))
            row["RDAP NAME SERVERS"] = ", ".join(rdap_ns)
            row["SOURCE"] = info.get("source", "")
        else:
            rdap_error = err or "RDAP failed"
            row["ERROR"] = rdap_error

    eff_ns, ns_source, parked = effective_name_servers(ns_records, rdap_ns, settings.ignore_patterns)
    row["EFFECTIVE NAME SERVERS"] = ", ".join(eff_ns)
    row["NS SOURCE"] = ns_source if ns_source != "Parked/Placeholder" else ""

    valid_rdap = (not valid_dns) and ns_match_expected(eff_ns, settings.expected_ns_parts)
    pending_delete = any("delete" in s or "redemption" in s for s in rdap_status)

    if valid_dns: status = "Valid"
    elif valid_rdap: status = "Valid (via RDAP)"
    elif parked: status = "Parked / Registrar Hold"
    elif pending_delete: status = "Pending Delete"
    elif has_rdap: status = "Registered - Wrong DNS"
    else: status = "Not Found / RDAP Unsupported"
    
    row["STATUS"] = status

    notes = []
    if parked: notes.append("RDAP lists only registrar placeholder NS")
    if pending_delete: notes.append("Domain in deletion/redemption period")
    if valid_rdap: notes.append("Live DNS failed, but RDAP confirms correct NS")
    if rdap_error: notes.append(f"RDAP unavailable: {rdap_error}")
    row["NOTES"] = "; ".join(notes)

    return row


# --------------------------------------------------------------------------
# Excel Output & Styling
# --------------------------------------------------------------------------
def style_workbook(path: Path) -> None:
    try:
        from openpyxl import load_workbook
        from openpyxl.styles import Alignment, Font, PatternFill
        from openpyxl.utils import get_column_letter
    except Exception: return

    wb = load_workbook(path)
    header_fill = PatternFill("solid", fgColor="1F4E78")
    header_font = Font(bold=True, color="FFFFFF")
    status_fills = {
        "Valid": PatternFill("solid", fgColor="C6EFCE"),
        "Valid (via RDAP)": PatternFill("solid", fgColor="DDEBF7"),
        "Registered - Wrong DNS": PatternFill("solid", fgColor="FFEB9C"),
        "Parked / Registrar Hold": PatternFill("solid", fgColor="FFEB9C"),
        "Pending Delete": PatternFill("solid", fgColor="F8CBAD"),
        "Not Found / RDAP Unsupported": PatternFill("solid", fgColor="FFC7CE"),
    }

    for ws in wb.worksheets:
        ws.freeze_panes = "A2"
        ws.auto_filter.ref = ws.dimensions
        for cell in ws[1]:
            cell.fill = header_fill
            cell.font = header_font
            cell.alignment = Alignment(vertical="center", horizontal="center")
        for column_cells in ws.columns:
            letter = get_column_letter(column_cells[0].column)
            width = max((len(str(c.value)) if c.value is not None else 0) for c in column_cells)
            ws.column_dimensions[letter].width = min(max(width + 2, 10), 55)

        if ws.title == "Summary":
            header = {c.value: c.column for c in ws[1]}
            status_col = header.get("STATUS")
            if status_col:
                for row_cells in ws.iter_rows(min_row=2):
                    cell = row_cells[status_col - 1]
                    fill = status_fills.get(str(cell.value))
                    if fill: cell.fill = fill
    wb.save(path)

def write_report(results: List[Dict[str, Any]], path: Path) -> Path:
    path = Path(path)
    if not path.suffix: path = path.with_suffix(".xlsx")
    if path.suffix.lower() == ".xls": path = path.with_suffix(".xlsx")

    all_df = pd.DataFrame.from_records(results)
    summary_df = all_df[SUMMARY_COLUMNS].copy()
    dns_df = all_df[DNS_COLUMNS].copy()
    rdap_df = all_df[RDAP_COLUMNS].copy()
    rdap_df = rdap_df[(rdap_df["SOURCE"] != "") | (rdap_df["ERROR"] != "")]

    path.parent.mkdir(parents=True, exist_ok=True)
    with pd.ExcelWriter(path, engine="openpyxl") as writer:
        summary_df.to_excel(writer, sheet_name="Summary", index=False)
        dns_df.to_excel(writer, sheet_name="DNS Details", index=False)
        rdap_df.to_excel(writer, sheet_name="RDAP Details", index=False)
    style_workbook(path)
    return path


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main() -> None:
    args = parse_args()
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if args.workers < 1: args.workers = 1
    if not args.input.is_file(): raise SystemExit(f"Input file not found: {args.input}")

    df = read_table(args.input, args.header, args.delimiter, args.encoding)
    df = maybe_drop_header_row(df, args.domain_column, args.header)
    if df.empty: raise SystemExit("Input file contains no rows.")

    try: domains = select_domain_series(df, args.domain_column)
    except ValueError as exc: raise SystemExit(str(exc))

    total = len(domains)
    results: List[Optional[Dict[str, Any]]] = [None] * total
    LOG.info("Processing %d domains using Live DNS + RDAP...", total)

    try:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            future_map = {executor.submit(process_domain, domains.iloc[i], args): i for i in range(total)}
            done = 0
            for future in as_completed(future_map):
                idx = future_map[future]
                try: results[idx] = future.result()
                except Exception as exc: results[idx] = {"DOMAIN": domains.iloc[idx], "STATUS": "Error", "NOTES": str(exc)}
                done += 1
                if done % 25 == 0 or done == total: LOG.info("Processed %d/%d", done, total)
    except KeyboardInterrupt: raise SystemExit("Interrupted.")

    filled = [{**{c: "" for c in set(SUMMARY_COLUMNS) | set(DNS_COLUMNS) | set(RDAP_COLUMNS)}, **r} for r in results if r]
    output_path = args.output or args.input.with_name(f"{args.input.stem}_report.xlsx")
    
    try: saved = write_report(filled, output_path)
    except Exception as exc: raise SystemExit(f"Failed saving report: {exc}")
    
    LOG.info("Report saved to: %s", saved)
    summary = pd.DataFrame.from_records(filled)["STATUS"].value_counts()
    LOG.info("Summary:\n%s", summary.to_string())

if __name__ == "__main__":
    main()
