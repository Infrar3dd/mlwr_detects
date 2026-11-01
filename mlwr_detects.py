#!/usr/bin/env python3
import argparse
import asyncio
import json
import os
import sys
from typing import Any, Dict, Optional

import aiohttp


# API KEYS
VT_API_KEY = "CHANGETHIS"
MB_AUTH_KEY = "CHANGETHIS"

# Endpoints
VT_API_BASE = "https://www.virustotal.com/api/v3"
MB_API_URL = "https://mb-api.abuse.ch/api/v1/"


# Colors
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return sys.stdout.isatty()


COLOR_ENABLED = _supports_color()


def c(text, color: str) -> str:
    if not COLOR_ENABLED:
        return str(text)
    return f"{color}{text}{Colors.RESET}"


def bold(t):    return c(t, Colors.BOLD)
def dim(t):     return c(t, Colors.DIM)
def red(t):     return c(t, Colors.BRIGHT_RED)
def green(t):   return c(t, Colors.BRIGHT_GREEN)
def yellow(t):  return c(t, Colors.BRIGHT_YELLOW)
def blue(t):    return c(t, Colors.BRIGHT_BLUE)
def magenta(t): return c(t, Colors.BRIGHT_MAGENTA)
def cyan(t):    return c(t, Colors.BRIGHT_CYAN)


class ScannerError(RuntimeError):
    pass


# type normalizers
def _as_dict(value) -> Dict[str, Any]:

    return value if isinstance(value, dict) else {}


def _as_list(value) -> list:

    return value if isinstance(value, list) else []


# VirusTotal
async def fetch_virustotal(
    session: aiohttp.ClientSession, file_hash: str
) -> Optional[Dict[str, Any]]:
    if not VT_API_KEY or VT_API_KEY == "CHANGETHIS":
        raise ScannerError(
            "VirusTotal API key is not set. Edit VT_API_KEY in the script."
        )

    url = f"{VT_API_BASE}/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY, "accept": "application/json"}

    try:
        async with session.get(url, headers=headers) as resp:
            if resp.status == 404:
                return None
            payload = await resp.json(content_type=None)
            if resp.status >= 400:
                error = payload.get("error", {}) if isinstance(payload, dict) else {}
                raise ScannerError(
                    f"VirusTotal error: {error.get('message', resp.status)}"
                )
            return payload
    except aiohttp.ClientError as e:
        raise ScannerError(f"Network error (VT): {e}")


def parse_vt_detections(vt_data: Dict[str, Any]) -> Dict[str, Any]:
    attributes = vt_data.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    results = attributes.get("last_analysis_results", {})

    detections = []
    for engine, info in results.items():
        category = info.get("category")
        if category in ("malicious", "suspicious"):
            detections.append(
                {
                    "engine": engine,
                    "category": category,
                    "result": info.get("result"),
                    "version": info.get("engine_version"),
                    "update": info.get("engine_update"),
                }
            )

    detections.sort(
        key=lambda x: (0 if x["category"] == "malicious" else 1, x["engine"])
    )

    return {
        "stats": stats,
        "detections": detections,
        "sha256": attributes.get("sha256"),
        "names": attributes.get("names", []),
        "type_description": attributes.get("type_description"),
        "meaningful_name": attributes.get("meaningful_name"),
        "size": attributes.get("size"),
        "first_submission_date": attributes.get("first_submission_date"),
        "last_analysis_date": attributes.get("last_analysis_date"),
        "tags": attributes.get("tags", []),
    }


# MalwareBazaar
async def fetch_malwarebazaar(
    session: aiohttp.ClientSession, file_hash: str
) -> Optional[Dict[str, Any]]:
    headers = {}
    if MB_AUTH_KEY and MB_AUTH_KEY != "CHANGETHIS":
        headers["Auth-Key"] = MB_AUTH_KEY

    data = {"query": "get_info", "hash": file_hash}

    try:
        async with session.post(MB_API_URL, data=data, headers=headers) as resp:
            payload = await resp.json(content_type=None)
            if not isinstance(payload, dict):
                return None
            if payload.get("query_status") == "hash_not_found":
                return None
            if payload.get("query_status") != "ok":
                return None
            return payload
    except aiohttp.ClientError:
        return None


def parse_mb_info(mb_data: Dict[str, Any]) -> Dict[str, Any]:
    data_list = _as_list(mb_data.get("data"))
    entry = _as_dict(data_list[0]) if data_list else {}

    # vendor_intel
    vendor_intel_raw = _as_dict(entry.get("vendor_intel"))
    vendor_summary: Dict[str, Dict[str, Any]] = {}
    for vendor, intel in vendor_intel_raw.items():
        intel = _as_dict(intel)
        if not intel:
            continue
        keep = {}
        for key in (
            "verdict",
            "score",
            "malware_family",
            "malware_name",
            "threat_name",
            "detection",
            "tags",
            "signatures",
            "family",
            "classification",
            "confidence",
            "analysis_url",
            "report_link",
            "link",
        ):
            if key in intel and intel[key]:
                keep[key] = intel[key]

        if "tags" not in keep and isinstance(intel.get("tags"), list):
            keep["tags"] = intel["tags"]
        if keep:
            vendor_summary[vendor] = keep

    # yara_rules
    yara_rules = []
    for rule in _as_list(entry.get("yara_rules")):
        rule = _as_dict(rule)
        if rule:
            yara_rules.append(
                {
                    "name": rule.get("rule_name") or rule.get("name"),
                    "author": rule.get("author"),
                    "description": rule.get("description"),
                    "reference": rule.get("reference"),
                }
            )

    # code_sign
    cs = _as_dict(entry.get("code_sign"))
    code_sign = {
        "subject_cn": cs.get("subject_cn"),
        "issuer_cn": cs.get("issuer_cn"),
        "algorithm": cs.get("algorithm"),
        "valid_from": cs.get("valid_from"),
        "valid_to": cs.get("valid_to"),
        "serial_number": cs.get("serial_number"),
        "cscb_listed": cs.get("cscb_listed"),
        "cscb_reason": cs.get("cscb_reason"),
    } if cs else {}

    # delivery_method 
    dm = entry.get("delivery_method")
    if not isinstance(dm, (dict, str)):
        dm = {}

    # OLE info (for docs)
    ole = _as_dict(entry.get("ole_information"))

    return {
        # identificators
        "sha256_hash": entry.get("sha256_hash"),
        "sha1_hash": entry.get("sha1_hash"),
        "md5_hash": entry.get("md5_hash"),
        "sha3_384_hash": entry.get("sha3_384_hash"),
        # file
        "file_name": entry.get("file_name"),
        "file_type": entry.get("file_type"),
        "file_type_mime": entry.get("file_type_mime"),
        "file_size": entry.get("file_size"),
        "imphash": entry.get("imphash"),
        "tlsh": entry.get("tlsh"),
        "ssdeep": entry.get("ssdeep"),
        "dhash_icon": entry.get("dhash_icon"),
        # timestamps
        "first_seen": entry.get("first_seen"),
        "last_seen": entry.get("last_seen"),
        # source
        "reporter": entry.get("reporter"),
        "origin_country": entry.get("origin_country"),
        "anonymous": entry.get("anonymous"),
        # classification
        "signature": entry.get("signature"),
        "tags": _as_list(entry.get("tags")),
        # delivery
        "delivery_method": dm,
        # YARA
        "yara_rules": yara_rules,
        # signing
        "code_sign": code_sign,
        # OLE
        "ole_information": {
            "oleid": ole.get("oleid"),
            "olevba": ole.get("olevba"),
        } if ole else {},
        # Vendor analytics
        "vendor_intel": vendor_summary,
    }


# output helpers
def _fmt_list(values, empty="None") -> str:
    if not values:
        return dim(empty)
    if isinstance(values, list):
        return ", ".join(str(v) for v in values)
    return str(values)


def _label(label: str, value, color=None) -> None:
    if value is None or value == "":
        value = dim("Unknown")
    elif color:
        value = c(value, color)
    print(f"{bold(label + ':')} {value}")


def print_report(
    file_hash: str,
    vt_result: Optional[Dict],
    mb_result: Optional[Dict],
    vt_error: Optional[str] = None,
):
    print()
    print(bold(cyan("File Hash: ")) + bold(file_hash))
    print()

    # VirusTotal
    if vt_result:
        parsed = parse_vt_detections(vt_result)
        print("\n" + bold(magenta("─── VIRUSTOTAL ───")))

        if parsed["meaningful_name"]:
            _label("Meaningful name", parsed["meaningful_name"], Colors.BRIGHT_WHITE)
        if parsed["names"]:
            print(f"{bold('Names:')} {', '.join(parsed['names'][:5])}")
        if parsed["type_description"]:
            print(f"{bold('Type:')} {parsed['type_description']}")
        if parsed["size"] is not None:
            print(f"{bold('Size:')} {parsed['size']} bytes")
        if parsed["tags"]:
            print(f"{bold('Tags:')} {_fmt_list(parsed['tags'])}")

        stats = parsed["stats"]
        mal = stats.get("malicious", 0)
        sus = stats.get("suspicious", 0)
        und = stats.get("undetected", 0)
        har = stats.get("harmless", 0)

        print(
            f"{bold('Stats:')} "
            f"Malicious: {red(str(mal)) if mal else green(str(mal))} | "
            f"Suspicious: {yellow(str(sus)) if sus else green(str(sus))} | "
            f"Undetected: {green(str(und))} | "
            f"Harmless: {green(str(har))}"
        )

        if parsed["detections"]:
            print(bold("\nDetections:"))
            for det in parsed["detections"]:
                if det["category"] == "malicious":
                    icon = red("🔴")
                    cat = red(det["category"])
                else:
                    icon = yellow("🟠")
                    cat = yellow(det["category"])
                result_str = f" {dim('→')} {det['result']}" if det["result"] else ""
                print(f"  {icon} {bold(det['engine'])} [{cat}]{result_str}")
        else:
            print(green("\n✔ No malicious/suspicious detections found."))

        vt_link = (
            f"https://www.virustotal.com/gui/file/"
            f"{parsed['sha256'] or file_hash}"
        )
        print(f"\n{bold('Link:')} {blue(vt_link)}")
    else:
        print("\n" + bold(magenta("─── VIRUSTOTAL ───")))
        if vt_error:
            print(red(f"✘ Error: {vt_error}"))
        else:
            print(yellow("⚠ No report found."))

    print("\n" + dim("─" * 60) + "\n")

    # MalwareBazaar
    if mb_result:
        m = parse_mb_info(mb_result)
        print(bold(magenta("─── MALWAREBAZAAR ───")))

        # Identifiers
        _label("SHA256", m["sha256_hash"] or "Unknown", Colors.BRIGHT_WHITE)
        if m["sha1_hash"]:
            print(f"{bold('SHA1:')}   {m['sha1_hash']}")
        if m["md5_hash"]:
            print(f"{bold('MD5:')}    {m['md5_hash']}")
        if m["sha3_384_hash"]:
            print(f"{bold('SHA3-384:')} {m['sha3_384_hash']}")

        # File
        _label("File name", m["file_name"], Colors.BRIGHT_WHITE)
        ftype = m["file_type"] or "Unknown"
        if m["file_type_mime"]:
            ftype += f" {dim('(' + str(m['file_type_mime']) + ')')}"
        print(f"{bold('File type:')} {ftype}")
        if m["file_size"]:
            print(f"{bold('File size:')} {m['file_size']} bytes")

        # Classification
        sig = m["signature"]
        if sig:
            sig_color = (
                red(sig)
                if str(sig).lower() not in ("clean", "unknown")
                else green(sig)
            )
            print(f"{bold('Signature:')} {sig_color}")
        else:
            print(f"{bold('Signature:')} {dim('Unknown')}")
        print(f"{bold('Tags:')} {_fmt_list(m['tags'])}")

        # Timestamps
        print(f"{bold('First seen:')} {m['first_seen'] or dim('Unknown')}")
        print(f"{bold('Last seen:')}  {m['last_seen'] or dim('Unknown')}")

        # Source
        print(f"{bold('Reporter:')} {m['reporter'] or dim('Unknown')}")
        if m["origin_country"]:
            print(f"{bold('Origin country:')} {m['origin_country']}")
        if m["anonymous"] is not None:
            print(f"{bold('Anonymous:')} {m['anonymous']}")

        # Delivery — may be a dict or a plain string
        dm = m["delivery_method"]
        if isinstance(dm, dict) and dm:
            dm_parts = []
            for k, v in dm.items():
                if v:
                    dm_parts.append(f"{k}={v}" if not isinstance(v, bool) else k)
            if dm_parts:
                print(f"{bold('Delivery:')} {', '.join(dm_parts)}")
        elif isinstance(dm, str) and dm.strip():
            print(f"{bold('Delivery:')} {dm}")

        # Hashes / fingerprints
        if m["imphash"]:
            print(f"{bold('Imphash:')} {m['imphash']}")
        if m["ssdeep"]:
            print(f"{bold('ssdeep:')} {m['ssdeep']}")
        if m["tlsh"]:
            print(f"{bold('TLSH:')}   {m['tlsh']}")
        if m["dhash_icon"]:
            print(f"{bold('dHash icon:')} {m['dhash_icon']}")

        # Code signature
        cs = m["code_sign"]
        if isinstance(cs, dict) and any(cs.values()):
            print(bold("\nCode signature:"))
            for k in (
                "subject_cn",
                "issuer_cn",
                "algorithm",
                "valid_from",
                "valid_to",
                "serial_number",
                "cscb_listed",
                "cscb_reason",
            ):
                if cs.get(k):
                    val = cs[k]
                    if k == "cscb_reason":
                        val = red(val)
                    print(f"  {cyan(k)}: {val}")

        # OLE
        ole = m["ole_information"]
        if isinstance(ole, dict) and any(ole.values()):
            print(bold("\nOLE information:"))
            if ole.get("oleid"):
                print(f"  {cyan('oleid')}: {ole['oleid']}")
            if ole.get("olevba"):
                print(f"  {cyan('olevba')}: {ole['olevba']}")

        # YARA
        yara = m["yara_rules"]
        if isinstance(yara, list) and yara:
            print(bold("\nYARA rules:"))
            for rule in yara:
                if not isinstance(rule, dict):
                    continue
                line = f"  {yellow('-')} {bold(rule.get('name') or 'unnamed')}"
                if rule.get("author"):
                    line += f" {dim('(author: ' + str(rule['author']) + ')')}"
                print(line)
                if rule.get("description"):
                    print(f"      {dim(rule['description'])}")
                if rule.get("reference"):
                    print(f"      {blue(rule['reference'])}")

        # Vendor intel
        vi = m["vendor_intel"]
        if isinstance(vi, dict) and vi:
            print(bold("\nVendor intel:"))
            for vendor, info in vi.items():
                if not isinstance(info, dict):
                    continue
                parts = []
                for k, v in info.items():
                    if isinstance(v, list):
                        v = ", ".join(str(x) for x in v)
                    parts.append(f"{cyan(k)}={v}")
                print(f"  {bold(vendor)}: {' | '.join(parts)}")

        mb_link = f"https://bazaar.abuse.ch/sample/{m['sha256_hash'] or file_hash}/"
        print(f"\n{bold('Link:')} {blue(mb_link)}")
    else:
        print(bold(magenta("─── MALWAREBAZAAR ───")))
        print(yellow("⚠ No sample found."))


async def main():
    global COLOR_ENABLED

    parser = argparse.ArgumentParser(
        description="Query VirusTotal and MalwareBazaar for file hash detection details."
    )
    parser.add_argument("hash", help="MD5, SHA1, or SHA256 hash of the file")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON instead of human-readable text",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    args = parser.parse_args()

    if args.no_color:
        COLOR_ENABLED = False

    file_hash = args.hash.strip().lower()

    if len(file_hash) not in (32, 40, 64) or not all(
        ch in "0123456789abcdef" for ch in file_hash
    ):
        print(
            red("Error:") + " Invalid hash format. Must be MD5 (32), SHA1 (40), "
            "or SHA256 (64) hex chars.",
            file=sys.stderr,
        )
        sys.exit(1)

    async with aiohttp.ClientSession() as session:
        vt_task = fetch_virustotal(session, file_hash)
        mb_task = fetch_malwarebazaar(session, file_hash)
        vt_result, mb_result = await asyncio.gather(
            vt_task, mb_task, return_exceptions=True
        )

    vt_error: Optional[str] = None
    if isinstance(vt_result, Exception):
        vt_error = str(vt_result)
        vt_result = None
    if isinstance(mb_result, Exception):
        mb_result = None

    if args.json:
        output = {
            "hash": file_hash,
            "virustotal": vt_result,
            "virustotal_error": vt_error,
            "malwarebazaar": mb_result,
        }
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        print_report(file_hash, vt_result, mb_result, vt_error)


if __name__ == "__main__":
    asyncio.run(main())