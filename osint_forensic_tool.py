#!/usr/bin/env python3
"""Simple OSINT forensic analysis toolkit for Linux/Termux.

This script demonstrates a lightweight workflow for:
- keyword profiling and risk flagging
- basic metadata inspection heuristics
- Google dork suggestions
- SQLite database inspection
- social engineering awareness guidance
- a simple report builder

It is designed for defensive, educational use and should be used responsibly.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sqlite3
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple


RISK_TERMS = {
    "social_engineering": ["phishing", "scam", "impersonation", "trust", "contact", "social"],
    "geolocation": ["location", "address", "street", "city", "country"],
    "weather": ["weather", "rain", "storm", "temperature", "forecast"],
    "geometry": ["geometry", "angle", "triangle", "circle", "vector"],
    "physics": ["physics", "gravity", "velocity", "momentum", "energy"],
    "biology": ["bio", "biology", "organism", "dna"],
    "metadata": ["metadata", "exif", "gps", "camera", "photo"],
    "injection": ["injection", "sql", "query", "payload"],
}


def build_keyword_profile(query: str) -> Dict[str, Any]:
    tokens = [token.lower() for token in query.split() if token.strip()]
    context_tags = []
    risk_flags = []

    for tag, terms in RISK_TERMS.items():
        if any(term in tokens for term in terms):
            context_tags.append(tag)

    if any(token in tokens for token in ["social", "engineer", "phishing", "scam", "impersonation", "cyber", "identity", "biodata"]):
        risk_flags.append("social_engineering_risk")

    if any(token in tokens for token in ["email", "phone", "name", "address", "dob", "birth"]):
        risk_flags.append("personal_data_risk")

    if any(token in tokens for token in ["sql", "injection", "database", "payload"]):
        risk_flags.append("injection_risk")

    return {
        "raw_query": query,
        "query_terms": tokens,
        "context_tags": context_tags,
        "risk_flags": risk_flags,
    }


def generate_dork_suggestions(target: str) -> List[str]:
    target_clean = target.strip().replace(" ", " ")
    terms = [term for term in target_clean.split() if term]
    base = " ".join(terms)
    dorks = [
        f'{base} site:linkedin.com',
        f'{base} site:github.com',
        f'{base} intitle:"index of"',
        f'{base} filetype:pdf',
        f'{base} "email" OR "phone"',
    ]
    return dorks


def inspect_sqlite_db(path: str) -> Dict[str, Any]:
    conn = sqlite3.connect(path)
    cursor = conn.cursor()
    tables = {}
    try:
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        table_names = [row[0] for row in cursor.fetchall()]
        for table in table_names:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            row_count = cursor.fetchone()[0]
            tables[table] = {"row_count": row_count}
    finally:
        conn.close()
    return {"path": path, "tables": tables}


def inspect_metadata(path: str) -> Dict[str, Any]:
    p = Path(path)
    return {
        "exists": p.exists(),
        "size_bytes": p.stat().st_size if p.exists() else None,
        "suffix": p.suffix,
        "is_file": p.is_file(),
        "is_dir": p.is_dir(),
        "platform": platform.platform(),
    }


def build_report(query: str, input_path: str = ".") -> Dict[str, Any]:
    profile = build_keyword_profile(query)
    dorks = generate_dork_suggestions(query)
    sqlite_analysis = {}

    if os.path.exists(input_path):
        for root, _, files in os.walk(input_path):
            for name in files:
                if name.endswith(".db") or name.endswith(".sqlite") or name.endswith(".sqlite3"):
                    db_path = os.path.join(root, name)
                    sqlite_analysis[db_path] = inspect_sqlite_db(db_path)

    return {
        "query": query,
        "keyword_profile": profile,
        "dork_suggestions": dorks,
        "sqlite_analysis": sqlite_analysis,
        "social_engineering_guidance": [
            "Verifikasi identitas sebelum membagikan data sensitif.",
            "Hindari klik tautan mencurigakan atau lampiran dari sumber yang tidak dikenal.",
            "Gunakan pengecekan silang di sumber resmi.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="OSINT forensic analysis toolkit")
    parser.add_argument("query", nargs="?", default="", help="Kata kunci atau nama target")
    parser.add_argument("--input", default=".", help="Path berkas atau direktori yang akan dianalisis")
    parser.add_argument("--json", action="store_true", help="Cetak hasil dalam JSON")
    args = parser.parse_args()

    if not args.query:
        args.query = input("Masukkan target atau kata kunci: ").strip()

    report = build_report(args.query, input_path=args.input)
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print("=== OSINT Forensic Report ===")
        print(f"Query: {report['query']}")
        print("Keyword Profile:")
        print(json.dumps(report["keyword_profile"], indent=2, ensure_ascii=False))
        print("Dork Suggestions:")
        for dork in report["dork_suggestions"]:
            print(f"- {dork}")
        print("SQLite Analysis:")
        print(json.dumps(report["sqlite_analysis"], indent=2, ensure_ascii=False))
        print("Social Engineering Guidance:")
        for item in report["social_engineering_guidance"]:
            print(f"- {item}")


if __name__ == "__main__":
    main()
