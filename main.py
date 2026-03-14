#!/usr/bin/env python3
"""
main.py — CLI entry point for MITRE ATT&CK TTP Mapper.

Supports multiple input formats, confidence filtering, and multiple
export formats including CSV, JSON, Markdown, Navigator layers, and Sigma rules.
"""

import argparse
import os
import sys

# Add 'confidence scoring' directory to path for utils, navigator_export, sigma_generator
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "confidence scoring"))

from mapping_engine import map_iocs, get_tactic_summary, get_technique_frequency
from utils import load_iocs, write_csv, write_json, write_markdown
from navigator_export import generate_and_save
from heatmap_export import save_heatmap
from sigma_generator import generate_sigma_rules, save_sigma_rules, rules_to_markdown
from parsers.log_parsers import (
    auto_detect_and_parse,
    parse_json_log,
    parse_sysmon_xml,
    parse_cef,
    parse_csv_log,
    parse_plain_text,
)
from parsers.cloud_parsers import (
    parse_cloudtrail,
    parse_azure_activity,
    parse_gcp_audit,
)


FORMAT_PARSERS = {
    "text": parse_plain_text,
    "json": parse_json_log,
    "sysmon": parse_sysmon_xml,
    "cef": parse_cef,
    "csv": parse_csv_log,
    "cloudtrail": parse_cloudtrail,
    "azure": parse_azure_activity,
    "gcp": parse_gcp_audit,
    "auto": auto_detect_and_parse,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="MITRE ATT&CK TTP Mapper — Map IOCs to ATT&CK techniques.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py -i samples/sample_input.txt\n"
            "  python main.py -i logs.json -f json --min-confidence Medium\n"
            "  python main.py -i trail.json -f cloudtrail --sigma --navigator\n"
            "  python main.py -i data.json -f auto --all-exports\n"
        ),
    )
    parser.add_argument(
        "-i", "--input", required=True,
        help="Path to input file containing IOCs or log events.",
    )
    parser.add_argument(
        "-f", "--format", default="auto",
        choices=list(FORMAT_PARSERS.keys()),
        help="Input format (default: auto-detect).",
    )
    parser.add_argument(
        "-o", "--output-dir", default="output",
        help="Output directory (default: output/).",
    )
    parser.add_argument(
        "--min-confidence", default="Low",
        choices=["Low", "Medium", "High"],
        help="Minimum confidence level (default: Low).",
    )
    parser.add_argument(
        "--source", default="cli",
        help="Source label for the IOCs (default: cli).",
    )
    parser.add_argument(
        "--csv", action="store_true",
        help="Export results to CSV.",
    )
    parser.add_argument(
        "--json", action="store_true", dest="export_json",
        help="Export results to JSON.",
    )
    parser.add_argument(
        "--markdown", action="store_true",
        help="Export results to Markdown.",
    )
    parser.add_argument(
        "--navigator", action="store_true",
        help="Export ATT&CK Navigator layer JSON.",
    )
    parser.add_argument(
        "--sigma", action="store_true",
        help="Export Sigma detection rules.",
    )
    parser.add_argument(
        "--sigma-single-file", action="store_true",
        help="Write all Sigma rules to one combined YAML file.",
    )
    parser.add_argument(
        "--sigma-author", default="MITRE ATT&CK TTP Mapper",
        help="Author name for generated Sigma rules.",
    )
    parser.add_argument(
        "--heatmap", action="store_true",
        help="Export a standalone HTML heat map of technique matches.",
    )
    parser.add_argument(
        "--all-exports", action="store_true",
        help="Generate all export formats (CSV, JSON, Markdown, Navigator, Heatmap, Sigma).",
    )
    parser.add_argument(
        "--layer-name", default="CLI TTP Mapper Layer",
        help="Name for the Navigator layer.",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Validate input file
    if not os.path.isfile(args.input):
        print(f"Error: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    # Parse input
    parse_fn = FORMAT_PARSERS[args.format]
    print(f"Parsing input ({args.format}): {args.input}")
    try:
        ioc_list = parse_fn(args.input)
    except Exception as e:
        print(f"Error parsing input: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Loaded {len(ioc_list)} IOC/event entries.")

    if not ioc_list:
        print("No IOCs found in input file.", file=sys.stderr)
        sys.exit(1)

    # Map IOCs
    results = map_iocs(ioc_list, min_confidence=args.min_confidence, source=args.source)
    print(f"Mapped {len(results)} technique matches.")

    if not results:
        print("No ATT&CK techniques matched.")
        sys.exit(0)

    # Summary
    tactic_summary = get_tactic_summary(results)
    tech_freq = get_technique_frequency(results)
    unique_techs = len(set(r["Technique ID"] for r in results))

    print(f"\nSummary:")
    print(f"  Unique techniques: {unique_techs}")
    print(f"  Tactics covered:   {len(tactic_summary)}")
    for tactic, count in sorted(tactic_summary.items(), key=lambda x: -x[1]):
        print(f"    {tactic}: {count}")

    # Determine which exports to produce
    os.makedirs(args.output_dir, exist_ok=True)
    do_all = args.all_exports
    # If no specific export flag is set, default to CSV
    any_export = args.csv or args.export_json or args.markdown or args.navigator or args.heatmap or args.sigma
    if not any_export and not do_all:
        args.csv = True  # Default export

    # CSV
    if args.csv or do_all:
        csv_path = os.path.join(args.output_dir, "report.csv")
        write_csv(results, csv_path)
        print(f"CSV report saved: {csv_path}")

    # JSON
    if args.export_json or do_all:
        json_path = os.path.join(args.output_dir, "report.json")
        write_json(results, json_path)
        print(f"JSON report saved: {json_path}")

    # Markdown
    if args.markdown or do_all:
        md_path = os.path.join(args.output_dir, "report.md")
        write_markdown(results, md_path)
        print(f"Markdown report saved: {md_path}")

    # Navigator layer
    if args.navigator or do_all:
        nav_path = os.path.join(args.output_dir, "navigator_layer.json")
        generate_and_save(results, nav_path, name=args.layer_name)
        print(f"Navigator layer saved: {nav_path}")

    # HTML heat map
    if args.heatmap or do_all:
        hm_path = os.path.join(args.output_dir, "heatmap.html")
        save_heatmap(results, hm_path, layer_name=args.layer_name)
        print(f"Heat map saved:        {hm_path}")

    # Sigma rules
    if args.sigma or do_all:
        sigma_dir = os.path.join(args.output_dir, "sigma")
        rules = generate_sigma_rules(results, author=args.sigma_author)
        if rules:
            paths = save_sigma_rules(rules, sigma_dir, single_file=args.sigma_single_file)
            print(f"Sigma rules saved ({len(rules)} rules): {sigma_dir}/")

            # Also write the markdown index
            md_index = rules_to_markdown(rules)
            index_path = os.path.join(sigma_dir, "SIGMA_INDEX.md")
            with open(index_path, "w", encoding="utf-8") as f:
                f.write(md_index)
            print(f"Sigma index saved: {index_path}")
        else:
            print("No Sigma templates available for matched techniques.")

    print("\nDone.")


if __name__ == "__main__":
    main()