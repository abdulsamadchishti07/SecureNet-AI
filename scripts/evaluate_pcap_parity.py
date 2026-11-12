"""Differential PCAP replay. Synthetic checks do not establish original-capture parity."""

import argparse
from collections import defaultdict
import csv
from datetime import datetime
from decimal import Decimal, InvalidOperation
from ipaddress import IPv4Address
import json
import math
from pathlib import Path
import sys
from zoneinfo import ZoneInfo

# Support the documented direct script invocation from any working directory.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ml_engine.preprocess import SELECTED_COLUMNS, sha256_file
from sniffer.capture import start_capture
from sniffer.main import run

EXACT = {"Src Port", "Dst Port", "Protocol", "Total Fwd Packet", "Total Bwd packets",
         "Packet Length Min", "Packet Length Max", "FIN Flag Count", "SYN Flag Count",
         "RST Flag Count", "PSH Flag Count", "ACK Flag Count"}
DEFAULT_TOLERANCES = {name: {"abs": 0.0 if name in EXACT else 1e-6,
                             "rel": 0.0 if name in EXACT else 0.001}
                      for name in SELECTED_COLUMNS}


def integer(value, name):
    try:
        numeric = Decimal(str(value))
        if not numeric.is_finite() or numeric != numeric.to_integral_value() or numeric < 0:
            raise ValueError(f"{name} must be a nonnegative integer")
        return int(numeric)
    except InvalidOperation as exc:
        raise ValueError(f"Invalid {name}") from exc


def normalize_row(row, timestamp_column=None, timestamp_format=None, timezone=None):
    result = {}
    for name in ("Src IP", "Dst IP"):
        address = row[name] if name in row else integer(row[name + " dec"], name + " dec")
        result[name] = str(IPv4Address(address))
    for name in SELECTED_COLUMNS:
        value = float(row[name])
        if not math.isfinite(value) or value < 0:
            raise ValueError(f"{name} must be finite and nonnegative")
        if name in EXACT and not value.is_integer():
            raise ValueError(f"{name} must be integral")
        result[name] = value
    for name, maximum in (("Src Port", 65535), ("Dst Port", 65535), ("Protocol", 255)):
        if result[name] > maximum:
            raise ValueError(f"{name} exceeds its range")
    if "flow_start_usec" in row:
        start = integer(row["flow_start_usec"], "flow_start_usec")
    elif timestamp_column and timestamp_format:
        if not all(part in timestamp_format for part in ("%Y", "%m", "%d", "%H", "%M", "%S")):
            raise ValueError("Full capture date and hour required: use %Y %m %d %H %M %S or canonical epoch microseconds")
        stamp = datetime.strptime(row[timestamp_column], timestamp_format)
        if stamp.utcoffset() is None:
            if not timezone:
                raise ValueError("Naive reference timestamps require --timezone")
            zone = ZoneInfo(timezone)
            # Ambiguous or nonexistent local times require an explicit numeric UTC offset.
            first, second = stamp.replace(tzinfo=zone, fold=0), stamp.replace(tzinfo=zone, fold=1)
            if first.utcoffset() != second.utcoffset():
                raise ValueError("Ambiguous/nonexistent local timestamp: supply an explicit UTC offset")
            stamp = first
        start = round(stamp.timestamp() * 1_000_000)
    else:
        raise ValueError("Reference needs flow_start_usec or explicit timestamp column and format")
    duration = integer(row["Flow Duration"], "Flow Duration (microseconds)")
    end = integer(row.get("flow_end_usec", start + duration), "flow_end_usec")
    if start < 0 or end < start or end - start != duration:
        raise ValueError("Capture bounds disagree with Flow Duration in microseconds")
    return {**result, "flow_start_usec": start, "flow_end_usec": end}


def flow_key(row):
    # Keep each port attached to its IP; sorting ports independently causes collisions.
    return (int(row["Protocol"]), *sorted(((row["Src IP"], int(row["Src Port"])),
                                           (row["Dst IP"], int(row["Dst Port"])))))


def compare_flows(extracted_flow, ref_flow, tolerances=None):
    tolerances = DEFAULT_TOLERANCES if tolerances is None else tolerances
    differences = {}
    for name in SELECTED_COLUMNS:
        extracted, reference = float(extracted_flow[name]), float(ref_flow[name])
        absolute = abs(extracted - reference)
        relative = absolute / (abs(reference) + 1e-6)
        tolerance = tolerances[name]
        if not all(math.isfinite(v) and v >= 0 for v in (extracted, reference, tolerance["abs"], tolerance["rel"])):
            raise ValueError(f"Invalid value/tolerance for {name}")
        if absolute > tolerance["abs"] and relative > tolerance["rel"]:
            differences[name] = {"extracted": extracted, "reference": reference,
                                 "absolute_error": absolute, "relative_error": relative}
    return differences


def align_flows(extracted, reference, time_tolerance_usec=1000):
    tolerance = integer(time_tolerance_usec, "time tolerance")
    by_key = defaultdict(list)
    for index, row in enumerate(reference):
        by_key[flow_key(row)].append(index)
    candidates, inverse = {}, defaultdict(list)
    for i, row in enumerate(extracted):
        candidates[i] = [j for j in by_key[flow_key(row)] if all(
            abs(row[name] - reference[j][name]) <= tolerance
            for name in ("flow_start_usec", "flow_end_usec"))]
        for j in candidates[i]:
            inverse[j].append(i)
    # Accept only mutually unique candidates. Overlapping windows stay ambiguous,
    # even when a global optimization could select an assignment.
    matched = [(i, js[0]) for i, js in candidates.items() if len(js) == 1 and len(inverse[js[0]]) == 1]
    accepted_ext, accepted_ref = {i for i, _ in matched}, {j for _, j in matched}
    return {"matched": matched,
            "unmatched_extracted": [i for i, js in candidates.items() if not js],
            "unmatched_reference": [j for j in range(len(reference)) if not inverse[j]],
            "ambiguous_extracted": [i for i, js in candidates.items() if js and i not in accepted_ext],
            "ambiguous_reference": [j for j in inverse if j not in accepted_ref],
            "candidate_pairs": [[i, j] for i, js in candidates.items() for j in js]}


def evaluate(extracted, reference, time_tolerance_usec=1000, tolerances=None):
    alignment = align_flows(extracted, reference, time_tolerance_usec)
    tolerances = DEFAULT_TOLERANCES if tolerances is None else tolerances
    comparisons, per_feature = [], {name: {"compared": 0, "mismatches": 0, "max_absolute_error": 0.0,
                                          "max_relative_error": 0.0} for name in SELECTED_COLUMNS}
    for i, j in alignment["matched"]:
        left, right = extracted[i], reference[j]
        reversed_direction = (left["Src IP"], left["Src Port"]) != (right["Src IP"], right["Src Port"])
        differences = compare_flows(left, right, tolerances)
        for name in SELECTED_COLUMNS:
            absolute = abs(left[name] - right[name])
            stats = per_feature[name]
            stats["compared"] += 1
            stats["mismatches"] += name in differences
            stats["max_absolute_error"] = max(stats["max_absolute_error"], absolute)
            stats["max_relative_error"] = max(stats["max_relative_error"], absolute / (abs(right[name]) + 1e-6))
        comparisons.append({"extracted_index": i, "reference_index": j,
                            "orientation_mismatch": reversed_direction, "differences": differences})
    complete = bool(comparisons) and len(comparisons) == len(extracted) == len(reference)
    agrees = complete and not any(c["differences"] or c["orientation_mismatch"] for c in comparisons)
    return {"status": "agreement" if agrees else "discrepancies", "alignment": alignment,
            "matching_rule": "unordered endpoint pairs with attached ports; mutually unique start/end windows",
            "time_tolerance_usec": time_tolerance_usec, "tolerances": tolerances,
            "extracted_count": len(extracted), "reference_count": len(reference),
            "comparisons": comparisons, "per_feature": per_feature}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--reference", type=Path)
    parser.add_argument("--report", type=Path, default=Path("reports/parity/extraction_parity.json"))
    parser.add_argument("--export-flows", type=Path)
    parser.add_argument("--termination-grace", type=float, default=5)
    parser.add_argument("--time-tolerance-usec", type=int, default=1000)
    parser.add_argument("--timestamp-column")
    parser.add_argument("--timestamp-format")
    parser.add_argument("--timezone", help="IANA timezone for naive reference timestamps")
    parser.add_argument("--reference-exporter", help="Pinned exporter/version; reported as user-supplied")
    parser.add_argument("--tolerances", type=Path, help="JSON mapping all 20 names to abs/rel tolerances")
    args = parser.parse_args(argv)
    try:
        if args.time_tolerance_usec < 0 or not math.isfinite(args.termination_grace) or args.termination_grace < 0:
            raise ValueError("Invalid time tolerance or termination grace")
        if args.report.resolve() in {args.pcap.resolve(), args.reference.resolve() if args.reference else None}:
            raise ValueError("Output must differ from inputs")
        for path in (args.report, args.export_flows):
            if path and path.exists():
                raise FileExistsError(f"Preserve existing output: {path}")
        if args.export_flows and args.export_flows.resolve() == args.report.resolve():
            raise ValueError("Report and export must differ")
        tolerances = json.loads(args.tolerances.read_text()) if args.tolerances else DEFAULT_TOLERANCES
        if set(tolerances) != set(SELECTED_COLUMNS):
            raise ValueError("Tolerances must specify exactly the 20 model features")
        # Validate tolerances even when the capture produces no matched flows.
        compare_flows(dict.fromkeys(SELECTED_COLUMNS, 0), dict.fromkeys(SELECTED_COLUMNS, 0), tolerances)
        flows, diagnostics = [], {}
        run(start_capture(pcap=str(args.pcap)), flows.append, args.termination_grace, diagnostics=diagnostics)
        extracted = [normalize_row(row) for row in flows]
        if args.reference:
            with args.reference.open(newline="") as stream:
                reader = csv.DictReader(stream)
                if reader.fieldnames is None or len(reader.fieldnames) != len(set(reader.fieldnames)):
                    raise ValueError("Missing or duplicate CSV headers")
                reference = [normalize_row(row, args.timestamp_column, args.timestamp_format, args.timezone)
                             for row in reader]
            report = evaluate(extracted, reference, args.time_tolerance_usec, tolerances)
        else:
            report = {"status": "extraction_only", "extracted_count": len(extracted),
                      "limitation": "No independent reference supplied; no parity conclusion"}
        report.update({"pcap_sha256": sha256_file(args.pcap), "reference_sha256": sha256_file(args.reference) if args.reference else None,
                       "extraction_diagnostics": diagnostics,
                       "tool_sha256": sha256_file(__file__),
                       "extractor_sha256": sha256_file(Path(__file__).resolve().parents[1] / "sniffer/extractor.py"),
                       "reference_exporter_user_supplied": args.reference_exporter,
                       "reference_timestamp": {"column": args.timestamp_column, "format": args.timestamp_format,
                                               "timezone": args.timezone},
                       "termination_grace_seconds": args.termination_grace,
                       "scope": "Supplied capture/reference only; synthetic agreement is not original-capture parity",
                       "feature_units": "ports/protocol/counts dimensionless; duration/IAT microseconds; lengths payload bytes; rates per second"})
        if args.export_flows:
            args.export_flows.parent.mkdir(parents=True, exist_ok=True)
            with args.export_flows.open("x", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=list(extracted[0]) if extracted else ["Src IP", "Dst IP", *SELECTED_COLUMNS, "flow_start_usec", "flow_end_usec"])
                writer.writeheader()
                writer.writerows(extracted)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        with args.report.open("x") as stream:
            json.dump(report, stream, indent=2, allow_nan=False)
            stream.write("\n")
        print(json.dumps({"status": report["status"], "extracted_count": len(extracted), "report": str(args.report)}))
        return 0
    except (ValueError, KeyError, TypeError, OSError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
