# Converts sorted capture folders (<root>/<defense>/<results_ts>/<class_label>/<visit_name>/traces/direct-quic.csv)
# into WFlib-format .npz datasets matching datasets/CW.npz: X is (N, seq_len) signed relative time in
# seconds (positive = outgoing, negative = incoming), y is (N,) integer class labels.
import argparse
import csv
import json
import os
from glob import glob

import numpy as np

DEFENSES = ["undefended", "tamaraw", "front"]


def length_align(trace, seq_len):
    """Truncate or zero-pad a 1D trace to seq_len."""
    if len(trace) >= seq_len:
        return trace[:seq_len]
    return np.pad(trace, (0, seq_len - len(trace)), mode="constant", constant_values=0)


def find_trace_files(root, defense):
    """Yield (class_label, csv_path) for every visit under root/<defense>."""
    for results_dir in sorted(glob(os.path.join(root, defense, "*"))):
        if not os.path.isdir(results_dir):
            continue
        for class_dir in sorted(glob(os.path.join(results_dir, "*_root_*"))):
            class_label = os.path.basename(class_dir)
            for visit_dir in sorted(glob(os.path.join(class_dir, f"{class_label}-visit-*"))):
                csv_path = os.path.join(visit_dir, "traces", "direct-quic.csv")
                if os.path.isfile(csv_path):
                    yield class_label, csv_path


def load_trace(csv_path):
    """Read a direct-quic.csv trace and return a signed-time-in-seconds 1D array."""
    times = []
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            t = int(row["relative_time_ns"]) / 1e9
            sign = 1.0 if row["direction"] == "outgoing" else -1.0
            times.append(sign * t)
    return np.array(times, dtype=np.float64)


def build_dataset(root, defense, seq_len, out_path, label_map_out=None):
    samples = list(find_trace_files(root, defense))
    if not samples:
        print(f"No traces found under {root!r} for defense '{defense}', skipping.")
        return

    labels = sorted({class_label for class_label, _ in samples})
    label_to_idx = {label: i for i, label in enumerate(labels)}

    X = np.zeros((len(samples), seq_len), dtype=np.float64)
    y = np.zeros(len(samples), dtype=np.int64)

    for i, (class_label, csv_path) in enumerate(samples):
        trace = load_trace(csv_path)
        X[i] = length_align(trace, seq_len)
        y[i] = label_to_idx[class_label]

    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    np.savez(out_path, X=X, y=y)
    print(f"Saved {out_path}: X = {X.shape}, y = {y.shape}, classes = {len(labels)}")

    if label_map_out:
        with open(label_map_out, "w") as f:
            json.dump(label_to_idx, f, indent=2)
        print(f"Saved label map to {label_map_out}")


def main():
    parser = argparse.ArgumentParser(description="Build WFlib npz datasets from sorted capture folders")
    parser.add_argument("--root", required=True, help="Root folder containing undefended/tamaraw/front subfolders")
    parser.add_argument("--defenses", nargs="+", default=DEFENSES, choices=DEFENSES, help="Defenses to build")
    parser.add_argument("--seq_len", type=int, default=10000, help="Padded/truncated sequence length")
    parser.add_argument("--out_dir", default="./datasets", help="Directory to write <Defense>.npz files into")
    parser.add_argument("--label_maps", action="store_true", help="Also save <Defense>_labels.json label maps")
    args = parser.parse_args()

    for defense in args.defenses:
        out_path = os.path.join(args.out_dir, f"{defense.capitalize()}.npz")
        label_map_out = os.path.join(args.out_dir, f"{defense.capitalize()}_labels.json") if args.label_maps else None
        build_dataset(args.root, defense, args.seq_len, out_path, label_map_out)


if __name__ == "__main__":
    main()
