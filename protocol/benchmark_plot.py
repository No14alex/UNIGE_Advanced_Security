from __future__ import annotations

import json
from pathlib import Path
import sys

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from protocol import benchmark_metrics


DEFAULT_INPUT = benchmark_metrics.DEFAULT_OUTPUT_JSON
DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / "security_report" / "benchmark_timing_chart.png"


def load_report(path: Path = DEFAULT_INPUT) -> dict:
    return json.loads(path.read_text())


def generate_timing_bar_chart(
    input_path: Path = DEFAULT_INPUT,
    output_path: Path = DEFAULT_OUTPUT,
) -> Path:
    """
    Generate a bar chart comparing classical and PQ execution times.

    Requires:
    - matplotlib

    Run benchmark_metrics.py first so that benchmark_results.json exists.
    """
    import matplotlib.pyplot as plt

    report = load_report(input_path)
    classical = report["classical_timing"]
    pq = report["pq_timing"]

    labels = [
        "Keygen",
        "Exchange/Encap",
        "Decap/Peer",
        "Sign",
        "Verify",
        "Handshake",
    ]
    classical_values = [
        classical["keygen_ms"],
        classical["encaps_or_exchange_ms"],
        classical["decaps_or_exchange_ms"],
        classical["sign_ms"],
        classical["verify_ms"],
        classical["full_handshake_ms"],
    ]
    pq_values = [
        pq["keygen_ms"],
        pq["encaps_or_exchange_ms"],
        pq["decaps_or_exchange_ms"],
        pq["sign_ms"],
        pq["verify_ms"],
        pq["full_handshake_ms"],
    ]

    x = range(len(labels))
    width = 0.36

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar([i - width / 2 for i in x], classical_values, width=width, label="Classical", color="#6c8ebf")
    ax.bar([i + width / 2 for i in x], pq_values, width=width, label="Post-Quantum", color="#d79b00")

    ax.set_title("Classical vs Post-Quantum Timing Comparison")
    ax.set_ylabel("Average execution time (ms)")
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, rotation=20)
    ax.legend()
    ax.grid(axis="y", linestyle="--", alpha=0.4)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(output_path, dpi=200)
    plt.close(fig)
    return output_path


if __name__ == "__main__":
    output = generate_timing_bar_chart()
    print(f"Timing bar chart written to: {output}")
