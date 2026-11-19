"""
Test Suite: Expanded Multi-Tier DLP Benchmark & Confusion Matrix Validation.
Validates detection metrics across:
1. Development Set (40 samples)
2. Calibration Set (40 samples)
3. Held-Out Evaluation Set (60 samples)
Total: 140 synthetic enterprise samples.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from benchmarks.dlp_benchmark import (
    CALIBRATION_DATASET,
    DEVELOPMENT_DATASET,
    HELD_OUT_EVALUATION_DATASET,
    evaluate_dataset,
)
from src.proxy_gateway import inspect_text_for_threats


def test_development_dataset_metrics():
    """Evaluates development dataset: asserts zero false positives and high recall."""
    results = evaluate_dataset(DEVELOPMENT_DATASET, inspect_text_for_threats)
    print("\n--- DEVELOPMENT DATASET RESULTS ---")
    print(f"Total: {results['total']} | TP: {results['tp']} | FP: {results['fp']} | TN: {results['tn']} | FN: {results['fn']}")
    print(f"Precision: {results['precision']:.4f} (95% CI: {results['precision_ci_95']})")
    print(f"Recall:    {results['recall']:.4f} (95% CI: {results['recall_ci_95']})")
    print(f"F1 Score:  {results['f1']:.4f}")
    print(f"FPR:       {results['fpr']:.4f}")

    assert results["fp"] == 0, f"False positives detected: {results['false_positives']}"
    assert results["precision"] == 1.0
    assert results["recall"] >= 0.95
    assert results["f1"] >= 0.97


def test_calibration_dataset_metrics():
    """Evaluates calibration dataset containing difficult borderlines and obfuscations."""
    results = evaluate_dataset(CALIBRATION_DATASET, inspect_text_for_threats)
    print("\n--- CALIBRATION DATASET RESULTS ---")
    print(f"Total: {results['total']} | TP: {results['tp']} | FP: {results['fp']} | TN: {results['tn']} | FN: {results['fn']}")
    print(f"Precision: {results['precision']:.4f} (95% CI: {results['precision_ci_95']})")
    print(f"Recall:    {results['recall']:.4f} (95% CI: {results['recall_ci_95']})")
    print(f"F1 Score:  {results['f1']:.4f}")
    print(f"FPR:       {results['fpr']:.4f}")

    assert results["fp"] == 0, f"False positives on borderlines: {results['false_positives']}"
    assert results["precision"] == 1.0
    assert results["recall"] >= 0.95
    assert results["f1"] >= 0.97


def test_held_out_evaluation_dataset_metrics():
    """
    BLIND EVALUATION: Evaluates held-out evaluation dataset (60 samples).
    Detector was NOT tuned against this dataset.
    Asserts precision >= 0.98, recall >= 0.95, and F1 >= 0.97.
    """
    results = evaluate_dataset(HELD_OUT_EVALUATION_DATASET, inspect_text_for_threats)
    print("\n--- HELD-OUT EVALUATION DATASET RESULTS (BLIND) ---")
    print(f"Total: {results['total']} | TP: {results['tp']} | FP: {results['fp']} | TN: {results['tn']} | FN: {results['fn']}")
    print(f"Precision: {results['precision']:.4f} (95% CI: {results['precision_ci_95']})")
    print(f"Recall:    {results['recall']:.4f} (95% CI: {results['recall_ci_95']})")
    print(f"F1 Score:  {results['f1']:.4f}")
    print(f"Accuracy:  {results['accuracy']:.4f} (95% CI: {results['accuracy_ci_95']})")
    print(f"FPR:       {results['fpr']:.4f}")

    # Display Confusion Matrix
    print("\nCONFUSION MATRIX:")
    print("                Actual Positive    Actual Negative")
    print(f"Pred Positive   {results['tp']:<18} {results['fp']:<18}")
    print(f"Pred Negative   {results['fn']:<18} {results['tn']:<18}")

    # Display per-category breakdown
    print("\nPER-CATEGORY BREAKDOWN:")
    for cat, counts in results["per_category"].items():
        print(f"  - {cat:<24}: TP={counts['tp']} FP={counts['fp']} TN={counts['tn']} FN={counts['fn']}")

    if results["false_negatives"]:
        print(f"\nFalse Negatives to investigate: {results['false_negatives']}")
    if results["false_positives"]:
        print(f"\nFalse Positives to investigate: {results['false_positives']}")

    assert results["fp"] == 0, f"Unexpected false positives: {results['false_positives']}"
    assert results["precision"] == 1.0
    assert results["recall"] >= 0.95
    assert results["f1"] >= 0.97
