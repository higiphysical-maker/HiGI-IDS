#!/usr/bin/env python3
"""
HiGI IDS — Unified Entry Point.

Single command-line interface for all HiGI operations:

    python main.py train  --source Monday.pcap     --bundle models/baseline.pkl
    python main.py detect --source Wednesday.pcap  --bundle models/baseline.pkl
    python main.py report --results data/processed/wednesday_results.csv --bundle models/baseline_model.pkl --output-dir reports/forensic_wednesday/ 
    python main.py run    --source Wednesday.pcap  --bundle models/baseline.pkl

Modes:
    train  — Ingest a benign PCAP, build feature matrix, train the four-tier
             detection engine (BallTree + GMM + IForest + Velocity Bypass),
             and persist an ArtifactBundle to disk.

    detect — Load an ArtifactBundle, ingest a test PCAP, run inference, and
             write a results CSV with anomaly flags, severity, and forensic
             evidence for every time window.

    report — Read an existing results CSV and generate a professional
             forensic report (PDF + Markdown) with incident clustering,
             MITRE ATT&CK mapping, and data-quality heuristics.

    run    — Shorthand for detect followed immediately by report.  Produces
             the CSV, PDF, and Markdown in a single command.

Design principles:
    • Zero magic numbers — every threshold is read from config.yaml via
      src/config.py → HiGISettings.
    • No business logic — this file contains only CLI glue.  All physics,
      ML, and forensic logic lives in the src/ modules.
    • Micro-batch ready — the DetectionPipeline processes data in chunks,
      so swapping the PCAP reader for a live socket reader tomorrow requires
      changing only one function in src/ingestion/.
    • Idempotent — all outputs are deterministic for a given (source, bundle)
      pair; running the same command twice produces identical results.

Usage examples:
    # Establish Monday baseline:
    python main.py train \\
        --source data/raw/Monday.pcap \\
        --bundle models/baseline_monday.pkl

    # Detect on Wednesday with verbose logging:
    python main.py detect \\
        --source data/raw/Wednesday.pcap \\
        --bundle models/baseline_monday.pkl \\
        --output data/processed/wednesday_results.csv \\
        --verbose

    # Generate forensic report with strict filters:
    python main.py report \\
        --results data/processed/wednesday_results.csv \\
        --confidence 0.90 \\
        --min-anomalies 5 \\
        --output-dir reports/

    # Full pipeline in one command (detect + report):
    python main.py run \\
        --source data/raw/Wednesday.pcap \\
        --bundle models/baseline_monday.pkl \\
        --output-dir data/processed/ \\
        --confidence 0.75

    # Use a custom config file:
    python main.py train --source Monday.pcap --bundle models/b.pkl \\
        --config configs/production.yaml

Author: Blue Team Engineering
Version: 4.0.0
"""

from __future__ import annotations

import os
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
os.environ["OPENBLAS_NUM_THREADS"] = "1"

import argparse
import gc
import json
import logging
import logging.handlers
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path
from src.orchestrator import TrainingError, TrainingPipeline

# Project root on PYTHONPATH so `src.*` imports resolve correctly.
_ROOT = Path(__file__).parent
sys.path.insert(0, str(_ROOT))

from src.config import HiGISettings, load_settings


# ============================================================================
# LOGGING SETUP
# ============================================================================

def _configure_logging(settings: HiGISettings, verbose: bool = False) -> logging.Logger:
    """
    Configure the root logger from HiGISettings.

    If verbose=True the effective level is forced to DEBUG regardless of the
    config file value.  Log files rotate at 10 MB by default.

    Args:
        settings: Loaded HiGISettings from config.yaml.
        verbose: Override log level to DEBUG when True.

    Returns:
        Root logger ready for use.
    """
    cfg = settings.logging
    level_name = "DEBUG" if verbose else cfg.level.upper()
    level = getattr(logging, level_name, logging.INFO)

    formatter = logging.Formatter(fmt=cfg.format, datefmt=cfg.date_format)

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()

    # Console handler (always enabled)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root.addHandler(console_handler)

    # Rotating file handler (optional)
    if cfg.file_enabled:
        log_dir = Path(settings.paths.logs_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / f"higi_{datetime.now().strftime('%Y%m%d')}.log"
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=cfg.file_max_bytes,
            backupCount=cfg.file_backup_count,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)

    return logging.getLogger("higi")


# ============================================================================
# MODE: TRAIN
# ============================================================================

def run_train(args: argparse.Namespace, settings: HiGISettings) -> int:
    """
        Training pipeline: PCAP → feature matrix → HiGIEngine → ArtifactBundle.

        Reads all tunable parameters (chunk size, HiGI thresholds, GMM components)
        from HiGISettings derived from config.yaml.

        Args:
            args: Parsed CLI arguments (source, bundle).
            settings: Loaded HiGISettings.

        Returns:
            Exit code (0 = success, 1 = failure).
    """
        

    logger = logging.getLogger("higi.train")

    source = Path(args.source)
    bundle_path = Path(args.bundle)

    if not source.exists():
        logger.error(f"Source PCAP not found: {source}")
        return 1

    logger.info("=" * 80)
    logger.info("HiGI TRAINING MODE")
    logger.info("=" * 80)
    logger.info(f"  Source PCAP : {source}")
    logger.info(f"  Output Bundle: {bundle_path}")
    logger.info("")

    try:
        # Extract configuration from loaded settings (dependency injection)
        higi_config = settings.to_higi_config()
        
        logger.info("Injected Configuration:")
        logger.info(f"  Engine config: {higi_config.use_bayesian_gmm=}, "
                    f"{higi_config.gmm_score_normalization_method=}, "
                    f"{higi_config.per_feature_thresholds=}")
        logger.info(f"  Augmentation: noise_scale={settings.training.augmentation_noise_scale}, "
                    f"synthetic_fraction={settings.training.augmentation_synthetic_fraction}")
        
        # Initialize pipeline with all configuration injected
        pipeline = TrainingPipeline(
            pcap_path=str(source),
            output_bundle_path=str(bundle_path),
            chunks=settings.ingestion.chunk_size,
            cores=settings.ingestion.n_jobs,
            higi_config=higi_config,
            augmentation_noise_scale=settings.training.augmentation_noise_scale,
            augmentation_synthetic_fraction=settings.training.augmentation_synthetic_fraction,
        )
        bundle = pipeline.run()
        bundle.save(str(bundle_path))
        logger.info(f"  ✓ Training complete. Bundle saved to {bundle_path}")

        return 0
    except TrainingError as exc:
        print(f"\n[!] Error en el Pipeline de Entrenamiento: {exc}")
        return 1
    except Exception as exc:
        print(f"\n[!] Error inesperado: {exc}")
        return 1
    


# ============================================================================
# MODE: DETECT
# ============================================================================

def run_detect(args: argparse.Namespace, settings: HiGISettings) -> int:
    """
    Detection mode: delegate to DetectionPipeline.

    Args:
        args: Parsed CLI arguments (source, bundle, output).
        settings: Loaded HiGISettings.

    Returns:
        Exit code (0 = success, 1 = failure).
    """
    from src.orchestrator import DetectionPipeline, DetectionError

    logger = logging.getLogger("higi.detect")

    source = Path(args.source)
    bundle_path = Path(args.bundle)
    output_path = Path(getattr(args, "output", None) or _default_results_path(source, settings))

    if not source.exists():
        logger.error(f"Source PCAP not found: {source}")
        return 1
    if not bundle_path.exists():
        logger.error(f"Bundle not found: {bundle_path}")
        return 1

    output_path.parent.mkdir(parents=True, exist_ok=True)

    logger.info("=" * 80)
    logger.info("HiGI DETECTION MODE")
    logger.info("=" * 80)
    logger.info(f"  Source PCAP  : {source}")
    logger.info(f"  Bundle       : {bundle_path}")
    logger.info(f"  Output CSV   : {output_path}")
    logger.info("")

    try:
        pipeline = DetectionPipeline(
            pcap_path=str(source),
            bundle_path=str(bundle_path),
            output_results_path=str(output_path),
            settings=settings,
        )
        pipeline.run()

        if hasattr(args, "_results_path_out"):
            args._results_path_out = str(output_path)

        return 0

    except DetectionError as exc:
        logger.error(f"Detection pipeline failed: {exc}")
        return 1
    except Exception as exc:
        logger.error(f"Unexpected detection error: {exc}")
        logger.debug(traceback.format_exc())
        return 1



# ============================================================================
# MODE: REPORT
# ============================================================================

def run_report(args: argparse.Namespace, settings: HiGISettings) -> int:
    """
    Forensic report generation: results CSV → PDF + Markdown.

    All filtering parameters (confidence, min_anomalies, min_duration) default
    to values from config.yaml → forensic section and can be overridden via CLI.

    Args:
        args: Parsed CLI arguments (results, output_dir, confidence, etc.).
        settings: Loaded HiGISettings.

    Returns:
        Exit code (0 = success, 1 = failure).
    """
    from src.analysis.forensic_engine import (
        HiGIForensicEngine,
        generate_forensic_pdf,
        generate_markdown_report,
    )
    from src.orchestrator import ArtifactBundle

    logger = logging.getLogger("higi.report")

    results_path = Path(args.results)
    output_dir = Path(
        getattr(args, "output_dir", None) or settings.paths.reports_dir
    )

    #Load the trained bundle for forensic attribution (optional but recommended)
    bundle = None
    if hasattr(args, "bundle") and args.bundle:
        bundle_path = Path(args.bundle)
        if bundle_path.exists():
            try:
                bundle = ArtifactBundle.load(bundle_path)
                logger.info(f"[✓] PCA Metadata loaded from {bundle_path}")
            except Exception as e:
                logger.warning(f"Could not load ArtifactBundle: {e}. Degrading to CSV-only mode.")
    
    if not results_path.exists():
        logger.error(f"Results CSV not found: {results_path}")
        return 1

    # Resolve filter parameters: CLI overrides config defaults
    confidence = getattr(args, "confidence", None) or settings.forensic.default_confidence_filter
    min_anomalies = getattr(args, "min_anomalies", None) or settings.forensic.default_min_anomalies
    min_duration = getattr(args, "min_duration", None) or settings.forensic.default_min_duration_seconds
    sigma_min = settings.forensic.sigma_culprit_min

    output_dir.mkdir(parents=True, exist_ok=True)
    base_name = results_path.stem
    pdf_out = output_dir / f"{base_name}_FORENSIC.pdf"
    md_out = output_dir / f"{base_name}_FORENSIC.md"

    if not results_path.exists():
        logger.error(f"Results CSV not found: {results_path}")
        return 1

    output_dir.mkdir(parents=True, exist_ok=True)
    base_name = results_path.stem
    pdf_out = output_dir / f"{base_name}_FORENSIC.pdf"
    md_out = output_dir / f"{base_name}_FORENSIC.md"

    logger.info("=" * 80)
    logger.info("HiGI FORENSIC REPORT MODE")
    logger.info("=" * 80)
    logger.info(f"  Results CSV  : {results_path}")
    logger.info(f"  Output dir   : {output_dir}")
    logger.info(f"  Confidence   : ≥ {confidence:.0%}")
    logger.info(f"  Min anomalies: {min_anomalies}")
    logger.info(f"  Min duration : {min_duration}s")
    logger.info("")

    try:
        # ForensicEnginev2 reads the CSV and clusters incidents internally.
        engine = HiGIForensicEngine(
            settings=settings, 
            results_path=results_path, 
            bundle=bundle
        )
        logger.info(f"[INFO] Clustering incidents (Debounce: {settings.forensic.debounce_seconds}s)...")

        logger.info(
            f"[INFO] Clustering with {settings.forensic.debounce_seconds:.0f}s debounce…"
        )
        data_drops = engine.detect_data_drops()

        logger.info(f"  ✓ {len(data_drops)} data gaps detected")

        filter_kwargs = {
            "confidence_filter": confidence,
            "min_anomalies_per_incident": min_anomalies,
            "min_duration_seconds": min_duration,
            "sigma_culprit_min": sigma_min,
        }

        stats = engine.generate_summary_stats(**filter_kwargs)
        capture_health = stats.get("capture_health", {})

        logger.info(
            f"  ✓ Quality score: "
            f"{capture_health.get('capture_quality_score', 0):.1%}"
        )

        # Generate visualizations for the Markdown report
        logger.info("[VIS] Generating Physical Stress Radar and Timeline...")
        try:
            visual_paths = engine.generate_visuals(output_dir)
            logger.info(f"  ✓ Timeline plot: {visual_paths.get('timeline_plot', 'N/A')}")
            logger.info(f"  ✓ Distribution plot: {visual_paths.get('distribution_plot', 'N/A')}")
        except Exception as vis_exc:
            logger.warning(f"Failed to generate visualizations: {vis_exc}")
            visual_paths = None

        # PDF report
        logger.info(f"[PDF] Generating {pdf_out.name}…")
        generate_forensic_pdf(engine, str(pdf_out), **filter_kwargs)
        logger.info(f"  ✓ {pdf_out.stat().st_size / 1024:.1f} KB")

        # Markdown report with visual evidence
        logger.info(f"[MD ] Generating {md_out.name}…")
        generate_markdown_report(engine, str(md_out), visual_paths=visual_paths, **filter_kwargs)
        logger.info(f"  ✓ {md_out.stat().st_size / 1024:.1f} KB")

        logger.info("")
        logger.info("[SUMMARY]")
        logger.info("-" * 80)
        logger.info(f"  Total anomalies  : {stats.get('total_anomalies', 0)}")
        logger.info(f"  ✓ Quality Score   : {stats.get('capture_health', {}).get('capture_quality_score', 0):.1%}")
        logger.info(f"  ✓ Total Incidents : {stats.get('total_incidents', 0)}")
        logger.info(f"  ✓ Max Severity    : {stats.get('max_severity', 0)}/3")
        logger.info("=" * 80)
        logger.info(
            f"  Max / Avg severity: "
            f"{stats.get('max_severity', 0)}/3 / "
            f"{stats.get('avg_severity', 0):.2f}/3"
        )
        logger.info(f"  Data drops       : {stats.get('data_drops_detected', 0)}")

        logger.info("=" * 80)
        logger.info("✓ REPORT GENERATION COMPLETE")
        logger.info(f"  PDF  : {pdf_out}")
        logger.info(f"  MD   : {md_out}")
        logger.info("=" * 80)
        return 0

    except Exception as exc:
        logger.error(f"Report generation failed: {exc}")
        logger.debug(traceback.format_exc())
        return 1


# ============================================================================
# MODE: RUN (detect + report in one shot)
# ============================================================================

def run_pipeline(args: argparse.Namespace, settings: HiGISettings) -> int:
    """
    Full pipeline shorthand: detect → report.

    Derives the intermediate results CSV path from --output-dir and the source
    PCAP stem so intermediate files are always predictably named.

    Args:
        args: Parsed CLI arguments.
        settings: Loaded HiGISettings.

    Returns:
        Exit code (0 = success, 1 = failure).
    """
    logger = logging.getLogger("higi.run")

    output_dir = Path(getattr(args, "output_dir", None) or settings.paths.results_dir)
    source_stem = Path(args.source).stem
    results_csv = output_dir / f"{source_stem}_results.csv"

    # Inject the computed output path so run_detect knows where to write.
    args.output = str(results_csv)
    args._results_path_out = str(results_csv)

    logger.info("=" * 80)
    logger.info("HiGI FULL PIPELINE (detect + report)")
    logger.info("=" * 80)

    rc = run_detect(args, settings)
    if rc != 0:
        return rc

    # Wire the report step to the just-written CSV.
    args.results = str(results_csv)
    args.output_dir = str(output_dir)
    return run_report(args, settings)


# ============================================================================
# CLI PARSER
# ============================================================================

def _build_parser() -> argparse.ArgumentParser:
    """Construct and return the top-level argument parser."""
    parser = argparse.ArgumentParser(
        prog="python main.py",
        description="HiGI IDS — Physical-layer Network Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument(
        "--config",
        type=str,
        default=None,
        metavar="PATH",
        help="Path to config YAML (default: config.yaml in project root).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Force DEBUG-level logging.",
    )

    subparsers = parser.add_subparsers(dest="mode", required=True)

    # ── train ──────────────────────────────────────────────────────────────
    p_train = subparsers.add_parser(
        "train",
        help="Establish baseline from a benign PCAP.",
    )
    p_train.add_argument(
        "--source", required=True, metavar="PCAP",
        help="Path to benign baseline PCAP file.",
    )
    p_train.add_argument(
        "--bundle", required=True, metavar="PKL",
        help="Output path for trained ArtifactBundle (.pkl).",
    )

    # ── detect ─────────────────────────────────────────────────────────────
    p_detect = subparsers.add_parser(
        "detect",
        help="Run anomaly detection on a test PCAP.",
    )
    p_detect.add_argument(
        "--source", required=True, metavar="PCAP",
        help="Path to test PCAP file.",
    )
    p_detect.add_argument(
        "--bundle", required=True, metavar="PKL",
        help="Path to trained ArtifactBundle (.pkl).",
    )
    p_detect.add_argument(
        "--output", default=None, metavar="CSV",
        help="Output results CSV (default: <results_dir>/<source_stem>_results.csv).",
    )

    # ── report ─────────────────────────────────────────────────────────────
    p_report = subparsers.add_parser(
        "report",
        help="Generate PDF + Markdown forensic report from a results CSV.",
    )
    p_report.add_argument(
        "--results", required=True, metavar="CSV",
        help="Path to detection results CSV (output of detect).",
    )
    p_report.add_argument(
        "--output-dir", default=None, metavar="DIR",
        help="Directory for PDF and Markdown outputs (default: from config.yaml).",
    )
    p_report.add_argument(
        "--confidence", type=float, default=None, metavar="FLOAT",
        help="Minimum incident confidence to report (0.0–1.0; default from config.yaml).",
    )
    p_report.add_argument(
        "--min-anomalies", type=int, default=None, metavar="N",
        help="Minimum anomalies per incident (default from config.yaml).",
    )
    p_report.add_argument(
        "--min-duration", type=float, default=None, metavar="SEC",
        help="Minimum incident duration in seconds (default from config.yaml).",
    )

    p_report.add_argument(
        "--bundle", type = Path,
        help="Path to the trained ArtifactBundle (.pkl)."
    )

    # ── run ────────────────────────────────────────────────────────────────
    p_run = subparsers.add_parser(
        "run",
        help="Full pipeline: detect + report in one command.",
    )
    p_run.add_argument(
        "--source", required=True, metavar="PCAP",
        help="Path to test PCAP file.",
    )
    p_run.add_argument(
        "--bundle", required=True, metavar="PKL",
        help="Path to trained ArtifactBundle (.pkl).",
    )
    p_run.add_argument(
        "--output-dir", default=None, metavar="DIR",
        help="Directory for all outputs (CSV, PDF, MD; default from config.yaml).",
    )
    p_run.add_argument(
        "--confidence", type=float, default=None, metavar="FLOAT",
        help="Min incident confidence for report (default from config.yaml).",
    )
    p_run.add_argument(
        "--min-anomalies", type=int, default=None, metavar="N",
        help="Min anomalies per incident for report (default from config.yaml).",
    )
    p_run.add_argument(
        "--min-duration", type=float, default=None, metavar="SEC",
        help="Min incident duration in seconds for report (default from config.yaml).",
    )

    return parser


def _default_results_path(source: Path, settings: HiGISettings) -> str:
    """Derive a sensible default results CSV path from source stem + config."""
    return str(Path(settings.paths.results_dir) / f"{source.stem}_results.csv")


# ============================================================================
# ENTRY POINT
# ============================================================================

def main() -> int:
    """
    Parse arguments, load settings, dispatch to the appropriate mode handler.

    Returns:
        Exit code passed to sys.exit().
    """
    parser = _build_parser()
    args = parser.parse_args()

    # Load settings first (needed by logging setup)
    try:
        settings = load_settings(args.config)
    except ValueError as exc:
        # config.yaml validation failure — print directly since logger not ready
        print(f"[ERROR] Configuration error: {exc}", file=sys.stderr)
        return 1

    _configure_logging(settings, verbose=args.verbose)
    logger = logging.getLogger("higi")
    logger.info(f"HiGI IDS v4.0  |  mode={args.mode}")

    dispatch = {
        "train": run_train,
        "detect": run_detect,
        "report": run_report,
        "run": run_pipeline,
    }

    handler = dispatch.get(args.mode)
    if handler is None:
        parser.print_help()
        return 1

    try:
        return handler(args, settings)
    except KeyboardInterrupt:
        logger.warning("Interrupted by user.")
        return 130
    except Exception as exc:
        logger.error(f"Fatal error: {exc}")
        logger.debug(traceback.format_exc())
        return 1


if __name__ == "__main__":
    sys.exit(main())
