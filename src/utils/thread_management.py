#!/usr/bin/env python3
"""
Minimal Thread Control: Enforce single-threaded BLAS during parallel-heavy scikit-learn calls.

Problem: joblib workers × BLAS threads = nested parallelism → virtual memory bloat.
Solution: Wrap .fit()/.predict() calls with threadpoolctl to enforce 1 BLAS thread per worker.

Reference: https://threadpoolctl.readthedocs.io/
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Generator

try:
    from threadpoolctl import threadpool_limits
    _HAS_THREADPOOL = True
except ImportError:
    _HAS_THREADPOOL = False


@contextmanager
def limit_blas_threads(n_threads: int = 1) -> Generator[None, None, None]:
    """
    Context manager: Force BLAS/LAPACK to use exactly n_threads.

    If threadpoolctl unavailable, yields immediately (graceful degradation).

    Args:
        n_threads: Target thread count for BLAS libraries (default: 1).

    Yields:
        None

    Example:
        with limit_blas_threads(n_threads=1):
            gmm.fit(X)  # Uses exactly 1 BLAS thread
    """
    if not _HAS_THREADPOOL:
        yield
        return

    with threadpool_limits(limits=n_threads, user_api="blas"):
        yield
