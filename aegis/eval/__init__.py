"""
aegis.eval — Detection evaluation, coverage matrix, noise metrics, and TTT.

Exported classes:
- :class:`CoverageAnalyzer`
- :class:`NoiseAnalyzer`
- :class:`FPAnalyzer`
- :class:`TTTAnalyzer`
- :class:`ResilienceTester`
"""

from aegis.eval.coverage import CoverageAnalyzer
from aegis.eval.noise import NoiseAnalyzer
from aegis.eval.false_positives import FPAnalyzer
from aegis.eval.ttt import TTTAnalyzer, ResilienceTester

__all__ = [
    "CoverageAnalyzer",
    "NoiseAnalyzer",
    "FPAnalyzer",
    "TTTAnalyzer",
    "ResilienceTester",
]
