"""
AEGIS pySigma pipelines sub-package.

Provides:
    - ``sysmon_ecs_pipeline`` — custom pySigma ProcessingPipeline mapping
      Sysmon field names to ECS (Elastic Common Schema).
    - ``RuleCompiler`` — batch-compile Sigma rules through pySigma backends.
"""

from aegis.pipelines.sysmon_ecs import sysmon_ecs_pipeline
from aegis.pipelines.compile import RuleCompiler

__all__ = ["sysmon_ecs_pipeline", "RuleCompiler"]
