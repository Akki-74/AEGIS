"""
Custom pySigma processing pipeline — Sysmon fields → ECS.

Maps Microsoft Sysmon event-log field names to the Elastic Common
Schema (ECS) equivalents so that Sigma rules authored with Sysmon
field names compile correctly against Elasticsearch / OpenSearch
indices that use the ECS naming convention (e.g. Winlogbeat 8+, Elastic
Agent, or any other ECS-normalised pipeline).

Usage::

    from aegis.pipelines.sysmon_ecs import sysmon_ecs_pipeline
    pipeline = sysmon_ecs_pipeline()

The returned :class:`sigma.processing.pipeline.ProcessingPipeline` can
be passed to any pySigma backend's ``convert_rule`` method.
"""

from __future__ import annotations

try:
    from sigma.processing.conditions import LogsourceCondition  # type: ignore[import-untyped]
    from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline  # type: ignore[import-untyped]
    from sigma.processing.transformations import (  # type: ignore[import-untyped]
        FieldMappingTransformation,
        ChangeLogsourceTransformation,
    )
    _SIGMA_AVAILABLE = True
except ImportError:
    _SIGMA_AVAILABLE = False
    LogsourceCondition = object  # type: ignore[misc,assignment]
    ProcessingItem = object  # type: ignore[misc,assignment]
    ProcessingPipeline = object  # type: ignore[misc,assignment]
    FieldMappingTransformation = object  # type: ignore[misc,assignment]
    ChangeLogsourceTransformation = object  # type: ignore[misc,assignment]


# ── Field-mapping tables ──────────────────────────────────────────────

# General Sysmon → ECS field mappings applicable to most event types.
_SYSMON_GENERAL_FIELD_MAP: dict[str, str] = {
    "Image": "process.executable",
    "OriginalFileName": "process.pe.original_file_name",
    "CommandLine": "process.command_line",
    "ParentImage": "process.parent.executable",
    "ParentCommandLine": "process.parent.command_line",
    "User": "user.name",
    "SourceIp": "source.ip",
    "DestinationIp": "destination.ip",
    "DestinationPort": "destination.port",
    "TargetFilename": "file.path",
    "ProcessGuid": "process.entity_id",
    "ParentProcessGuid": "process.parent.entity_id",
    "LogonId": "winlog.logon.id",
    "ProcessId": "process.pid",
    "ParentProcessId": "process.parent.pid",
    "CurrentDirectory": "process.working_directory",
    "IntegrityLevel": "winlog.event_data.IntegrityLevel",
    "Company": "process.pe.company",
    "Description": "process.pe.description",
    "Product": "process.pe.product",
    "FileVersion": "process.pe.file_version",
}

# Hash sub-fields.  Sysmon reports a composite ``Hashes`` string; after
# extraction these individual fields may appear.
_SYSMON_HASH_FIELD_MAP: dict[str, str] = {
    "md5": "hash.md5",
    "sha1": "hash.sha1",
    "sha256": "hash.sha256",
    "Hashes": "hash.value",
}

# Event ID 10 (ProcessAccess) specific mappings.
_SYSMON_PROCESS_ACCESS_FIELD_MAP: dict[str, str] = {
    "SourceImage": "process.executable",
    "TargetImage": "winlog.event_data.TargetImage",
    "GrantedAccess": "winlog.event_data.GrantedAccess",
    "SourceProcessGuid": "process.entity_id",
    "TargetProcessGuid": "winlog.event_data.TargetProcessGuid",
    "SourceProcessId": "process.pid",
    "TargetProcessId": "winlog.event_data.TargetProcessId",
    "CallTrace": "winlog.event_data.CallTrace",
}

# Event ID 3 (NetworkConnect) specific mappings.
_SYSMON_NETWORK_FIELD_MAP: dict[str, str] = {
    "SourcePort": "source.port",
    "DestinationHostname": "destination.domain",
    "Protocol": "network.transport",
    "SourceHostname": "source.domain",
    "Initiated": "winlog.event_data.Initiated",
}


# ── Log-source mappings ──────────────────────────────────────────────

def _logsource_condition(category: str | None = None) -> LogsourceCondition:
    """Build a :class:`LogsourceCondition` for Sysmon."""
    kwargs: dict[str, str] = {"product": "windows"}
    if category:
        kwargs["category"] = category
    return LogsourceCondition(**kwargs)


# ── Pipeline factory ─────────────────────────────────────────────────

def sysmon_ecs_pipeline() -> ProcessingPipeline:
    """Return a pySigma :class:`ProcessingPipeline` for Sysmon → ECS.

    The pipeline contains:

    1. **General field mappings** — applied unconditionally to all
       Windows/Sysmon rules.
    2. **Hash field mappings** — maps individual hash algorithm fields.
    3. **ProcessAccess field mappings** — applied when the log-source
       category is ``process_access`` (Sysmon Event ID 10).
    4. **NetworkConnect field mappings** — applied when the log-source
       category is ``network_connection`` (Sysmon Event ID 3).
    5. **Log-source transformations** — rewrites Sigma log-source
       declarations to match ECS index patterns.

    Returns
    -------
    ProcessingPipeline
        Ready-to-use pipeline instance.
    """
    items: list[ProcessingItem] = [
        # ── 1. General field mapping (all Windows/Sysmon rules) ───────
        ProcessingItem(
            identifier="aegis_sysmon_ecs_general_fieldmap",
            transformation=FieldMappingTransformation(
                mapping=_SYSMON_GENERAL_FIELD_MAP,
            ),
            rule_conditions=[
                _logsource_condition(),
            ],
        ),
        # ── 2. Hash field mapping ─────────────────────────────────────
        ProcessingItem(
            identifier="aegis_sysmon_ecs_hash_fieldmap",
            transformation=FieldMappingTransformation(
                mapping=_SYSMON_HASH_FIELD_MAP,
            ),
            rule_conditions=[
                _logsource_condition(),
            ],
        ),
        # ── 3. ProcessAccess (Event ID 10) field mapping ──────────────
        ProcessingItem(
            identifier="aegis_sysmon_ecs_processaccess_fieldmap",
            transformation=FieldMappingTransformation(
                mapping=_SYSMON_PROCESS_ACCESS_FIELD_MAP,
            ),
            rule_conditions=[
                _logsource_condition(category="process_access"),
            ],
        ),
        # ── 4. NetworkConnect (Event ID 3) field mapping ──────────────
        ProcessingItem(
            identifier="aegis_sysmon_ecs_network_fieldmap",
            transformation=FieldMappingTransformation(
                mapping=_SYSMON_NETWORK_FIELD_MAP,
            ),
            rule_conditions=[
                _logsource_condition(category="network_connection"),
            ],
        ),
        # ── 5. Log-source rewrites ────────────────────────────────────
        # Process creation (Event ID 1)
        ProcessingItem(
            identifier="aegis_sysmon_ecs_logsource_process_creation",
            transformation=ChangeLogsourceTransformation(
                category="process_creation",
                product="windows",
                service="sysmon",
            ),
            rule_conditions=[
                _logsource_condition(category="process_creation"),
            ],
        ),
        # File creation / modification (Event ID 11)
        ProcessingItem(
            identifier="aegis_sysmon_ecs_logsource_file_event",
            transformation=ChangeLogsourceTransformation(
                category="file_event",
                product="windows",
                service="sysmon",
            ),
            rule_conditions=[
                _logsource_condition(category="file_event"),
            ],
        ),
        # Network connection (Event ID 3)
        ProcessingItem(
            identifier="aegis_sysmon_ecs_logsource_network_connection",
            transformation=ChangeLogsourceTransformation(
                category="network_connection",
                product="windows",
                service="sysmon",
            ),
            rule_conditions=[
                _logsource_condition(category="network_connection"),
            ],
        ),
        # Registry events (Event ID 13)
        ProcessingItem(
            identifier="aegis_sysmon_ecs_logsource_registry",
            transformation=ChangeLogsourceTransformation(
                category="registry_set",
                product="windows",
                service="sysmon",
            ),
            rule_conditions=[
                _logsource_condition(category="registry_set"),
            ],
        ),
        # Image/DLL loaded (Event ID 7)
        ProcessingItem(
            identifier="aegis_sysmon_ecs_logsource_image_load",
            transformation=ChangeLogsourceTransformation(
                category="image_load",
                product="windows",
                service="sysmon",
            ),
            rule_conditions=[
                _logsource_condition(category="image_load"),
            ],
        ),
        # Process access (Event ID 10)
        ProcessingItem(
            identifier="aegis_sysmon_ecs_logsource_process_access",
            transformation=ChangeLogsourceTransformation(
                category="process_access",
                product="windows",
                service="sysmon",
            ),
            rule_conditions=[
                _logsource_condition(category="process_access"),
            ],
        ),
    ]

    if not _SIGMA_AVAILABLE:
        return None  # pySigma not installed

    return ProcessingPipeline(
        name="AEGIS Sysmon → ECS Pipeline",
        priority=20,  # Run before backend-specific pipelines.
        items=items,
    )
