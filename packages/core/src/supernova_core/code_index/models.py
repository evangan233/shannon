from collections import Counter

from pydantic import BaseModel, ConfigDict, Field
from enum import Enum

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from supernova_core.code_index.parameter_models import ParameterPropagationGraph, SinkCallSite, SourcePoint


class Verdict(str, Enum):
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    RECLASSIFIED = "reclassified"
    NEEDS_REVIEW = "needs_review"


class EntryPointSource(str, Enum):
    CODE_INDEX = "code_index"
    LLM_DISCOVERY = "llm_discovery"


class FuncBlock(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str  # "file_path:function_name:start_line"
    file_path: str
    function_name: str
    start_line: int
    end_line: int
    source_code: str
    parameters: list[str]
    class_name: str | None = None
    decorators: list[str] = []
    language: str  # "python" | "go" | "typescript" | "java" | "php"


class CallEdge(BaseModel):
    model_config = ConfigDict(frozen=True)

    caller_id: str  # FuncBlock.id
    callee_name: str  # called function name
    callee_file: str | None = None
    resolved: bool  # whether callee was found in known blocks
    line: int  # line number of the call


class EntryPoint(BaseModel):
    model_config = ConfigDict(frozen=True)

    func_block_id: str
    entry_type: str  # "http_route" | "rpc" | "cli" | "message_consumer" | ...
    route: str | None = None
    http_method: str | None = None
    confidence: float
    evidence: str
    needs_llm_review: bool  # True when confidence < 0.8
    authentication: str | None = None  # "public" | "required" | "unknown"
    source: str = "code_index"  # "code_index" | "gitnexus" | "schema" | "llm_pre_recon"


class CallChain(BaseModel):
    model_config = ConfigDict(frozen=True)

    entry_point_id: str
    path: list[str]  # ordered list of FuncBlock.id
    depth: int
    has_unresolved: bool  # path contains unresolved calls


class CodeIndex(BaseModel):
    repository: str
    language: str
    total_blocks: int
    total_entry_points: int
    total_chains: int
    blocks: list[FuncBlock]
    edges: list[CallEdge]
    entry_points: list[EntryPoint]
    chains: list[CallChain]
    # Extended fields for GitNexus integration (forward refs to avoid circular order)
    file_manifest: "FileManifest | None" = None
    degradation_level: "DegradationLevel | None" = None
    # Spec B: AST-precise sink detection (use forward ref; resolved at runtime via model_rebuild)
    sink_call_sites: list["SinkCallSite"] = []
    source_points: list["SourcePoint"] = []
    storage_write_points: list["StorageWritePoint"] = []
    parameter_graph: "ParameterPropagationGraph | None" = None


class AdjudicatedEntryPoint(BaseModel):
    func_block_id: str
    verdict: Verdict
    entry_type: str
    route: str | None = None
    http_method: str | None = None
    evidence: str
    source: EntryPointSource


class AdjudicationResult(BaseModel):
    repository: str
    language: str
    adjudicated_entry_points: list[AdjudicatedEntryPoint]


class ParameterSource(str, Enum):
    """HTTP parameter source for taint tracking."""
    QUERY_PARAM = "query"
    PATH_PARAM = "path"
    BODY_FIELD = "body"
    FORM_FIELD = "form"
    HEADER = "header"
    COOKIE = "cookie"
    FILE_UPLOAD = "file"
    SESSION_ATTR = "session"
    INTERNAL = "internal"
    UNKNOWN = "unknown"
    STORAGE = "storage"
    # RPC/Socket 入口（2026-09-15 单仓跨服务补齐）：gRPC 等请求消息字段 /
    # socket 收包读到的帧。可达性标签 = 上游网关转发公网输入时公网可达。
    RPC_FIELD = "rpc"
    SOCKET_DATA = "socket"


class TypedParameter(BaseModel):
    """Full parameter info — foundation for taint analysis."""
    name: str
    type_annotation: str | None = None
    default_value: str | None = None
    is_variadic: bool = False          # *args
    is_keyword_variadic: bool = False  # **kwargs
    is_optional: bool = False          # TypeScript ? modifier
    source: ParameterSource | None = None


class UnifiedEntryPoint(BaseModel):
    """Entry point from any source, with unified scoring."""
    model_config = ConfigDict(frozen=True)

    uid: str                    # "file_path:function_name:start_line"
    name: str
    file_path: str
    confidence: float
    source: str                 # "gitnexus" | "schema_file" | "framework_convention" | "code_index" | "llm_batch"
    entry_type: str
    route: str | None = None
    http_method: str | None = None
    evidence: str = ""


class FileEntry(BaseModel):
    """A file discovered in the repository with its security classification."""
    file_path: str
    file_type: str              # "template" | "config" | "schema" | "query" | "source"
    size_bytes: int


class FileManifest(BaseModel):
    """Complete manifest of all security-relevant files."""
    entries: list[FileEntry] = Field(default_factory=list)

    @property
    def total_count(self) -> int:
        return len(self.entries)

    @property
    def by_type(self) -> dict[str, int]:
        return dict(Counter(e.file_type for e in self.entries))

    def filter_by_type(self, file_type: str) -> list[FileEntry]:
        return [e for e in self.entries if e.file_type == file_type]


class DegradationLevel(str, Enum):
    """Degradation level for the code indexing engine."""
    FULL = "full"           # GitNexus + MCP full
    DEGRADED = "degraded"   # AST BFS fallback
    MINIMAL = "minimal"     # Pure LLM analysis


class CoverageGap(BaseModel):
    """A single coverage gap in degraded mode."""
    capability: str
    reason: str
    affected_phases: list[str]
    estimated_coverage_loss: str


class DegradationReport(BaseModel):
    """调用图降级报告。"""
    total_edges: int = 0
    resolved_count: int = 0
    unresolved_count: int = 0
    ambiguous_count: int = 0
    truncated_count: int = 0


class CallGraphResult(BaseModel):
    """GitNexus MCP 构建的调用图结果。复用现有 CallEdge / CallChain / FuncBlock。"""
    edges: list[CallEdge] = []
    chains: list[CallChain] = []
    entry_points: list[FuncBlock] = []
    degradation_report: "DegradationReport | None" = None


class GitNexusNotIndexedError(Exception):
    """GitNexus 未索引目标仓库时抛出。"""


class GitNexusConnectionError(Exception):
    """GitNexus MCP 连接失败时抛出。"""


# Resolve forward references for sink_call_sites (Spec B)
def _resolve_forward_refs() -> None:
    try:
        from supernova_core.code_index.parameter_models import (  # noqa: F401
            ParameterPropagationGraph, SinkCallSite, SourcePoint,
        )
        from supernova_core.code_index.storage_models import StorageWritePoint  # noqa: F401
        CodeIndex.model_rebuild()
    except ImportError:
        pass


_resolve_forward_refs()