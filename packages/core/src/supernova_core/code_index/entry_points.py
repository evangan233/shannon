import os
import re
import logging
from pathlib import Path, PurePosixPath

from supernova_core.code_index.models import EntryPoint, FuncBlock
from supernova_core.code_index.path_exclusions import is_excluded_dir, is_test_file_name

logger = logging.getLogger(__name__)

LLM_REVIEW_THRESHOLD = 0.8


def detect_entry_points(
    blocks: list[FuncBlock], language: str, repo_path: str | None = None,
) -> list[EntryPoint]:
    """Detect entry points from function blocks using per-language rules."""
    if language == "python":
        return _detect_python(blocks)
    elif language == "go":
        return _detect_go(blocks)
    elif language == "typescript":
        return _detect_typescript(blocks, repo_path)
    elif language == "java":
        return _detect_java(blocks)
    elif language == "php":
        return _detect_php(blocks)
    else:
        return []


# Python
_PYTHON_RULES: list[tuple[str, re.Pattern, str | None, float]] = [
    ("http_route", re.compile(r"@.*\.route\(\s*['\"](.+?)['\"]"), None, 0.95),
    # G4: receiver 扩 app/api_router（FastAPI），加 api_route；group(1)=receiver/group(2)=method/group(3)=route
    ("http_route", re.compile(r"@(app|api_router|router)\.(get|post|put|delete|patch|api_route)\(\s*['\"](.+?)['\"]"), None, 0.95),
    ("http_route", re.compile(r"@(api_view|require_http_methods)"), None, 0.90),
    ("message_consumer", re.compile(r"@(celery\.task|app\.task|shared_task)"), None, 0.90),
]


def _should_skip_async_catchall(block: FuncBlock) -> bool:
    if block.function_name.startswith("_"):
        return True

    file_name = PurePosixPath(block.file_path).name
    if file_name.startswith("test_") or file_name.endswith("_test.py") or file_name == "conftest.py":
        return True

    parts = PurePosixPath(block.file_path).parts
    if any(p in ("tests", "test", "spec") for p in parts):
        return True

    return False


def _detect_python(blocks: list[FuncBlock]) -> list[EntryPoint]:
    entry_points: list[EntryPoint] = []

    for block in blocks:
        matched = False
        for decorator in block.decorators:
            for rule_type, pattern, _, confidence in _PYTHON_RULES:
                m = pattern.search(decorator)
                if m:
                    route = None
                    http_method = None

                    if ".route(" in decorator:
                        route = m.group(1) if m.lastindex >= 1 else None
                        method_match = re.search(r"""methods\s*=\s*\[['"](\w+)['"]\]""", decorator)
                        http_method = method_match.group(1) if method_match else "GET"

                    elif re.match(r"@(app|api_router|router)\.(get|post|put|delete|patch|api_route)", decorator):
                        # G4: receiver=group(1), method=group(2), route=group(3)
                        method_tok = m.group(2)
                        http_method = None if method_tok == "api_route" else method_tok.upper()
                        route = m.group(3) if m.lastindex and m.lastindex >= 3 else None

                    entry_points.append(EntryPoint(
                        func_block_id=block.id,
                        entry_type=rule_type,
                        route=route,
                        http_method=http_method,
                        confidence=confidence,
                        evidence=f"Decorated with {decorator}",
                        needs_llm_review=confidence < LLM_REVIEW_THRESHOLD,
                    ))
                    matched = True
                    break
            if matched:
                break

        if not matched and block.source_code.strip().startswith("async def "):
            if _should_skip_async_catchall(block):
                continue

            entry_points.append(EntryPoint(
                func_block_id=block.id,
                entry_type="unknown",
                confidence=0.40,
                evidence="async def with no known decorator",
                needs_llm_review=True,
            ))

    return entry_points


# G4: echo/gin e.GET / chi r.Get 路由注册式（在 source_code）
# Review fix (Minor): receiver 白名单（路由器惯例变量名），避免 db.Get / cache.Delete 等非路由调用误报
_GO_ROUTE_RECEIVERS = r"(?:e|r|router|engine|mux|app|api|group|server)"
_GO_ROUTE_PATTERN = re.compile(
    rf"\b{_GO_ROUTE_RECEIVERS}\.(GET|POST|PUT|DELETE|PATCH|Any|Get|Post|Put|Delete|Patch)\(\s*['\"]([^'\"]+)['\"]"
)
_GO_METHOD_NORM: dict[str, str] = {
    "GET": "GET", "POST": "POST", "PUT": "PUT", "DELETE": "DELETE",
    "PATCH": "PATCH", "Any": "*",
    "Get": "GET", "Post": "POST", "Put": "PUT", "Delete": "DELETE", "Patch": "PATCH",
}


# Go
def _detect_go(blocks: list[FuncBlock]) -> list[EntryPoint]:
    entry_points: list[EntryPoint] = []

    for block in blocks:
        params_str = " ".join(block.parameters)

        if "http.ResponseWriter" in params_str and "http.Request" in params_str:
            entry_points.append(EntryPoint(
                func_block_id=block.id,
                entry_type="http_route",
                confidence=0.95,
                evidence="Parameters include http.ResponseWriter and *http.Request",
                needs_llm_review=False,
            ))
            continue

        if "gin.Context" in params_str:
            entry_points.append(EntryPoint(
                func_block_id=block.id,
                entry_type="http_route",
                confidence=0.95,
                evidence="Parameter includes *gin.Context",
                needs_llm_review=False,
            ))
            continue

        if block.function_name == "main":
            entry_points.append(EntryPoint(
                func_block_id=block.id,
                entry_type="cli",
                confidence=0.30,
                evidence="func main()",
                needs_llm_review=True,
            ))

    # G4: echo/gin/chi 路由注册式（在 source_code）
    for block in blocks:
        for m in _GO_ROUTE_PATTERN.finditer(block.source_code):
            method_tok = m.group(1)
            route = m.group(2)
            http_method = _GO_METHOD_NORM.get(method_tok)
            if http_method is None:
                continue
            entry_points.append(EntryPoint(
                func_block_id=block.id,
                entry_type="http_route",
                route=route,
                http_method=http_method,
                confidence=0.90,
                evidence=f"Go route registration: {m.group(0).strip()}",
                needs_llm_review=False,
            ))

    return entry_points


# TypeScript
_TS_DECORATOR_RULES: list[tuple[str, re.Pattern, str | None, float]] = [
    ("http_route", re.compile(r"@(Get|Post|Put|Delete|Patch)\b"), None, 0.95),
]

# Express.js route detection
_EXPRESS_ROUTE_PATTERN = re.compile(
    r"""(app|router)\.(get|post|put|delete|patch|all|use)\(\s*['"](/[^'"]*)['"]\s*"""
)


def _strip_js_comments(source: str) -> str:
    """注释替换为等长空白（保留 \\n）——供路由正则扫描前剔除 /* */ 与 // 注释。

    字符串感知（'/"`/` 反引号 + 反斜杠转义），避免把字符串字面量里的 //（URL）
    误判为行注释。等长替换是为了保住偏移→行号换算（Pass 2 用 match 起点算
    行号再对照 FuncBlock 覆盖行）。NodeGoat 事故（2026-09-11）：块注释里的
    修复版路由注册与真注册同 method+route，产重复 entry → 矩阵歧义拒挂。
    """
    out = list(source)
    i, n = 0, len(source)
    quote: str | None = None  # 当前所处字符串引号（None = 代码态）
    while i < n:
        c = source[i]
        if quote is not None:
            if c == "\\" and i + 1 < n:
                i += 2  # 转义：引号字符本身不参与出串判定
                continue
            if c == quote:
                quote = None
            i += 1
            continue
        if c in ("'", '"', "`"):
            quote = c
            i += 1
            continue
        if c == "/" and i + 1 < n and source[i + 1] == "/":
            j = source.find("\n", i)
            j = n if j == -1 else j
            out[i:j] = [" "] * (j - i)
            i = j
            continue
        if c == "/" and i + 1 < n and source[i + 1] == "*":
            j = source.find("*/", i + 2)
            j = n if j == -1 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
            continue
        i += 1
    return "".join(out)

_EXPRESS_METHOD_MAP: dict[str, str | None] = {
    "get": "GET",
    "post": "POST",
    "put": "PUT",
    "delete": "DELETE",
    "patch": "PATCH",
    "all": "*",
    "use": "MIDDLEWARE",
}

_EXPRESS_CONFIDENCE: dict[str, float] = {
    "get": 0.90,
    "post": 0.90,
    "put": 0.90,
    "delete": 0.90,
    "patch": 0.90,
    "all": 0.85,
    "use": 0.80,
}

_ROUTE_FILE_NAMES = {"server.js", "server.ts", "app.js", "app.ts", "index.js", "index.ts"}


def _detect_express_routes(
    blocks: list[FuncBlock], repo_path: str | None = None,
) -> list[EntryPoint]:
    """Detect Express.js route registrations.

    Pass 1: Scan each FuncBlock's source_code for (app|router).(get|post|...) patterns.
    Pass 2 (if repo_path given): Scan full file source for top-level routes
            not inside any FuncBlock, in common route directories.
    """
    entry_points: list[EntryPoint] = []

    # Pass 1: FuncBlock source_code scan（剔注释——见 _strip_js_comments）
    for block in blocks:
        for match in _EXPRESS_ROUTE_PATTERN.finditer(
                _strip_js_comments(block.source_code)):
            method_str = match.group(2)
            route_path = match.group(3)

            http_method = _EXPRESS_METHOD_MAP.get(method_str)
            confidence = _EXPRESS_CONFIDENCE.get(method_str, 0.80)

            entry_points.append(EntryPoint(
                func_block_id=block.id,
                entry_type="http_route",
                route=route_path,
                http_method=http_method,
                confidence=confidence,
                evidence=f"Express route: {match.group(1)}.{method_str}('{route_path}')",
                needs_llm_review=confidence < LLM_REVIEW_THRESHOLD,
            ))

    # Pass 2: Top-level route scan (implemented in Task 2)
    if repo_path is not None:
        entry_points.extend(_scan_top_level_express_routes(blocks, repo_path))

    return entry_points


def _is_route_file(file_path: str) -> bool:
    """Check if a file is likely a top-level Express route file."""
    parts = PurePosixPath(file_path).parts
    basename = parts[-1] if parts else ""
    if basename in _ROUTE_FILE_NAMES:
        return True
    return any(p in ("routes", "router") for p in parts)


def _scan_top_level_express_routes(
    blocks: list[FuncBlock], repo_path: str,
) -> list[EntryPoint]:
    """Scan full file source for Express routes not inside any FuncBlock.

    Only scans files in common route directories (routes/, router/,
    server.js, app.js, etc.).
    """
    repo = Path(repo_path)
    entry_points: list[EntryPoint] = []

    # Group blocks by file_path
    blocks_by_file: dict[str, list[FuncBlock]] = {}
    for block in blocks:
        blocks_by_file.setdefault(block.file_path, []).append(block)

    # Also scan files that have NO blocks at all (e.g., purely top-level routes)
    # We discover these by checking route-file paths that appear in blocks_by_file
    # plus common route files that may have no parsed functions
    candidate_files: set[str] = set(blocks_by_file.keys())

    # Also check common route files that might not have any FuncBlocks
    for name in ("server.js", "server.ts", "app.js", "app.ts", "index.js", "index.ts"):
        if (repo / name).exists():
            candidate_files.add(name)

    # Discover route files via filesystem walk. Some route files contain only
    # top-level route registrations (no function declarations), so the parser
    # produces no FuncBlocks for them and they would be missed by the
    # blocks_by_file seed above.
    for walk_root, dirnames, filenames in os.walk(repo):
        # Prune dependency/build/test dirs in-place so we don't descend into them
        # (shared exclusion list, §4.6)
        dirnames[:] = [d for d in dirnames if not is_excluded_dir(d) and not d.startswith(".")]
        for filename in filenames:
            if filename.endswith((".ts", ".js")) and not is_test_file_name(filename):
                rel = (Path(walk_root) / filename).relative_to(repo).as_posix()
                if _is_route_file(rel):
                    candidate_files.add(rel)

    for file_path_str in sorted(candidate_files):
        if not _is_route_file(file_path_str):
            continue

        file_path = repo / file_path_str
        if not file_path.exists():
            continue

        try:
            full_source = file_path.read_text(errors="replace")
        except Exception:
            continue

        # Build set of line ranges covered by FuncBlocks
        covered_lines: set[int] = set()
        for block in blocks_by_file.get(file_path_str, []):
            for line in range(block.start_line, block.end_line + 1):
                covered_lines.add(line)

        # Scan for route patterns not inside any FuncBlock（剔注释；等长替换保证
        # match 偏移在原文上算行号依然正确）
        for match in _EXPRESS_ROUTE_PATTERN.finditer(_strip_js_comments(full_source)):
            line_num = full_source[:match.start()].count("\n") + 1
            if line_num in covered_lines:
                continue

            method_str = match.group(2)
            route_path = match.group(3)

            http_method = _EXPRESS_METHOD_MAP.get(method_str)
            confidence = _EXPRESS_CONFIDENCE.get(method_str, 0.80)

            entry_points.append(EntryPoint(
                func_block_id=f"{file_path_str}::0",
                entry_type="http_route",
                route=route_path,
                http_method=http_method,
                confidence=confidence,
                evidence=f"Express top-level route: {match.group(1)}.{method_str}('{route_path}')",
                needs_llm_review=confidence < LLM_REVIEW_THRESHOLD,
            ))

    return entry_points


def _detect_typescript(
    blocks: list[FuncBlock], repo_path: str | None = None,
) -> list[EntryPoint]:
    entry_points: list[EntryPoint] = []

    # NestJS decorator patterns
    for block in blocks:
        for decorator in block.decorators:
            for rule_type, pattern, _, confidence in _TS_DECORATOR_RULES:
                m = pattern.search(decorator)
                if m:
                    http_method = m.group(1).upper()
                    entry_points.append(EntryPoint(
                        func_block_id=block.id,
                        entry_type=rule_type,
                        http_method=http_method,
                        confidence=confidence,
                        evidence=f"Decorated with {decorator}",
                        needs_llm_review=confidence < LLM_REVIEW_THRESHOLD,
                    ))
                    break

    # Express.js route patterns
    entry_points.extend(_detect_express_routes(blocks, repo_path))

    return entry_points


# Java
_JAVA_ANNOTATION_RULES: list[tuple[str, re.Pattern, str, float]] = [
    ("http_route", re.compile(r"@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)"), "http_route", 0.95),
    # G4: JAX-RS method 注解（javax.ws.rs），无 @Path 类级组合故 confidence 略低 + needs_review
    ("http_route", re.compile(r"@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b"), "http_route", 0.85),
    ("message_consumer", re.compile(r"@RabbitListener"), "message_consumer", 0.90),
]


def _detect_java(blocks: list[FuncBlock]) -> list[EntryPoint]:
    entry_points: list[EntryPoint] = []

    for block in blocks:
        for decorator in block.decorators:
            for rule_type, pattern, _, confidence in _JAVA_ANNOTATION_RULES:
                m = pattern.search(decorator)
                if m:
                    http_method = None
                    if m.lastindex and m.lastindex >= 1:
                        ann = m.group(1)
                        method_map = {
                            "GetMapping": "GET", "PostMapping": "POST",
                            "PutMapping": "PUT", "DeleteMapping": "DELETE",
                            "PatchMapping": "PATCH", "RequestMapping": None,
                        }
                        if ann in method_map:
                            http_method = method_map[ann]
                        elif ann.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                            http_method = ann.upper()  # JAX-RS (G4)
                        else:
                            http_method = None

                    route = None
                    route_match = re.search(r'[\'"](/[^\'"]+)[\'"]', decorator)
                    if route_match:
                        route = route_match.group(1)

                    entry_points.append(EntryPoint(
                        func_block_id=block.id,
                        entry_type=rule_type,
                        route=route,
                        http_method=http_method,
                        confidence=confidence,
                        evidence=f"Annotated with {decorator}",
                        needs_llm_review=confidence < LLM_REVIEW_THRESHOLD,
                    ))
                    break

    return entry_points


# PHP
_PHP_DECORATOR_RULES: list[tuple[str, re.Pattern, float]] = [
    ("http_route", re.compile(r"#\[Route\("), 0.95),
]

# G4: Laravel / $router 路由注册（顶层调用，在 source_code 里）
_LARAVEL_ROUTE_PATTERN = re.compile(r"(?:Route::|\$router->)(get|post|put|delete|patch|any|match)\(\s*['\"]([^'\"]+)['\"]")
_LARAVEL_METHOD_MAP: dict[str, str | None] = {
    "get": "GET", "post": "POST", "put": "PUT", "delete": "DELETE",
    "patch": "PATCH", "any": "*", "match": "*",
}


def _detect_php(blocks: list[FuncBlock]) -> list[EntryPoint]:
    entry_points: list[EntryPoint] = []

    for block in blocks:
        for decorator in block.decorators:
            for rule_type, pattern, confidence in _PHP_DECORATOR_RULES:
                m = pattern.search(decorator)
                if m:
                    http_method = None
                    method_match = re.search(r"methods:\s*\[\s*['\"](\w+)['\"]", decorator)
                    if method_match:
                        http_method = method_match.group(1)

                    route = None
                    route_match = re.search(r"[\'\"](/[^\'\"]+)[\'\"]", decorator)
                    if route_match:
                        route = route_match.group(1)

                    entry_points.append(EntryPoint(
                        func_block_id=block.id,
                        entry_type=rule_type,
                        route=route,
                        http_method=http_method,
                        confidence=confidence,
                        evidence=f"Attribute: {decorator}",
                        needs_llm_review=confidence < LLM_REVIEW_THRESHOLD,
                    ))
                    break

    # G4: Laravel Route:: / $router-> 注册式（在 source_code，非 decorator）
    for block in blocks:
        for m in _LARAVEL_ROUTE_PATTERN.finditer(block.source_code):
            method_tok = m.group(1)
            route = m.group(2)
            http_method = _LARAVEL_METHOD_MAP.get(method_tok)
            entry_points.append(EntryPoint(
                func_block_id=block.id,
                entry_type="http_route",
                route=route,
                http_method=http_method,
                confidence=0.90,
                evidence=f"Laravel route: {m.group(0).strip()}",
                needs_llm_review=False,
            ))

    return entry_points
