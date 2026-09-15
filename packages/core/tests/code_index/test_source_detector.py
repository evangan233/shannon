from supernova_core.code_index.parameter_models import SourcePoint
from supernova_core.code_index.models import CodeIndex, ParameterSource


def test_source_point_basic_fields():
    sp = SourcePoint(
        id="app/routes/allocations.js:displayAllocations:11::userId::18",
        entry_point_id="app/routes/allocations.js:displayAllocations:11",
        param_name="userId",
        source_type=ParameterSource.PATH_PARAM,
        expression="req.params.userId",
        file_path="app/routes/allocations.js",
        line=18,
        validation="parseInt()",
        confidence=0.9,
        rule_id="ts-express-path",
    )
    assert sp.param_name == "userId"
    assert sp.source_type == ParameterSource.PATH_PARAM
    assert sp.validation == "parseInt()"
    assert sp.needs_review is False  # default


def test_code_index_has_source_points_field():
    ci = CodeIndex(
        repository="r", language="typescript", total_blocks=0,
        total_entry_points=0, total_chains=0, blocks=[], edges=[],
        entry_points=[], chains=[],
    )
    assert ci.source_points == []  # default empty list


from supernova_core.code_index.source_detector import detect_sources, DEFAULT_SOURCE_RULES
from supernova_core.code_index.models import FuncBlock


def test_default_source_rules_externalized_stable():
    """外部化锚点:source 规则库搬迁到 YAML 后数量不退化(原 18 条)。

    detect_sources 硬编码迭代 DEFAULT_SOURCE_RULES,若 YAML 写错(漏语言分组)此前无任何
    回归保护 —— 此断言是唯一护栏。
    """
    assert len(DEFAULT_SOURCE_RULES) >= 18
    ids = {r.rule_id for r in DEFAULT_SOURCE_RULES}
    for rid in ("ts-express-path", "py-django-get", "php-get", "go-gin-query", "java-request-param"):
        assert rid in ids, f"missing source rule {rid}"
    # deepsec 吸收 §2 代表性 source 规则(防 YAML 丢条)
    for rid in ("ts-hono-query", "ts-fastify-query", "ts-next-searchparams",
                "py-flask-args-get", "go-gin-getheader", "j-jaxrs-queryparam",
                "php-superglobal-cookie", "php-laravel-input"):
        assert rid in ids, f"missing deepsec source rule {rid}"


def _block(file_path, func_name, start_line, source, language="typescript", params=None):
    return FuncBlock(
        id=f"{file_path}:{func_name}:{start_line}", file_path=file_path,
        function_name=func_name, start_line=start_line, end_line=start_line + 10,
        source_code=source, parameters=params or [], language=language,
    )


def _provider_from(block):
    return lambda b: block.source_code.encode("utf-8") if b.id == block.id else None


def test_express_req_params_yields_path_source():
    src = (
        "function displayAllocations(req, res) {\n"
        "  const userId = req.params.userId;\n"   # line 2
        "  const threshold = req.query.threshold;\n"
        "}\n"
    )
    block = _block("allocations.js", "displayAllocations", 11, src, "typescript", ["req", "res"])
    out = detect_sources([block], parser=None, entry_point_ids={block.id},
                         source_provider=_provider_from(block))
    sp = next(s for s in out if s.param_name == "userId")
    assert sp.source_type.value == "path"
    assert sp.expression == "req.params.userId"
    assert sp.line == 12  # start_line(11) + 行内偏移(1) → 第 2 行
    assert sp.rule_id.startswith("ts-express")


def test_express_req_query_and_body_distinct_source_types():
    src = "function f(req){ const q=req.query.q; const b=req.body.b; }\n"
    block = _block("f.js", "f", 1, src, "typescript", ["req"])
    out = detect_sources([block], parser=None, entry_point_ids={block.id},
                         source_provider=_provider_from(block))
    types = {(s.param_name, s.source_type.value) for s in out}
    assert ("q", "query") in types
    assert ("b", "body") in types


def test_django_request_get_yields_query():
    src = "def view(request):\n    q = request.GET['q']\n    return HttpResponse(q)\n"
    block = _block("views.py", "view", 5, src, "python", ["request"])
    out = detect_sources([block], parser=None, entry_point_ids={block.id},
                         source_provider=_provider_from(block))
    assert any(s.param_name == "q" and s.source_type.value == "query" for s in out)


def test_php_get_yields_query():
    src = "<?php $id = $_GET['id']; ?>\n"
    block = _block("index.php", "handler", 1, src, "php", [])
    out = detect_sources([block], parser=None, entry_point_ids={block.id},
                         source_provider=_provider_from(block))
    assert any(s.param_name == "id" and s.source_type.value == "query" for s in out)


def test_non_entry_block_skipped():
    src = "function helper(req){ return req.query.x; }\n"
    block = _block("util.js", "helper", 1, src, "typescript", ["req"])
    # entry_point_ids 为空 → 该 block 不被扫
    out = detect_sources([block], parser=None, entry_point_ids=set(),
                         source_provider=_provider_from(block))
    assert out == []


def test_dedup_same_field_same_type():
    # 同一 handler 里 userId 被 req.params 取用两次 → 去重为一个 SourcePoint
    src = "function f(req){ let a=req.params.id; let b=req.params.id; }\n"
    block = _block("f.js", "f", 1, src, "typescript", ["req"])
    out = detect_sources([block], parser=None, entry_point_ids={block.id},
                         source_provider=_provider_from(block))
    ids = [(s.entry_point_id, s.param_name, s.source_type) for s in out]
    assert len(ids) == len(set(ids))  # no duplicates


def test_build_code_index_populates_source_points():
    """pipeline 冒烟:build_code_index_with_gitnexus ⑧b 填充 source_points。

    route 注册放在 setup 函数体内(Express Pass 1: app.get 在 FuncBlock.source_code
    内 → func_block_id 是真实 block id,非 Pass 2 合成 "::0"),使 entry handler 真实
    被识别并落入 detect_sources 的扫描范围。断言 source_points 真实被填充(无 mock)。
    """
    import asyncio
    from unittest.mock import AsyncMock
    from supernova_core.code_index import build_code_index_with_gitnexus
    import tempfile, os

    # route 注册 + handler 取用都在 setupRoutes 函数体内 → detect_entry_points Pass 1 命中
    src = (
        "function setupRoutes(app) {\n"
        "  app.get('/allocations/:userId', function displayAllocations(req, res){\n"
        "    const userId = req.params.userId;\n"
        "    const threshold = req.query.threshold;\n"
        "  });\n"
        "}\n"
    )

    with tempfile.TemporaryDirectory() as repo:
        f = os.path.join(repo, "app.js")
        with open(f, "w") as fh:
            fh.write(src)
        os.makedirs(os.path.join(repo, ".git"), exist_ok=True)

        fake_mcp = AsyncMock()
        fake_mcp.call_tool = AsyncMock(return_value={"upstream": [], "downstream": []})
        fake_llm = AsyncMock(return_value="[]")  # LLM soft 无产出

        index, _rule_gaps, _source_gaps, _storage_gaps = asyncio.run(build_code_index_with_gitnexus(
            repo, mcp_client=fake_mcp, llm_client=fake_llm,
        ))
        # entry handler 的 req.params.userId / req.query.threshold 应被识别
        names = {(s.param_name, s.source_type.value) for s in index.source_points}
        assert ("userId", "path") in names
        assert ("threshold", "query") in names


# ===== Koa(ctx.*)source 规则(trip 等 Koa+Sequelize 项目治本,改动1)=====


def test_koa_ctx_query_yields_query_source():
    """Koa ctx.query.userId → ts-koa-query-direct 命中产 query source(改动1)。

    回归锚点:trip 104/141 controller 用 ctx.*,原 Express-only(req.*)规则全漏 →
    加 5 条 ts-koa-* 规则覆盖 ctx.request.body / ctx.query / ctx.params / ctx.headers。
    """
    src = (
        "function getUser(ctx) {\n"
        "  const userId = ctx.query.userId;\n"      # line 2
        "  const name = ctx.request.body.name;\n"   # line 3
        "}\n"
    )
    block = _block("user.ts", "getUser", 11, src, "typescript", ["ctx"])
    out = detect_sources([block], parser=None, entry_point_ids={block.id},
                         source_provider=_provider_from(block))
    names = {(s.param_name, s.source_type.value, s.rule_id) for s in out}
    assert ("userId", "query", "ts-koa-query-direct") in names
    assert ("name", "body", "ts-koa-body") in names


def test_koa_ctx_params_yields_path_source():
    """Koa ctx.params.id → ts-koa-params 命中产 path source(改动1)。"""
    src = "function f(ctx){ const id = ctx.params.id; }\n"
    block = _block("r.ts", "f", 1, src, "typescript", ["ctx"])
    out = detect_sources([block], parser=None, entry_point_ids={block.id},
                         source_provider=_provider_from(block))
    assert any(s.param_name == "id" and s.source_type.value == "path"
               and s.rule_id == "ts-koa-params" for s in out)


def test_koa_ctx_headers_yields_header_source():
    """Koa ctx.headers.token → ts-koa-headers 命中产 header source(改动1)。"""
    src = "function f(ctx){ const t = ctx.headers.token; }\n"
    block = _block("r.ts", "f", 1, src, "typescript", ["ctx"])
    out = detect_sources([block], parser=None, entry_point_ids={block.id},
                         source_provider=_provider_from(block))
    assert any(s.param_name == "token" and s.source_type.value == "header"
               and s.rule_id == "ts-koa-headers" for s in out)


# ===== deepsec 吸收 §2 source 规则(deepsec matchers/source-*.ts)=====

class TestDeepsecSourceTs:
    """Hono/Fastify/Next source 补召回(原规则只覆盖 Express req.* / Koa ctx.*)。"""

    def _detect(self, src, lang="typescript", params=None):
        block = _block("a.ts", "handler", 1, src, lang, params or [])
        return detect_sources([block], parser=None, entry_point_ids={block.id},
                              source_provider=_provider_from(block))

    def test_hono_query_param_json(self):
        src = (
            "function h(c){\n"
            '  const q = c.req.query("q");\n'
            "  const id = c.req.param('id');\n"
            "  const body = c.req.json();\n"
            "}\n"
        )
        out = self._detect(src, "typescript", ["c"])
        types = {(s.param_name, s.source_type.value, s.rule_id) for s in out}
        assert ("q", "query", "ts-hono-query") in types
        assert ("id", "path", "ts-hono-param") in types
        assert any(s.rule_id == "ts-hono-json" and s.source_type.value == "body" for s in out)

    def test_fastify_query_params_body_headers(self):
        src = (
            "function h(request){\n"
            "  const q = request.query.q;\n"
            "  const id = request.params.id;\n"
            "  const name = request.body.name;\n"
            "  const tok = request.headers.token;\n"
            "}\n"
        )
        out = self._detect(src, "typescript", ["request"])
        types = {(s.param_name, s.source_type.value, s.rule_id) for s in out}
        assert ("q", "query", "ts-fastify-query") in types
        assert ("id", "path", "ts-fastify-params") in types
        assert ("name", "body", "ts-fastify-body") in types
        assert ("token", "header", "ts-fastify-headers") in types

    def test_next_searchparams_json(self):
        src = (
            "export async function GET(request){\n"
            '  const q = request.nextUrl.searchParams.get("q");\n'
            "  const body = await request.json();\n"
            "}\n"
        )
        out = self._detect(src, "typescript", ["request"])
        assert any(s.param_name == "q" and s.source_type.value == "query"
                   and s.rule_id == "ts-next-searchparams" for s in out)
        assert any(s.rule_id == "ts-next-json" and s.source_type.value == "body" for s in out)

    def test_express_rules_still_work(self):
        """既有 Express req.* 规则不受新增影响(回归)。"""
        src = "function f(req){ const q = req.query.q; const id = req.params.id; }\n"
        out = self._detect(src, "typescript", ["req"])
        types = {(s.param_name, s.rule_id) for s in out}
        assert ("q", "ts-express-query") in types
        assert ("id", "ts-express-path") in types


class TestDeepsecSourcePy:
    """Python Flask method 式访问器(原规则只有索引写法 request.GET['x'])。"""

    def _detect(self, src, params=None):
        block = _block("a.py", "view", 1, src, "python", params or [])
        return detect_sources([block], parser=None, entry_point_ids={block.id},
                              source_provider=_provider_from(block))

    def test_flask_args_form_json_get(self):
        src = (
            "def view(request):\n"
            "    q = request.args.get('q')\n"
            "    name = request.form.get('name')\n"
            "    data = request.json.get('k')\n"
            "    body = request.get_json()\n"
            "\n"
        )
        out = self._detect(src, ["request"])
        types = {(s.param_name, s.source_type.value, s.rule_id) for s in out}
        assert ("q", "query", "py-flask-args-get") in types
        assert ("name", "form", "py-flask-form-get") in types
        assert ("k", "body", "py-flask-json-get") in types
        assert any(s.rule_id == "py-flask-get-json" and s.source_type.value == "body" for s in out)

    def test_flask_headers_cookies_files_get(self):
        src = (
            "def view(request):\n"
            "    tok = request.headers.get('X-Token')\n"
            "    sid = request.cookies.get('sid')\n"
            "    f = request.files.get('upload')\n"
            "\n"
        )
        out = self._detect(src, ["request"])
        types = {(s.param_name, s.source_type.value, s.rule_id) for s in out}
        assert ("X-Token", "header", "py-flask-headers-get") in types
        assert ("sid", "cookie", "py-flask-cookies-get") in types
        assert ("upload", "file", "py-flask-files-get") in types


class TestDeepsecSourceGo:
    """Go Gin/net-http 访问器补召回(原规则只有 c.Query/Param/PostForm + r.URL.Query)。"""

    def _detect(self, src, params=None):
        block = _block("a.go", "handler", 1, src, "go", params or [])
        return detect_sources([block], parser=None, entry_point_ids={block.id},
                              source_provider=_provider_from(block))

    def test_gin_getheader_shouldbindjson(self):
        src = (
            'func h(c Context){\n'
            '  tok := c.GetHeader("Authorization")\n'
            "  var body Body\n"
            "  c.ShouldBindJSON(&body)\n"
            "}\n"
        )
        out = self._detect(src, ["c"])
        assert any(s.param_name == "Authorization" and s.source_type.value == "header"
                   and s.rule_id == "go-gin-getheader" for s in out)
        assert any(s.param_name == "body" and s.source_type.value == "body"
                   and s.rule_id == "go-gin-shouldbindjson" for s in out)

    def test_net_formvalue_header_cookie(self):
        src = (
            'func h(r *Request){\n'
            '  id := r.FormValue("id")\n'
            '  name := r.PostFormValue("name")\n'
            '  tok := r.Header.Get("X-Token")\n'
            '  sid, _ := r.Cookie("sid")\n'
            "}\n"
        )
        out = self._detect(src, ["r"])
        types = {(s.param_name, s.source_type.value, s.rule_id) for s in out}
        assert ("id", "form", "go-net-formvalue") in types
        assert ("name", "form", "go-net-postformvalue") in types
        assert ("X-Token", "header", "go-net-header-get") in types
        assert ("sid", "cookie", "go-net-cookie") in types


class TestDeepsecSourceJava:
    """Java 注解 + HttpServlet 访问器补召回。"""

    def _detect(self, src, params=None):
        block = _block("a.java", "handler", 1, src, "java", params or [])
        return detect_sources([block], parser=None, entry_point_ids={block.id},
                              source_provider=_provider_from(block))

    def test_spring_requestheader_cookievalue(self):
        src = (
            "@GetMapping('/h')\n"
            'public String h(@RequestHeader("X-Token") String tok,\n'
            "                @CookieValue('sid') String sid){ return null; }\n"
        )
        out = self._detect(src, ["tok", "sid"])
        types = {(s.param_name, s.source_type.value, s.rule_id) for s in out}
        assert ("X-Token", "header", "j-spring-requestheader") in types
        assert ("sid", "cookie", "j-spring-cookievalue") in types

    def test_jaxrs_queryparam_pathparam_headerparam_formparam(self):
        src = (
            "@GET\n"
            'public String h(@QueryParam("q") String q,\n'
            '                @PathParam("id") String id,\n'
            '                @HeaderParam("X-Token") String tok,\n'
            '                @FormParam("name") String name){ return null; }\n'
        )
        out = self._detect(src, ["q", "id", "tok", "name"])
        types = {(s.param_name, s.source_type.value, s.rule_id) for s in out}
        assert ("q", "query", "j-jaxrs-queryparam") in types
        assert ("id", "path", "j-jaxrs-pathparam") in types
        assert ("X-Token", "header", "j-jaxrs-headerparam") in types
        assert ("name", "form", "j-jaxrs-formparam") in types

    def test_httpservlet_getparameter_getheader_getcookies(self):
        src = (
            "public String h(HttpServletRequest req){\n"
            '  String q = req.getParameter("q");\n'
            '  String tok = req.getHeader("X-Token");\n'
            "  Cookie[] cs = req.getCookies();\n"
            "  return null;\n"
            "}\n"
        )
        out = self._detect(src, ["req"])
        types = {(s.param_name, s.source_type.value, s.rule_id) for s in out}
        assert ("q", "query", "j-httpservlet-getparameter") in types
        assert ("X-Token", "header", "j-httpservlet-getheader") in types
        assert any(s.rule_id == "j-httpservlet-getcookies" and s.source_type.value == "cookie"
                   for s in out)


class TestRpcSocketSourceRules:
    """RPC/Socket source 规则（2026-09-15 单仓跨服务补齐）。

    gRPC service 方法体内对请求消息的取用（pb getter / 字段访问）→ rpc；
    socket 收包读调用（conn.Read*）→ socket。receiver 限定 req/conn 形态
    惯例名，实际误报收敛靠「只在 entry（签名已识别）内扫」双层结构。
    """

    def _detect(self, src, params=None, lang="go"):
        block = _block("a.go", "handler", 1, src, lang, params or [])
        return detect_sources([block], parser=None, entry_point_ids={block.id},
                              source_provider=_provider_from(block))

    def test_grpc_getter_yields_rpc_source(self):
        src = (
            "func h(ctx Context, req *pb.ExecReq){\n"
            "  cmd := req.GetCommand()\n"
            "}\n"
        )
        out = self._detect(src, ["ctx context.Context", "req *pb.ExecReq"])
        assert any(s.param_name == "Command" and s.source_type.value == "rpc"
                   and s.rule_id == "go-grpc-req-getter" for s in out)

    def test_grpc_field_access_yields_rpc_source(self):
        src = (
            "func h(ctx Context, req *pb.ExecReq){\n"
            "  name := req.Name\n"
            "}\n"
        )
        out = self._detect(src, ["ctx context.Context", "req *pb.ExecReq"])
        assert any(s.param_name == "Name" and s.source_type.value == "rpc"
                   and s.rule_id == "go-grpc-req-field" for s in out)

    def test_grpc_field_rule_not_match_method_call(self):
        """字段规则负向前瞻：方法调用 req.Reset() 不当字段。"""
        src = "func h(ctx Context, req *pb.ExecReq){ req.Reset() }\n"
        out = self._detect(src, ["ctx context.Context", "req *pb.ExecReq"])
        assert not any(s.rule_id == "go-grpc-req-field" for s in out)

    def test_non_req_receiver_not_rpc(self):
        """普通 struct 字段访问（receiver 非 req 形态惯例名）不产 rpc source。"""
        src = "func h(ctx Context, o *Order){ v := o.Name }\n"
        out = self._detect(src, ["ctx context.Context", "o *Order"])
        assert not any(s.source_type.value == "rpc" for s in out)

    def test_socket_read_yields_socket_source(self):
        src = (
            "func h(conn Conn){\n"
            "  n, _ := conn.Read(buf)\n"
            "  msg, _ := conn.ReadMessage()\n"
            "}\n"
        )
        out = self._detect(src, ["conn net.Conn"])
        assert any(s.source_type.value == "socket"
                   and s.rule_id == "go-socket-read" for s in out)

    def test_socket_readjson_readstring(self):
        src = (
            "func h(conn Conn){\n"
            "  var m Msg\n"
            "  _ = conn.ReadJSON(&m)\n"
            "  s, _ := conn.ReadString('\\n')\n"
            "}\n"
        )
        out = self._detect(src, ["conn *websocket.Conn"])
        params = {s.param_name for s in out if s.source_type.value == "socket"}
        assert {"ReadJSON", "ReadString"} <= params

    def test_write_call_not_socket_source(self):
        """出站写调用不是收包 source。"""
        src = "func h(conn Conn){ conn.Write(data) }\n"
        out = self._detect(src, ["conn net.Conn"])
        assert not any(s.source_type.value == "socket" for s in out)


class TestDeepsecSourcePhp:
    """PHP superglobal 补齐 + Laravel(原规则只有 $_GET/$_POST/$_REQUEST)。"""

    def _detect(self, src, params=None):
        block = _block("a.php", "handler", 1, src, "php", params or [])
        return detect_sources([block], parser=None, entry_point_ids={block.id},
                              source_provider=_provider_from(block))

    def test_superglobal_cookie_files_server(self):
        src = (
            "<?php\n"
            "$sid = $_COOKIE['sid'];\n"
            "$f = $_FILES['upload'];\n"
            "$agent = $_SERVER['HTTP_USER_AGENT'];\n"
            "?>\n"
        )
        out = self._detect(src)
        types = {(s.param_name, s.source_type.value, s.rule_id) for s in out}
        assert ("sid", "cookie", "php-superglobal-cookie") in types
        assert ("upload", "file", "php-superglobal-files") in types
        assert ("HTTP_USER_AGENT", "header", "php-superglobal-server") in types

    def test_laravel_input_query_route_file(self):
        src = (
            "<?php\n"
            "function h($request){\n"
            "$name = $request->input('name');\n"
            "$q = $request->query('q');\n"
            "$id = $request->route('id');\n"
            "$f = $request->file('avatar');\n"
            "}\n"
        )
        out = self._detect(src, ["request"])
        types = {(s.param_name, s.source_type.value, s.rule_id) for s in out}
        assert ("name", "body", "php-laravel-input") in types
        assert ("q", "query", "php-laravel-query") in types
        assert ("id", "path", "php-laravel-route") in types
        assert ("avatar", "file", "php-laravel-file") in types

