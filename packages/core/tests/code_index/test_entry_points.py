from supernova_core.code_index.models import FuncBlock
from supernova_core.code_index.entry_points import detect_entry_points


def _block(**overrides) -> FuncBlock:
    defaults = dict(
        id="src/app.py:f:1",
        file_path="src/app.py",
        function_name="f",
        start_line=1,
        end_line=5,
        source_code="def f(): pass",
        parameters=[],
        language="python",
    )
    defaults.update(overrides)
    return FuncBlock(**defaults)


class TestPythonEntryPoints:
    def test_flask_route(self):
        block = _block(
            decorators=["@app.route('/api/users', methods=['GET'])"],
            function_name="list_users",
        )
        eps = detect_entry_points([block], "python")
        assert len(eps) == 1
        assert eps[0].entry_type == "http_route"
        assert eps[0].route == "/api/users"
        assert eps[0].http_method == "GET"
        assert eps[0].confidence == 0.95
        assert eps[0].needs_llm_review is False

    def test_flask_route_post(self):
        block = _block(
            decorators=["@app.route('/api/users', methods=['POST'])"],
            function_name="create_user",
        )
        eps = detect_entry_points([block], "python")
        assert len(eps) == 1
        assert eps[0].http_method == "POST"

    def test_fastapi_route(self):
        block = _block(
            decorators=["@router.get('/users')"],
            function_name="get_users",
        )
        eps = detect_entry_points([block], "python")
        assert len(eps) == 1
        assert eps[0].confidence == 0.95

    def test_django_view(self):
        block = _block(
            decorators=["@api_view(['GET'])"],
            function_name="user_list",
        )
        eps = detect_entry_points([block], "python")
        assert len(eps) == 1
        assert eps[0].confidence == 0.90

    def test_celery_task(self):
        block = _block(
            decorators=["@shared_task"],
            function_name="process_queue",
        )
        eps = detect_entry_points([block], "python")
        assert len(eps) == 1
        assert eps[0].entry_type == "message_consumer"
        assert eps[0].confidence == 0.90

    def test_async_undecorated_needs_review(self):
        block = _block(
            source_code="async def process(): pass",
            function_name="process",
        )
        eps = detect_entry_points([block], "python")
        assert len(eps) == 1
        assert eps[0].needs_llm_review is True
        assert eps[0].confidence == 0.40

    def test_async_private_function_excluded(self):
        block = _block(
            source_code="async def _internal(): pass",
            function_name="_internal",
        )
        eps = detect_entry_points([block], "python")
        assert len(eps) == 0

    def test_async_in_test_file_excluded(self):
        block = _block(
            source_code="async def test_handler(): pass",
            function_name="test_handler",
            file_path="tests/test_app.py",
        )
        eps = detect_entry_points([block], "python")
        assert len(eps) == 0

    def test_async_in_conftest_excluded(self):
        block = _block(
            source_code="async def setup_fixtures(): pass",
            function_name="setup_fixtures",
            file_path="conftest.py",
        )
        eps = detect_entry_points([block], "python")
        assert len(eps) == 0

    def test_async_in_test_suffix_file_excluded(self):
        block = _block(
            source_code="async def helper(): pass",
            function_name="helper",
            file_path="src/app_test.py",
        )
        eps = detect_entry_points([block], "python")
        assert len(eps) == 0

    def test_async_in_spec_dir_excluded(self):
        block = _block(
            source_code="async def run_spec(): pass",
            function_name="run_spec",
            file_path="spec/runner.py",
        )
        eps = detect_entry_points([block], "python")
        assert len(eps) == 0

    def test_async_valid_candidate_detected(self):
        block = _block(
            source_code="async def handle_request(): pass",
            function_name="handle_request",
            file_path="app/handlers.py",
        )
        eps = detect_entry_points([block], "python")
        assert len(eps) == 1
        assert eps[0].confidence == 0.40
        assert eps[0].entry_type == "unknown"

    def test_plain_function_no_entry_point(self):
        block = _block(function_name="helper")
        eps = detect_entry_points([block], "python")
        assert len(eps) == 0


class TestGoEntryPoints:
    def test_net_http_handler(self):
        block = _block(
            parameters=["w http.ResponseWriter", "r *http.Request"],
            function_name="handleUsers",
            language="go",
        )
        eps = detect_entry_points([block], "go")
        assert len(eps) == 1
        assert eps[0].entry_type == "http_route"
        assert eps[0].confidence == 0.95

    def test_gin_handler(self):
        block = _block(
            parameters=["c *gin.Context"],
            function_name="handleUsers",
            language="go",
        )
        eps = detect_entry_points([block], "go")
        assert len(eps) == 1
        assert eps[0].confidence == 0.95

    def test_plain_go_function_no_entry_point(self):
        block = _block(
            parameters=["x int", "y int"],
            function_name="add",
            language="go",
        )
        eps = detect_entry_points([block], "go")
        assert len(eps) == 0


class TestTypeScriptEntryPoints:
    def test_nestjs_get(self):
        block = _block(
            decorators=["@Get()"],
            function_name="listUsers",
            language="typescript",
        )
        eps = detect_entry_points([block], "typescript")
        assert len(eps) == 1
        assert eps[0].entry_type == "http_route"
        assert eps[0].confidence == 0.95

    def test_nestjs_post(self):
        block = _block(
            decorators=["@Post()"],
            function_name="createUser",
            language="typescript",
        )
        eps = detect_entry_points([block], "typescript")
        assert len(eps) == 1
        assert eps[0].http_method == "POST"

    def test_plain_ts_function_no_entry_point(self):
        block = _block(
            function_name="helper",
            language="typescript",
        )
        eps = detect_entry_points([block], "typescript")
        assert len(eps) == 0


class TestJavaEntryPoints:
    def test_spring_get_mapping(self):
        block = _block(
            decorators=["@GetMapping"],
            function_name="listUsers",
            language="java",
        )
        eps = detect_entry_points([block], "java")
        assert len(eps) == 1
        assert eps[0].entry_type == "http_route"
        assert eps[0].confidence == 0.95

    def test_spring_request_mapping(self):
        block = _block(
            decorators=['@RequestMapping("/api/users")'],
            function_name="users",
            language="java",
        )
        eps = detect_entry_points([block], "java")
        assert len(eps) == 1
        assert eps[0].confidence == 0.95

    def test_rabbit_listener(self):
        block = _block(
            decorators=['@RabbitListener(queues = "orders")'],
            function_name="processOrder",
            language="java",
        )
        eps = detect_entry_points([block], "java")
        assert len(eps) == 1
        assert eps[0].entry_type == "message_consumer"
        assert eps[0].confidence == 0.90


class TestPhpEntryPoints:
    def test_laravel_route_get(self):
        # Laravel Route::get('/path', ...) 现在被检测（spec-1b G4：Laravel 路由注册式
        # 在 source_code 中识别）。原为 asserts-nothing 占位测试，转为正向断言。
        block = _block(
            source_code="Route::get('/api/users', function () { return getUsers(); });",
            function_name="getUsers",
            language="php",
        )
        eps = detect_entry_points([block], "php")
        routes = [(e.route, e.http_method) for e in eps]
        assert ("/api/users", "GET") in routes, \
            f"Laravel Route::get should be detected, got {routes}"

    def test_symfony_route_attribute(self):
        block = _block(
            decorators=["#[Route('/api/users', methods: ['GET'])]"],
            function_name="listUsers",
            language="php",
        )
        eps = detect_entry_points([block], "php")
        assert len(eps) == 1
        assert eps[0].confidence == 0.95

    def test_plain_php_no_entry_point(self):
        block = _block(
            function_name="helper",
            language="php",
        )
        eps = detect_entry_points([block], "php")
        assert len(eps) == 0


class TestFrameworkExpansionG4:
    """G4 (spec-1b): extend entry_points to FastAPI / JAX-RS / Laravel / echo+chi."""

    def test_python_fastapi_app_get_detected(self):
        """FastAPI @app.get (receiver=app, existing @router.* did not cover)."""
        block = _block(
            id="app.py:h:1",
            file_path="app.py",
            function_name="h",
            decorators=["@app.get('/items/{id}')"],
            language="python",
        )
        eps = detect_entry_points([block], "python")
        routes = [(e.route, e.http_method) for e in eps]
        assert ("/items/{id}", "GET") in routes, \
            f"FastAPI @app.get should be detected, got {routes}"

    def test_java_jaxrs_method_annotation_detected(self):
        """JAX-RS @GET (javax.ws.rs, existing Spring @*Mapping did not cover)."""
        block = _block(
            id="A.java:h:1",
            file_path="A.java",
            function_name="h",
            decorators=["@GET"],
            language="java",
        )
        eps = detect_entry_points([block], "java")
        assert any(e.http_method == "GET" and e.entry_type == "http_route" for e in eps), \
            f"JAX-RS @GET should be detected, got {[(e.http_method, e.entry_type) for e in eps]}"

    def test_php_laravel_route_registration_detected(self):
        """Laravel Route::get (top-level call, in source_code, not decorator)."""
        block = _block(
            id="routes/api.php:reg:1",
            file_path="routes/api.php",
            function_name="reg",
            source_code="Route::get('/users/{id}', [UserController::class,'show']);",
            language="php",
        )
        eps = detect_entry_points([block], "php")
        routes = [(e.route, e.http_method) for e in eps]
        assert ("/users/{id}", "GET") in routes, \
            f"Laravel Route::get should be detected, got {routes}"

    def test_go_echo_route_registration_detected(self):
        """echo/gin e.GET / chi r.Get route-registration style."""
        block = _block(
            id="main.go:setup:1",
            file_path="main.go",
            function_name="setup",
            parameters=["e echo.Context"],
            source_code='e.GET("/orders/{id}", getOrder)',
            language="go",
        )
        eps = detect_entry_points([block], "go")
        routes = [(e.route, e.http_method) for e in eps]
        assert ("/orders/{id}", "GET") in routes, \
            f"echo e.GET should be detected, got {routes}"

    def test_go_non_route_call_not_detected(self):
        """Review fix (Minor): 非 router receiver 不应误报为 http_route。

        db.Get("user:1") / cache.Delete("k") / client.Put("/v1/item") 都不是路由
        注册——receiver 不在白名单（e/r/router/engine/mux/app/api/group/server），
        故即便 method token 形似 GET/Delete/Put 也不应产 http_route EntryPoint。
        """
        block = _block(
            id="store.go:op:1",
            file_path="store.go",
            function_name="op",
            parameters=["db *sql.DB", "cache *redis.Client"],
            source_code=(
                'func op(db *sql.DB, cache *redis.Client) {\n'
                '    db.Get("user:1")\n'
                '    cache.Delete("k")\n'
                '    client.Put("/v1/item")\n'
                '}\n'
            ),
            language="go",
        )
        eps = detect_entry_points([block], "go")
        http_routes = [e for e in eps if e.entry_type == "http_route"]
        bad_routes = {e.route for e in http_routes} & {"user:1", "k", "/v1/item"}
        assert not bad_routes, \
            f"non-route calls must not be detected as http_route, got {bad_routes}"


class TestGoRpcSocketEntryPoints:
    """RPC/Socket 入口（2026-09-15 补齐）：单仓扫描下游 gRPC / socket 服务仓曾零识别。

    根因是两层闸门：detect_entry_points 只认 HTTP handler，而 detect_sources
    只扫 entry_point_ids 内的函数——entry 不识别，source 规则再全也不生效。
    """

    def test_go_grpc_service_method_detected(self):
        """unary RPC 形态签名：(ctx context.Context, req *pb.XxxRequest)。"""
        block = _block(
            parameters=["ctx context.Context", "req *pb.ExecRequest"],
            function_name="ExecRobotCommand",
            language="go",
        )
        eps = detect_entry_points([block], "go")
        grpc = [e for e in eps if e.entry_type == "grpc_service"]
        assert len(grpc) == 1
        assert grpc[0].confidence == 0.70
        assert grpc[0].needs_llm_review is True

    def test_go_grpc_request_param_name_variants(self):
        """参数名惯例变体（request/in/msg/input/payload）都识别。"""
        block = _block(
            parameters=["ctx context.Context", "request *v1.CreateReq"],
            function_name="Create",
            language="go",
        )
        eps = detect_entry_points([block], "go")
        assert any(e.entry_type == "grpc_service" for e in eps)

    def test_go_ctx_with_scalar_params_not_grpc(self):
        """ctx + 纯标量参数的普通函数不算（收敛误报：无消息指针入参）。"""
        block = _block(
            parameters=["ctx context.Context", "id int"],
            function_name="Get",
            language="go",
        )
        eps = detect_entry_points([block], "go")
        assert len(eps) == 0

    def test_go_ctx_only_not_grpc(self):
        block = _block(
            parameters=["ctx context.Context"],
            function_name="cleanup",
            language="go",
        )
        eps = detect_entry_points([block], "go")
        assert len(eps) == 0

    def test_go_req_pointer_without_ctx_not_grpc(self):
        """无 ctx 的 req 指针函数（纯内部透传）不算。"""
        block = _block(
            parameters=["req *pb.ExecRequest"],
            function_name="validate",
            language="go",
        )
        eps = detect_entry_points([block], "go")
        assert len(eps) == 0

    def test_go_http_handler_not_double_labeled(self):
        """HTTP handler 走 http 分支，不重复产 grpc_service。"""
        block = _block(
            parameters=["w http.ResponseWriter", "r *http.Request"],
            function_name="handleUsers",
            language="go",
        )
        eps = detect_entry_points([block], "go")
        assert len(eps) == 1
        assert eps[0].entry_type == "http_route"

    def test_go_net_conn_socket_handler(self):
        block = _block(
            parameters=["conn net.Conn"],
            function_name="handleConn",
            language="go",
        )
        eps = detect_entry_points([block], "go")
        socks = [e for e in eps if e.entry_type == "socket_handler"]
        assert len(socks) == 1
        assert socks[0].confidence == 0.70
        assert socks[0].needs_llm_review is True

    def test_go_websocket_handler(self):
        block = _block(
            parameters=["conn *websocket.Conn"],
            function_name="readPump",
            language="go",
        )
        eps = detect_entry_points([block], "go")
        assert any(e.entry_type == "socket_handler" for e in eps)


class TestJavaGrpcEntryPoints:
    def test_java_grpc_stream_observer_param(self):
        """gRPC Java service 实现：参数含 StreamObserver（unary 的 response
        observer / streaming 皆然）。gRPC 方法无注解，注解检测不覆盖。"""
        block = _block(
            parameters=["HelloRequest request",
                        "StreamObserver<HelloReply> responseObserver"],
            function_name="sayHello",
            language="java",
        )
        eps = detect_entry_points([block], "java")
        grpc = [e for e in eps if e.entry_type == "grpc_service"]
        assert len(grpc) == 1
        assert grpc[0].confidence == 0.75
        assert grpc[0].needs_llm_review is True


class TestUnknownLanguage:
    def test_unknown_language_returns_empty(self):
        block = _block(language="rust")
        eps = detect_entry_points([block], "rust")
        assert len(eps) == 0


class TestExpressEntryPoints:
    """Express.js route detection — Pass 1 (FuncBlock source_code scan)."""

    def test_express_app_get_in_func_block(self):
        """Routes registered inside a function body (e.g., NodeGoat's index(app, db))."""
        block = _block(
            id="src/routes.ts:setupRoutes:10",
            file_path="src/routes.ts",
            function_name="setupRoutes",
            start_line=10,
            source_code=(
                "app.get('/api/users', (req, res) => {\n"
                "  res.json(getUsers());\n"
                "});\n"
            ),
            language="typescript",
        )
        eps = detect_entry_points([block], "typescript")
        express_eps = [ep for ep in eps if ep.evidence.startswith("Express")]
        assert len(express_eps) == 1
        assert express_eps[0].entry_type == "http_route"
        assert express_eps[0].route == "/api/users"
        assert express_eps[0].http_method == "GET"
        assert express_eps[0].confidence == 0.90
        assert express_eps[0].needs_llm_review is False

    def test_express_router_post_in_func_block(self):
        block = _block(
            id="src/routes.ts:registerRoutes:5",
            file_path="src/routes.ts",
            function_name="registerRoutes",
            start_line=5,
            source_code=(
                "router.post('/api/users/:id', async (req, res) => {\n"
                "  const result = await saveUser(req.params.id, req.body);\n"
                "  res.json(result);\n"
                "});\n"
            ),
            language="typescript",
        )
        eps = detect_entry_points([block], "typescript")
        express_eps = [ep for ep in eps if ep.evidence.startswith("Express")]
        assert len(express_eps) == 1
        assert express_eps[0].http_method == "POST"
        assert express_eps[0].route == "/api/users/:id"
        assert express_eps[0].confidence == 0.90

    def test_express_app_all_route(self):
        block = _block(
            id="src/app.ts:catchAll:20",
            file_path="src/app.ts",
            function_name="catchAll",
            start_line=20,
            source_code="app.all('/api/*', (req, res, next) => { next(); });",
            language="typescript",
        )
        eps = detect_entry_points([block], "typescript")
        express_eps = [ep for ep in eps if ep.evidence.startswith("Express")]
        assert len(express_eps) == 1
        assert express_eps[0].http_method == "*"
        assert express_eps[0].confidence == 0.85

    def test_block_commented_route_not_detected(self):
        """NodeGoat 事故（2026-09-11 evidence 矩阵歧义拒挂根因）：/* */ 块注释里的
        修复版注册与真注册同 method+route，产出逐字段重复 entry → match_entry
        歧义拒挂。注释代码不是路由。"""
        block = _block(
            id="app/routes/index.js:index:11",
            file_path="app/routes/index.js",
            function_name="index",
            start_line=11,
            source_code=(
                'app.get("/benefits", isLoggedIn, benefitsHandler.displayBenefits);\n'
                'app.post("/benefits", isLoggedIn, benefitsHandler.updateBenefits);\n'
                '/* Fix for A7 - checks user role\n'
                ' app.get("/benefits", isLoggedIn, isAdmin, benefitsHandler.displayBenefits);\n'
                ' app.post("/benefits", isLoggedIn, isAdmin, benefitsHandler.updateBenefits);\n'
                ' */\n'
            ),
            language="typescript",
        )
        eps = detect_entry_points([block], "typescript")
        express_eps = [ep for ep in eps if ep.evidence.startswith("Express")]
        assert [(ep.http_method, ep.route) for ep in express_eps] == [
            ("GET", "/benefits"), ("POST", "/benefits")]

    def test_line_commented_route_not_detected(self):
        block = _block(
            id="src/routes.ts:setup:1",
            file_path="src/routes.ts",
            function_name="setup",
            start_line=1,
            source_code=(
                "app.get('/real', handler);\n"
                "// app.get('/commented-out', handler);\n"
            ),
            language="typescript",
        )
        eps = detect_entry_points([block], "typescript")
        express_eps = [ep for ep in eps if ep.evidence.startswith("Express")]
        assert [ep.route for ep in express_eps] == ["/real"]

    def test_route_after_url_string_still_detected(self):
        """字符串字面量里的 //（如 URL）不是行注释——剔除逻辑须感知字符串，
        不得误伤后续真路由。"""
        block = _block(
            id="src/routes.ts:setup:1",
            file_path="src/routes.ts",
            function_name="setup",
            start_line=1,
            source_code=(
                "const u = 'http://example.com/x';\n"
                "app.get('/after-url', handler);\n"
            ),
            language="typescript",
        )
        eps = detect_entry_points([block], "typescript")
        express_eps = [ep for ep in eps if ep.evidence.startswith("Express")]
        assert [ep.route for ep in express_eps] == ["/after-url"]

    def test_express_app_use_with_path(self):
        block = _block(
            id="src/app.ts:setup:1",
            file_path="src/app.ts",
            function_name="setup",
            start_line=1,
            source_code="app.use('/api', router);",
            language="typescript",
        )
        eps = detect_entry_points([block], "typescript")
        express_eps = [ep for ep in eps if ep.evidence.startswith("Express")]
        assert len(express_eps) == 1
        assert express_eps[0].http_method == "MIDDLEWARE"
        assert express_eps[0].route == "/api"
        assert express_eps[0].confidence == 0.80

    def test_express_app_use_without_path_excluded(self):
        """app.use() without a string path argument (framework middleware) is excluded."""
        block = _block(
            id="src/server.ts:setup:5",
            file_path="src/server.ts",
            function_name="setup",
            start_line=5,
            source_code="app.use(express.json());",
            language="typescript",
        )
        eps = detect_entry_points([block], "typescript")
        express_eps = [ep for ep in eps if ep.evidence.startswith("Express")]
        assert len(express_eps) == 0

    def test_express_app_use_bare_function_excluded(self):
        """app.use(bodyParser()) without route string is excluded."""
        block = _block(
            id="src/server.ts:middleware:3",
            file_path="src/server.ts",
            function_name="middleware",
            start_line=3,
            source_code="app.use(session({ secret: 'keyboard cat' }));",
            language="typescript",
        )
        eps = detect_entry_points([block], "typescript")
        express_eps = [ep for ep in eps if ep.evidence.startswith("Express")]
        assert len(express_eps) == 0

    def test_multiple_routes_in_one_block(self):
        """Multiple routes in one function (NodeGoat pattern)."""
        block = _block(
            id="src/routes.ts:register:1",
            file_path="src/routes.ts",
            function_name="register",
            start_line=1,
            source_code=(
                "app.get('/users', getUsersHandler);\n"
                "app.post('/users', createUserHandler);\n"
                "app.delete('/users/:id', deleteUserHandler);\n"
            ),
            language="typescript",
        )
        eps = detect_entry_points([block], "typescript")
        express_eps = [ep for ep in eps if ep.evidence.startswith("Express")]
        assert len(express_eps) == 3
        methods = {ep.http_method for ep in express_eps}
        assert methods == {"GET", "POST", "DELETE"}
        # All share the same func_block_id
        assert all(ep.func_block_id == block.id for ep in express_eps)

    def test_express_put_patch_delete(self):
        block = _block(
            id="src/routes.ts:crud:10",
            file_path="src/routes.ts",
            function_name="crud",
            start_line=10,
            source_code=(
                "router.put('/users/:id', updateHandler);\n"
                "router.patch('/users/:id', patchHandler);\n"
                "router.delete('/users/:id', deleteHandler);\n"
            ),
            language="typescript",
        )
        eps = detect_entry_points([block], "typescript")
        express_eps = [ep for ep in eps if ep.evidence.startswith("Express")]
        assert len(express_eps) == 3
        methods = {ep.http_method for ep in express_eps}
        assert methods == {"PUT", "PATCH", "DELETE"}

    def test_no_express_in_python_block(self):
        """Express patterns in Python files are not scanned."""
        block = _block(
            source_code="app.get('/api/users', handler)",
            function_name="setup",
            language="python",
        )
        eps = detect_entry_points([block], "python")
        express_eps = [ep for ep in eps if ep.evidence.startswith("Express")]
        assert len(express_eps) == 0


class TestExpressPass2TopLevel:
    """Express.js route detection — Pass 2 (top-level route scan in route files)."""

    def test_top_level_route_in_routes_dir(self, tmp_path):
        """Routes in a routes/ directory are detected even if not inside a function."""
        repo = tmp_path / "repo"
        routes_dir = repo / "routes"
        routes_dir.mkdir(parents=True)

        (routes_dir / "users.ts").write_text(
            "import { Router } from 'express';\n"
            "const router = Router();\n"
            "\n"
            "router.get('/users', (req, res) => {\n"
            "  res.json(getUsers());\n"
            "});\n"
            "\n"
            "router.post('/users', (req, res) => {\n"
            "  res.json(createUser());\n"
            "});\n"
        )

        # Create a FuncBlock for a helper function inside the same file
        block = _block(
            id="routes/users.ts:getUsers:12",
            file_path="routes/users.ts",
            function_name="getUsers",
            start_line=12,
            end_line=15,
            source_code="function getUsers() { return []; }",
            language="typescript",
        )

        eps = detect_entry_points([block], "typescript", repo_path=str(repo))
        top_level = [ep for ep in eps
                     if ep.evidence.startswith("Express top-level")]
        assert len(top_level) == 2
        methods = {ep.http_method for ep in top_level}
        assert methods == {"GET", "POST"}
        assert all(ep.route == "/users" for ep in top_level)
        # Synthetic func_block_id for top-level routes
        assert all(ep.func_block_id == "routes/users.ts::0" for ep in top_level)

    def test_commented_top_level_route_not_detected(self, tmp_path):
        """Pass 2 扫整文件源码——注释掉的路由注册同样不算（对齐 Pass 1 剔注释）。"""
        repo = tmp_path / "repo"
        routes_dir = repo / "routes"
        routes_dir.mkdir(parents=True)
        (routes_dir / "admin.ts").write_text(
            "const router = require('express').Router();\n"
            "\n"
            "router.get('/admin', (req, res) => { res.json({}); });\n"
            "/* router.get('/admin', requireAdmin, handler); */\n"
            "// router.post('/admin', requireAdmin, handler);\n"
        )
        eps = detect_entry_points([], "typescript", repo_path=str(repo))
        top_level = [ep for ep in eps
                     if ep.evidence.startswith("Express top-level")]
        assert [(ep.http_method, ep.route) for ep in top_level] == [
            ("GET", "/admin")]

    def test_top_level_route_in_server_js(self, tmp_path):
        """Routes in server.js are detected."""
        repo = tmp_path / "repo"
        repo.mkdir()

        (repo / "server.js").write_text(
            "const express = require('express');\n"
            "const app = express();\n"
            "\n"
            "app.get('/health', (req, res) => {\n"
            "  res.json({ status: 'ok' });\n"
            "});\n"
        )

        # No FuncBlocks at all — purely top-level routes
        eps = detect_entry_points([], "typescript", repo_path=str(repo))
        top_level = [ep for ep in eps
                     if ep.evidence.startswith("Express top-level")]
        assert len(top_level) == 1
        assert top_level[0].http_method == "GET"
        assert top_level[0].route == "/health"

    def test_non_route_file_not_scanned(self, tmp_path):
        """Files not in route directories are not scanned by Pass 2."""
        repo = tmp_path / "repo"
        repo.mkdir()

        (repo / "helpers.ts").write_text(
            "app.get('/internal', (req, res) => {\n"
            "  res.json({ data: 42 });\n"
            "});\n"
        )

        block = _block(
            id="helpers.ts:helper:1",
            file_path="helpers.ts",
            function_name="helper",
            start_line=1,
            end_line=3,
            source_code="function helper() { return 42; }",
            language="typescript",
        )

        eps = detect_entry_points([block], "typescript", repo_path=str(repo))
        top_level = [ep for ep in eps
                     if ep.evidence.startswith("Express top-level")]
        assert len(top_level) == 0

    def test_route_inside_funcblock_not_duplicated(self, tmp_path):
        """Routes inside a FuncBlock are NOT double-counted by Pass 2."""
        repo = tmp_path / "repo"
        repo.mkdir()

        (repo / "app.ts").write_text(
            "import express from 'express';\n"
            "const app = express();\n"
            "\n"
            "function setup(app) {\n"
            "  app.get('/api/users', getUsers);\n"
            "  app.post('/api/users', createUser);\n"
            "}\n"
        )

        block = _block(
            id="app.ts:setup:4",
            file_path="app.ts",
            function_name="setup",
            start_line=4,
            end_line=7,
            source_code=(
                "function setup(app) {\n"
                "  app.get('/api/users', getUsers);\n"
                "  app.post('/api/users', createUser);\n"
                "}\n"
            ),
            language="typescript",
        )

        eps = detect_entry_points([block], "typescript", repo_path=str(repo))
        # Pass 1 finds 2 routes from the FuncBlock source_code
        pass1 = [ep for ep in eps if ep.evidence.startswith("Express route:")]
        # Pass 2 should NOT duplicate these (they're inside the FuncBlock)
        pass2 = [ep for ep in eps
                 if ep.evidence.startswith("Express top-level")]
        assert len(pass1) == 2
        assert len(pass2) == 0

    def test_no_repo_path_skips_pass2(self):
        """When repo_path is None, Pass 2 is skipped entirely."""
        block = _block(
            id="src/routes.ts:setup:1",
            file_path="src/routes.ts",
            function_name="setup",
            start_line=1,
            source_code="app.get('/users', handler);",
            language="typescript",
        )
        eps = detect_entry_points([block], "typescript")
        top_level = [ep for ep in eps
                     if ep.evidence.startswith("Express top-level")]
        assert len(top_level) == 0
        # Pass 1 still works
        pass1 = [ep for ep in eps if ep.evidence.startswith("Express route:")]
        assert len(pass1) == 1

    def test_route_file_with_no_blocks_is_discovered(self, tmp_path):
        """A route file with only top-level routes (no functions) is found via filesystem walk.

        The parser produces no FuncBlocks for a file containing only top-level
        route registrations, so this file must be discovered independently.
        """
        repo = tmp_path / "repo"
        routes_dir = repo / "routes"
        routes_dir.mkdir(parents=True)

        (routes_dir / "api.ts").write_text(
            "import { Router } from 'express';\n"
            "const router = Router();\n"
            "router.get('/health', (req, res) => { res.json({ ok: true }); });\n"
        )

        # NO FuncBlock provided — simulates the parser finding no functions
        eps = detect_entry_points([], "typescript", repo_path=str(repo))
        top_level = [ep for ep in eps
                     if ep.evidence.startswith("Express top-level")]
        assert len(top_level) == 1
        assert top_level[0].route == "/health"
        assert top_level[0].http_method == "GET"
