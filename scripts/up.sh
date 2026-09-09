#!/usr/bin/env bash
# scripts/up.sh —— 一键启动 web/worker，自动判断 temporal 复用还是自建。
#
# 用法：
#   ./scripts/up.sh              # 启动（自动判断 temporal；镜像已有就不重建，秒起）
#   ./scripts/up.sh --build      # 强制重建镜像（改了 packages/ 源码、依赖、前端后用）
#   ./scripts/up.sh --dev        # 叠加 dev override：源码挂载进容器，改 Python 免 rebuild
#   ./scripts/up.sh restart web  # 重启进程（dev 下改完 Python 让它加载新代码）
#   ./scripts/up.sh down         # 停掉
#   ./scripts/up.sh logs web     # 看日志（其他 compose 子命令同理透传）
#   --dev 和 --build 可组合。
#
# temporal 怎么起，看三态：
#   自己的 temporal 在跑 → 自建（再次 up 的常态）
#   7233 被别的进程占用 → 复用外部 temporal（-f 加 external-temporal override）
#   7233 空闲           → 自建（主 compose 默认）
#   不能只看 7233 被占就当外部：自己的 temporal 也占 7233，套错 override 会让
#   worker 连一个不存在的主机名然后 crash loop（踩过）。
#
# 卡在拉 temporal 镜像 60s 后报 "context deadline exceeded"？
#   拉镜像走的是 Docker Desktop / macOS 系统代理，shell 里 export http_proxy 没用。
#   多半是代理软件在跑但「系统代理」开关被关了。修法任选：
#   1) 代理软件里重开「系统代理」（还不行就重启 Docker Desktop）；
#   2) Docker Desktop Settings → Proxies 手动填 http://127.0.0.1:7890，一劳永逸；
#   3) 绕开代理直接拉国内镜像（拉一次就缓存，之后不再拉）：
#      docker pull docker.m.daocloud.io/temporalio/temporal:latest \
#        && docker tag docker.m.daocloud.io/temporalio/temporal:latest temporalio/temporal:latest
#
# 开了系统代理、镜像能拉了，但 --build 时 pip 报 "DO NOT MATCH THE HASHES"？
#   不是包被篡改——是 Docker Desktop 系统代理为 VM 级透明代理，build 容器内 pip/apt/npm
#   的国内镜像流量也被劫持走 Clash，只剩 ~200kB/s（直连的 1/100），大 wheel 长连接被掐断，
#   截断文件去校验 hash 必然 mismatch（特征：报错前一行进度停在 60% 左右、龟速）。
#   治本（已配置，2026-08-25）：settings-store.json 写 manual proxy + bypass 分流——
#     ProxyHTTPMode=manual, OverrideProxyHTTP/HTTPS=http://127.0.0.1:7890,
#     OverrideProxyExclude=mirrors.cloud.tencent.com
#   docker.io 走代理出网、腾讯镜像容器内直连满速。改动后需重启 Docker Desktop。
#
# manual 代理模式下 build 又在 "load metadata" 卡 auth.docker.io 超时（dial tcp 162.125.x.x）？
#   manual 模式只给 daemon 配代理，buildkit resolver 不继承 → 直连被 DNS 污染（162.125.x.x
#   是 Dropbox 段假 IP）。docker pull 走 daemon 是通的。止血：先 daemon 预拉基础镜像再 build
#   （buildkit 与 daemon 共享镜像存储，FROM 命中本地就不发请求）：
#      docker pull python:3.12-slim-bookworm node:20-slim
#   改 Dockerfile 换新基础镜像 tag 时，同样先手动 pull 一次。
set -euo pipefail

# 切到仓库根（脚本可能在子目录被调用）
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# C1: worker 常驻消费 WEB 固定 task queue，up 时一并拉起。
# 参数解析：第一个非 flag 参数 = compose 子命令（默认 up）；--build/--dev 是 up 专属
# flag 不透传，其余原样透传。裸 up 复用现有镜像；镜像不存在时 compose 会自动构建。
ACTION="up"
PASSTHROUGH=()
WANT_BUILD=0
WANT_DEV=0
_ACTION_SET=0
for _arg in "$@"; do
  if [ "$_arg" = "--build" ]; then
    WANT_BUILD=1
  elif [ "$_arg" = "--dev" ]; then
    WANT_DEV=1
  elif [ "$_ACTION_SET" = "0" ] && [[ ! "$_arg" =~ ^- ]]; then
    ACTION="$_arg"; _ACTION_SET=1
  else
    PASSTHROUGH+=("$_arg")
  fi
done
unset _arg _ACTION_SET
BUILD_FLAG=""
if [ "$WANT_BUILD" = "1" ]; then
  BUILD_FLAG="--build"
fi

# 7233 端口是否被监听（docker-proxy / temporal 进程都算）
port_in_use() {
  if command -v ss >/dev/null 2>&1; then
    ss -tln 2>/dev/null | grep -q ':7233'
  elif command -v netstat >/dev/null 2>&1; then
    netstat -tln 2>/dev/null | grep -q ':7233'
  else
    # 兜底：尝试连一下
    timeout 1 bash -c 'echo > /dev/tcp/127.0.0.1/7233' 2>/dev/null
  fi
}

# 自己的 temporal 是否在跑——见文件头三态说明（自己的 7233 ≠ 外部 temporal）。
own_temporal_running() {
  local tid
  tid=$(docker compose -f docker-compose.yml ps -q temporal 2>/dev/null || true)
  [ -n "$tid" ] && [ "$(docker inspect -f '{{.State.Running}}' "$tid" 2>/dev/null)" = "true" ]
}

# 清掉本项目里 Created/Exited/Dead 的空壳容器（上次 up 失败留下的，会捣乱模式判断）。
# 只删本项目的非运行态容器，running 的一律不动，外部 shannon-temporal 更碰不到。
cleanup_stale_containers() {
  local stale c
  stale=$(docker compose ps -a --format '{{.Name}}\t{{.State}}' 2>/dev/null \
          | awk -F'\t' '$2 == "created" || $2 == "exited" || $2 == "dead" {print $1}' \
          || true)
  if [ -n "$stale" ]; then
    echo ">> 清理 compose 项目内失败/空壳容器（非运行态；外部 shannon-temporal 不受影响）："
    printf '%s\n' "$stale" | sed 's/^/   - /'
    while IFS= read -r c; do
      [ -n "$c" ] || continue
      remove_stale_container "$c"
    done <<< "$stale"
  fi
}

# 另一个请求正在删同一容器时会报 "already in progress"，等它删完再试，
# 别让 set -e 把整个脚本带崩。
remove_stale_container() {
  local c="$1"
  local max_attempts="${SUPERNOVA_CONTAINER_REMOVE_RETRIES:-30}"
  local interval="${SUPERNOVA_CONTAINER_REMOVE_INTERVAL:-1}"
  local attempt err

  [[ "$max_attempts" =~ ^[1-9][0-9]*$ ]] || max_attempts=30
  [[ "$interval" =~ ^[0-9]+([.][0-9]+)?$ ]] || interval=1

  for ((attempt = 1; attempt <= max_attempts; attempt++)); do
    # 其他请求已经删掉它：视为成功。
    if ! docker inspect "$c" >/dev/null 2>&1; then
      return 0
    fi

    if err=$(docker rm -f "$c" 2>&1); then
      return 0
    fi

    # rm 失败后它可能刚好被别人删完了。
    if ! docker inspect "$c" >/dev/null 2>&1; then
      return 0
    fi

    # 只有删除竞态值得重试；权限等真实错误直接报出来。
    if [[ "$err" != *"already in progress"* ]]; then
      printf '%s\n' "$err" >&2
      return 1
    fi

    if (( attempt < max_attempts )); then
      sleep "$interval"
    fi
  done

  printf '❌ 删除容器超时（Docker 仍报告 removal in progress）: %s\n' "$c" >&2
  return 1
}

# 如果本地存在 docker-compose.override.yml，警告（会干扰自动判断）
if [ -f docker-compose.override.yml ] && [ "$ACTION" != "down" ]; then
  echo "⚠️  检测到本地 docker-compose.override.yml（已被 .gitignore 排除）。" >&2
  echo "    本脚本用 -f 显式加载模板，本地 override 会干扰自动判断。" >&2
  echo "    建议：rm docker-compose.override.yml 后重试。" >&2
  echo "    （本次仍继续，但自动模式判断可能不准）" >&2
fi

OVERRIDE_FILE="docker-compose.override.external-temporal.yml"
DEV_FILE="docker-compose.dev.yml"

if [ "$ACTION" = "up" ]; then
  # buildx 就位 compose 才走 BuildKit；环境坏了让 set -e 直接中止，不带病硬跑。
  bash "$SCRIPT_DIR/ensure-docker.sh"
  cleanup_stale_containers
  if [ "$WANT_BUILD" = "1" ]; then
    echo ">> --build：重建 web/worker 镜像（COPY 进镜像的 packages/ 源码会重新打入）"
  else
    echo ">> 复用现有镜像（未传 --build）。dev 下改 Python 用 restart；改依赖/前端再加 --build。"
  fi

  # 组装 compose 文件：base + temporal 模式（二选一）+ dev override（可叠加）。
  COMPOSE_FILES=(-f docker-compose.yml)
  if own_temporal_running; then
    echo ">> 本项目 temporal(supernova-temporal) 已在运行 → 自建模式（不套 override）"
  elif port_in_use; then
    echo ">> 7233 被非本项目的进程占用 → 复用外部 temporal 模式"
    if [ ! -f "$OVERRIDE_FILE" ]; then
      echo "❌ 缺少 $OVERRIDE_FILE（复用模式依赖它）。请检查仓库。" >&2
      exit 1
    fi
    COMPOSE_FILES+=(-f "$OVERRIDE_FILE")
  else
    echo ">> 7233 空闲 → 自建 temporal 模式（主 compose 默认）"
  fi
  if [ "$WANT_DEV" = "1" ]; then
    if [ ! -f "$DEV_FILE" ]; then
      echo "❌ 缺少 $DEV_FILE（--dev 依赖它）。请检查仓库。" >&2
      exit 1
    fi
    echo ">> --dev：叠加 $DEV_FILE，bind mount packages/prompts 源码（改 Python restart 即生效，免 rebuild）"
    COMPOSE_FILES+=(-f "$DEV_FILE")
  fi

  # --wait：等到 web healthcheck 过（compose 里 web 服务的 /health 探测）才返回——
  # 脚本返回 = 页面可访问，消除 recreate 窗口「更新后第一次刷新连接拒绝」。
  # worker 无 healthcheck，running 即算过；90s 上限防端口被占/起挂时无限等待
  # （healthcheck 容忍 15s start_period + 12×5s retries ≈ 75s < 90s）。
  # BUILD_FLAG 不加引号是有意的（空时展开为零个参数）：
  # shellcheck disable=SC2086
  # ${ARR[@]+"${ARR[@]}"} 是 macOS bash 3.2 + set -u 下空数组的安全展开，勿简化。
  docker compose "${COMPOSE_FILES[@]}" up -d --wait --wait-timeout 90 $BUILD_FLAG ${PASSTHROUGH[@]+"${PASSTHROUGH[@]}"} web worker
else
  # down/logs/ps 等子命令透传。用 PASSTHROUGH 而非 $@（$@ 还带着 ACTION，会重复传）。
  # down 只停 compose 管辖的服务，不动外部 temporal。
  echo ">> 透传子命令: $ACTION ${PASSTHROUGH[*]}"
  docker compose "$ACTION" ${PASSTHROUGH[@]+"${PASSTHROUGH[@]}"}
fi
