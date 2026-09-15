import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import i18n from "@/i18n";
import { AddRepoDialog } from "./AddRepoDialog";

const mockCreateRepo = vi.fn();
const mockLinkReposInDir = vi.fn();
const mockUploadRepoZip = vi.fn();
const mockBatchClone = vi.fn();
const mockUseAuth = vi.fn();

vi.mock("@/api/client", () => ({
  createRepo: (...a: any[]) => mockCreateRepo(...a),
  linkReposInDir: (...a: any[]) => mockLinkReposInDir(...a),
  uploadRepoZip: (...a: any[]) => mockUploadRepoZip(...a),
  batchClone: (...a: any[]) => mockBatchClone(...a),
  ApiError: class ApiError extends Error {
    status: number;
    body: unknown;
    constructor(status: number, body: unknown) {
      super(`HTTP ${status}`);
      this.status = status;
      this.body = body;
    }
  },
}));

vi.mock("@/auth/AuthContext", () => ({ useAuth: () => mockUseAuth() }));

// toast 断言用（2026-09-15 跨分组挡板：skipped.existing 样例提示）
const mockToastSuccess = vi.fn();
vi.mock("sonner", () => ({ toast: { success: (...a: any[]) => mockToastSuccess(...a), error: vi.fn() } }));

// FileSystemPicker 有自己的测试；这里 mock 它验证 AddRepoDialog 集成（渲染 + onChange 填路径）
vi.mock("@/components/FileSystemPicker", () => ({
  FileSystemPicker: ({ value, onChange, triggerLabel }: {
    value: string; onChange: (v: string) => void; triggerLabel: string;
  }) => (
    <button data-testid="fs-picker" onClick={() => onChange("/app/repos/frontend")}>
      {triggerLabel}{value ? `:${value}` : ""}
    </button>
  ),
}));

function props(overrides: Record<string, unknown> = {}) {
  return { ws: "ws1", open: true, onOpenChange: vi.fn(), onCreated: vi.fn(), ...overrides };
}

describe("AddRepoDialog", () => {
  beforeEach(() => {
    // 断言用了翻译文案（分支(可选)/第 N 行…），固定 zh 防 CI navigator 语言漂移
    i18n.changeLanguage("zh");
    mockCreateRepo.mockReset();
    mockLinkReposInDir.mockReset();
    mockBatchClone.mockReset();
    mockUseAuth.mockReturnValue({ user: { id: 1, username: "tester", role: "admin" } });
  });

  it("批量模式：FileSystemPicker 选路径后提交调 linkReposInDir", async () => {
    mockLinkReposInDir.mockResolvedValue({ imported: [{ name: "frontend", path: "/app/repos/frontend" }], skipped: [] });
    const onCreated = vi.fn();
    const onOpenChange = vi.fn();
    render(<AddRepoDialog {...props({ onCreated, onOpenChange })} />);
    fireEvent.click(await screen.findByTestId("mode-linkdir"));
    // FileSystemPicker 选路径 -> 填入 linkdir-path
    fireEvent.click(screen.getByTestId("fs-picker"));
    expect((screen.getByTestId("linkdir-path") as HTMLInputElement).value).toBe("/app/repos/frontend");
    fireEvent.click(screen.getByTestId("submit"));
    await waitFor(() =>
      expect(mockLinkReposInDir).toHaveBeenCalledWith("ws1", { path: "/app/repos/frontend" }));
    expect(onCreated).toHaveBeenCalled();
    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(mockCreateRepo).not.toHaveBeenCalled();
  });

  it("批量模式：未选路径时提交按钮禁用，选后启用", async () => {
    render(<AddRepoDialog {...props()} />);
    fireEvent.click(await screen.findByTestId("mode-linkdir"));
    expect((screen.getByTestId("submit") as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByTestId("fs-picker"));
    expect((screen.getByTestId("submit") as HTMLButtonElement).disabled).toBe(false);
  });

  it("非 admin：不显示批量关联模式（link-dir 为 admin-only），但可见克隆/上传", async () => {
    mockUseAuth.mockReturnValue({ user: { id: 2, username: "member", role: "user" } });
    render(<AddRepoDialog {...props()} />);
    await screen.findByTestId("submit");
    expect(screen.queryByTestId("mode-linkdir")).toBeNull();
    expect(screen.queryByTestId("fs-picker")).toBeNull();
    // 上传对所有成员开放（与 clone 一致）→ 非 admin 也有模式切换（clone + upload）
    expect(screen.getByTestId("mode-clone")).toBeTruthy();
    expect(screen.getByTestId("mode-upload")).toBeTruthy();
  });

  it("克隆模式：admin 默认克隆，提交调 createRepo", async () => {
    mockCreateRepo.mockResolvedValue({ name: "foo" });
    const onCreated = vi.fn();
    render(<AddRepoDialog {...props({ onCreated })} />);
    fireEvent.change(
      await screen.findByPlaceholderText("https://gitlab.example/foo.git"),
      { target: { value: "https://x/foo.git" } });
    fireEvent.click(screen.getByTestId("submit"));
    await waitFor(() => expect(mockCreateRepo).toHaveBeenCalled());
    expect(onCreated).toHaveBeenCalledWith("foo");
  });

  // ---- 批量克隆（多行 textarea，2026-09-09）----

  /** 在 URL 多行框输入（fireEvent.change 传整段多行文本）。 */
  function pasteUrls(text: string) {
    fireEvent.change(screen.getByPlaceholderText("https://gitlab.example/foo.git"),
      { target: { value: text } });
  }

  it("批量克隆：多行输入走 batchClone，onCreated 回调首个仓库名", async () => {
    mockBatchClone.mockResolvedValue({ submitted: ["foo", "bar"], queued: [], skipped: [] });
    const onCreated = vi.fn();
    const onOpenChange = vi.fn();
    render(<AddRepoDialog {...props({ onCreated, onOpenChange })} />);
    pasteUrls("https://x/foo.git\nhttps://x/bar.git\n");
    fireEvent.click(screen.getByTestId("submit"));
    await waitFor(() => expect(mockBatchClone).toHaveBeenCalledWith(
      "ws1", { urls: ["https://x/foo.git", "https://x/bar.git"], group: undefined }));
    expect(onCreated).toHaveBeenCalledWith("foo");
    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(mockCreateRepo).not.toHaveBeenCalled();
  });

  it("批量克隆：多行时隐藏 branch/commit（批量无意义），单行保留", async () => {
    render(<AddRepoDialog {...props()} />);
    await screen.findByPlaceholderText("https://gitlab.example/foo.git");
    // 单行：branch/commit 可见（现有单条精确定位路径不动）
    pasteUrls("https://x/foo.git");
    expect(screen.getByPlaceholderText("分支(可选)")).toBeTruthy();
    // 多行：branch/commit 不渲染
    pasteUrls("https://x/foo.git\nhttps://x/bar.git");
    expect(screen.queryByPlaceholderText("分支(可选)")).toBeNull();
    expect(screen.queryByPlaceholderText("commit(可选)")).toBeNull();
  });

  it("批量克隆：任一行非法 → 行内报错 + 提交禁用", async () => {
    render(<AddRepoDialog {...props()} />);
    await screen.findByPlaceholderText("https://gitlab.example/foo.git");
    pasteUrls("https://x/foo.git\nnot-a-url\n");
    expect(screen.getByText(/第 2 行不是合法 git URL/)).toBeTruthy();
    expect((screen.getByTestId("submit") as HTMLButtonElement).disabled).toBe(true);
  });

  it("批量克隆提交成功后 onBatchCreated 收到全部新仓库名（submitted+queued）", async () => {
    const onBatchCreated = vi.fn();
    mockBatchClone.mockResolvedValue(
      { submitted: ["be/new-a"], queued: ["be/new-b"], skipped: [] });
    render(<AddRepoDialog ws="ws1" open onOpenChange={() => {}} onCreated={() => {}}
      onBatchCreated={onBatchCreated} />);
    fireEvent.change(await screen.findByTestId("repo-urls"),
      { target: { value: "https://gl/a.git\nhttps://gl/b.git" } });
    fireEvent.click(screen.getByTestId("submit"));
    await waitFor(() =>
      expect(onBatchCreated).toHaveBeenCalledWith(["be/new-a", "be/new-b"]));
  });

  it("未传 onBatchCreated 时批量克隆仍走 onCreated(首个)（向后兼容）", async () => {
    const onCreated = vi.fn();
    mockBatchClone.mockResolvedValue(
      { submitted: ["be/new-a"], queued: ["be/new-b"], skipped: [] });
    render(<AddRepoDialog ws="ws1" open onOpenChange={() => {}} onCreated={onCreated} />);
    fireEvent.change(await screen.findByTestId("repo-urls"),
      { target: { value: "https://gl/a.git\nhttps://gl/b.git" } });
    fireEvent.click(screen.getByTestId("submit"));
    await waitFor(() => expect(onCreated).toHaveBeenCalledWith("be/new-a"));
  });

  it("批量克隆：skipped 带 existing → toast 附已存在样例（跨分组挡板可感知）", async () => {
    mockBatchClone.mockResolvedValue({ submitted: [], queued: [], skipped: [
      { url: "https://x/foo.git", reason: "exists", existing: "2026H2/foo" },
      { url: "https://x/bar.git", reason: "exists", existing: "2026H2/bar" },
    ] });
    render(<AddRepoDialog {...props()} />);
    await screen.findByPlaceholderText("https://gitlab.example/foo.git");
    pasteUrls("https://x/foo.git\nhttps://x/bar.git");
    fireEvent.click(screen.getByTestId("submit"));
    await waitFor(() => expect(mockToastSuccess).toHaveBeenCalled());
    expect(mockToastSuccess).toHaveBeenCalledWith(
      expect.stringContaining("2026H2/foo"));
    expect(mockToastSuccess).toHaveBeenCalledWith(
      expect.stringContaining("2"));
  });

  it("批量克隆：group 共享透传", async () => {
    mockBatchClone.mockResolvedValue({ submitted: ["frontend/foo", "frontend/bar"], queued: [], skipped: [] });
    render(<AddRepoDialog {...props()} />);
    await screen.findByPlaceholderText("https://gitlab.example/foo.git");
    pasteUrls("https://x/foo.git\nhttps://x/bar.git");
    fireEvent.change(screen.getByPlaceholderText("如 frontend / backend，留空则放顶层"),
      { target: { value: "frontend" } });
    fireEvent.click(screen.getByTestId("submit"));
    await waitFor(() => expect(mockBatchClone).toHaveBeenCalledWith(
      "ws1", { urls: ["https://x/foo.git", "https://x/bar.git"], group: "frontend" }));
  });

  // ---- 上传模式（upload）：拖拽/选择 zip → uploadRepoZip ----

  function makeZip(name: string): File {
    return new File([new Uint8Array([0x50, 0x4b])], name, { type: "application/zip" });
  }

  it("上传模式：未选文件时提交禁用，选择 zip 后启用并提交", async () => {
    mockUploadRepoZip.mockResolvedValue({ name: "app" });
    const onCreated = vi.fn();
    const onOpenChange = vi.fn();
    render(<AddRepoDialog {...props({ onCreated, onOpenChange })} />);
    fireEvent.click(await screen.findByTestId("mode-upload"));
    expect((screen.getByTestId("submit") as HTMLButtonElement).disabled).toBe(true);
    const input = screen.getByTestId("upload-file-input") as HTMLInputElement;
    fireEvent.change(input, { target: { files: [makeZip("app.zip")] } });
    expect((screen.getByTestId("submit") as HTMLButtonElement).disabled).toBe(false);
    // 文件列表渲染 + 单文件 name 输入（placeholder = 文件名派生）
    expect(screen.getByTestId("upload-file-list").textContent).toContain("app.zip");
    expect((screen.getByTestId("upload-name") as HTMLInputElement).placeholder).toBe("app");
    fireEvent.click(screen.getByTestId("submit"));
    await waitFor(() => expect(mockUploadRepoZip).toHaveBeenCalledTimes(1));
    // 单文件 + 无自定义名 → name 不覆盖（undefined = 后端取文件名派生）
    expect(mockUploadRepoZip).toHaveBeenCalledWith("ws1", expect.any(File),
      { name: undefined, group: undefined }, expect.any(Function));
    expect(onCreated).toHaveBeenCalledWith("app");
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it("上传模式：非 .zip 文件被忽略", async () => {
    render(<AddRepoDialog {...props()} />);
    fireEvent.click(await screen.findByTestId("mode-upload"));
    const input = screen.getByTestId("upload-file-input") as HTMLInputElement;
    fireEvent.change(input, { target: { files: [makeZip("a.zip"), new File([], "b.tar.gz")] } });
    expect((screen.getByTestId("submit") as HTMLButtonElement).disabled).toBe(false);
    expect(screen.getByTestId("upload-file-list").textContent).toContain("a.zip");
    expect(screen.getByTestId("upload-file-list").textContent).not.toContain("b.tar.gz");
  });

  it("上传模式：多文件逐个上传，name 覆盖不生效（仅单文件）", async () => {
    mockUploadRepoZip.mockResolvedValue({ name: "x" });
    const onCreated = vi.fn();
    render(<AddRepoDialog {...props({ onCreated })} />);
    fireEvent.click(await screen.findByTestId("mode-upload"));
    fireEvent.change(screen.getByTestId("upload-file-input") as HTMLInputElement,
      { target: { files: [makeZip("a.zip"), makeZip("b.zip")] } });
    fireEvent.click(screen.getByTestId("submit"));
    await waitFor(() => expect(mockUploadRepoZip).toHaveBeenCalledTimes(2));
    expect(mockUploadRepoZip).toHaveBeenNthCalledWith(1, "ws1", expect.any(File),
      { name: undefined, group: undefined }, expect.any(Function));
    expect(mockUploadRepoZip).toHaveBeenNthCalledWith(2, "ws1", expect.any(File),
      { name: undefined, group: undefined }, expect.any(Function));
    expect(onCreated).toHaveBeenCalledTimes(1);  // 只回调首个（列表刷新触发）
  });
});
