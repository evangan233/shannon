// Task 12: HostProfilesPage CRUD（列表 + 新建档案对话框）。
// Harness 镜像 AuthProfilesPage.test.tsx（msw + MemoryRouter + <Route> + i18n.changeLanguage("zh")）。
// 简写说明：@testing-library/user-event 未装，用 fireEvent；
// `within` 未用故不导入（避免遗留 unused import）。
import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor, cleanup } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { setupServer } from "msw/node";
import { http, HttpResponse } from "msw";
import { SWRConfig } from "swr";
import i18n from "@/i18n";
import { Toaster } from "@/components/ui/sonner";
import { HostProfilesPage } from "./HostProfilesPage";

// 有状态 store：POST 后追加，模拟真实后端语义——否则提交后 refresh 仍返初始列表。
let store: Record<string, unknown>[];

const server = setupServer(
  http.get("/api/workspaces/:ws/host-profiles", () => HttpResponse.json(store)),
  http.post("/api/workspaces/:ws/host-profiles", async ({ request }) => {
    const body = (await request.json()) as Record<string, unknown>;
    const p = { ...body, id: "host_1", created_at: "", updated_at: "" };
    store = [...store, p];
    return HttpResponse.json(p);
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
// jsdom navigator.language 默认 en，LanguageDetector 会把 i18n 切到 en；现有断言依赖中文渲染，钉回 zh。
beforeEach(() => {
  i18n.changeLanguage("zh");
  store = [];
});
afterEach(() => { server.resetHandlers(); cleanup(); });
afterAll(() => server.close());

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/p/ws1/host-profiles"]}>
      {/* SWR 迁移适配（spec §6.5）：独立 cache 隔离。 */}
      <SWRConfig value={{ provider: () => new Map() }}>
        <Routes>
          <Route path="/p/:workspace/host-profiles" element={<><HostProfilesPage /><Toaster /></>} />
        </Routes>
      </SWRConfig>
    </MemoryRouter>,
  );
}

describe("HostProfilesPage", () => {
  it("列表 + 新建档案", async () => {
    renderPage();
    await waitFor(() => expect(screen.getByText("暂无 HOST 档案")).toBeInTheDocument());
    // 工具栏按钮（此时对话框未开，仅此一个 "新建档案" button）
    fireEvent.click(screen.getByRole("button", { name: "新建档案" }));
    fireEvent.change(screen.getByLabelText("档案名"), { target: { value: "华南生产" } });
    // mappings 行编辑器（IP / 域名 两列）
    fireEvent.change(screen.getByLabelText("IP"), { target: { value: "10.0.0.1" } });
    fireEvent.change(screen.getByLabelText("域名"), { target: { value: "api.test" } });
    // 对话框提交按钮文案 = "保存"（区别于工具栏 "新建档案"，无需 within 消歧）
    fireEvent.click(screen.getByRole("button", { name: "保存" }));
    await waitFor(() => expect(screen.getByText("华南生产")).toBeInTheDocument());
  });

  it("更新时间列渲染紧凑格式，完整 ISO 串进 title（曾 32 字符 ISO 溢出 w-36 挤到操作按钮）", async () => {
    const iso = "2026-09-11T08:30:45.123456+00:00";
    store = [{ id: "h1", name: "prod", mappings: [], created_at: iso, updated_at: iso }];
    renderPage();
    await waitFor(() => expect(screen.getByText("prod")).toBeInTheDocument());
    // 形状断言（时区无关）：MM-DD HH:mm 紧凑口径，对齐 fmtTime
    expect(screen.getByTitle(iso)).toHaveTextContent(/^\d{2}-\d{2} \d{2}:\d{2}$/);
    // 原始机器串不得直接作为单元格文本
    expect(screen.queryByText(iso)).not.toBeInTheDocument();
  });

  it("空时间戳兜底为 -（system fork 副本 updated_at/created_at 均清空）", async () => {
    store = [{ id: "h2", name: "forked", mappings: [], created_at: "", updated_at: "" }];
    renderPage();
    await waitFor(() => expect(screen.getByText("forked")).toBeInTheDocument());
    // 时间列不显示 "—" 长破折号，统一 fmtTime 口径 "-"
    expect(screen.queryByText("—")).not.toBeInTheDocument();
  });
});
