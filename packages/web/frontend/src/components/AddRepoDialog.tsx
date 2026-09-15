import { useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { createRepo, batchClone, linkReposInDir, uploadRepoZip, ApiError } from "@/api/client";
import { useAuth } from "@/auth/AuthContext";
import { FileSystemPicker } from "@/components/FileSystemPicker";
import { cn } from "@/lib/utils";

interface Props {
  /** P2: 仓库落在 ws 内，调用 createRepo(ws, body) / linkReposInDir(ws, body) */
  ws: string;
  open: boolean;
  onOpenChange: (o: boolean) => void;
  onCreated: (name: string) => void;
  /** 批量克隆提交成功回调（2026-09-11 批量白盒预选增强）：传本批全部新仓库名
   *  （submitted+queued，skipped 不含）——调用方（白盒表单）把它们预选进多选列表。
   *  可选：不传则维持旧行为 onCreated(首个)。 */
  onBatchCreated?: (names: string[]) => void;
}

type Mode = "clone" | "linkdir" | "upload";

export function AddRepoDialog({ ws, open, onOpenChange, onCreated, onBatchCreated }: Props) {
  const { t } = useTranslation();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const [mode, setMode] = useState<Mode>("clone");
  const [url, setUrl] = useState("");
  const [branch, setBranch] = useState("");
  const [commit, setCommit] = useState("");
  const [group, setGroup] = useState("");
  const [linkDirPath, setLinkDirPath] = useState("");
  const [busy, setBusy] = useState(false);
  // upload 模式：多 zip 各成一仓（name 自动取文件名）；name 覆盖仅单文件时生效
  const [files, setFiles] = useState<File[]>([]);
  const [customName, setCustomName] = useState("");
  const [dragOver, setDragOver] = useState(false);
  const [uploadPct, setUploadPct] = useState<number | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // 批量克隆（2026-09-09）：一行一条 URL——1 条 = 现有单条路径（branch/commit 保留），
  // ≥2 条 = 批量（branch/commit 隐藏，group 共享，提交走 batchClone）
  const urlLines = url.split("\n").map((l) => l.trim()).filter(Boolean);
  const isBatch = urlLines.length > 1;
  const badLineNos = urlLines
    .map((l, i) => ({ l, n: i + 1 }))
    .filter(({ l }) => !/^(https?:|git@|ssh:)/.test(l))
    .map(({ n }) => n);
  const urlOk = urlLines.length > 0 && badLineNos.length === 0;
  const linkDirOk = linkDirPath.trim() !== "";
  const derivedName = files.length === 1 ? files[0].name.replace(/\.zip$/i, "") : "";
  const canSubmit = mode === "clone" ? urlOk : mode === "linkdir" ? linkDirOk : files.length > 0;

  function reset() {
    setUrl(""); setBranch(""); setCommit(""); setGroup(""); setLinkDirPath("");
    setFiles([]); setCustomName(""); setUploadPct(null);
  }

  function pickFiles(list: FileList | null) {
    if (!list) return;
    const zips = Array.from(list).filter((f) => /\.zip$/i.test(f.name));
    const rejected = list.length - zips.length;
    if (rejected > 0) toast.error(t("repos.addDialog.uploadNotZip", { count: rejected }));
    if (zips.length) setFiles(zips);
  }

  async function submit() {
    try {
      setBusy(true);
      if (mode === "clone" && isBatch) {
        // 批量：urls + 共享 group；clone 均为后端后台任务（列表轮询可见），
        // queued（撞并发上限排队补位）与 skipped 汇总 toast。
        const r = await batchClone(ws, {
          urls: urlLines,
          group: group.trim() || undefined,
        });
        toast.success(t("repos.addDialog.batchResult",
          { submitted: r.submitted.length, queued: r.queued.length, skipped: r.skipped.length }));
        const names = [...r.submitted, ...r.queued];
        if (onBatchCreated) onBatchCreated(names);
        else onCreated(r.submitted[0] ?? r.queued[0] ?? "");
      } else if (mode === "clone") {
        const r = await createRepo(ws, {
          git_url: url.trim(),
          branch: branch.trim() || undefined,
          commit: commit.trim() || undefined,
          group: group.trim() || undefined,
        });
        onCreated(r.name);
      } else if (mode === "upload") {
        // 逐个上传：总进度 = (已完成数 + 当前文件进度) / 总数；name 覆盖仅单文件生效
        const nameOverride = files.length === 1 ? (customName.trim() || undefined) : undefined;
        for (let i = 0; i < files.length; i++) {
          const r = await uploadRepoZip(
            ws, files[i],
            { name: nameOverride, group: group.trim() || undefined },
            (pct) => setUploadPct(Math.round(((i + pct / 100) / files.length) * 100)),
          );
          if (i === 0) onCreated(r.name);
        }
        toast.success(t("repos.addDialog.uploadAccepted", { count: files.length }));
      } else {
        // 批量关联目录：扫描父目录下所有 git 仓库；toast 汇报 imported/skipped
        const res = await linkReposInDir(ws, { path: linkDirPath.trim() });
        toast.success(t("repos.addDialog.linkDirResult",
          { imported: res.imported.length, skipped: res.skipped.length }));
        onCreated(res.imported[0]?.name ?? "");
      }
      onOpenChange(false);
      reset();
    } catch (e) {
      if (e instanceof ApiError) {
        if (mode === "clone" && e.status === 503) toast.error(t("repos.addDialog.errors.noCreds"));
        else if (mode === "clone" && e.status === 409) toast.error(t("repos.addDialog.errors.exists"));
        else if (mode === "linkdir" && e.status === 422) toast.error(t("repos.addDialog.errors.badPath"));
        else if (mode === "upload" && e.status === 413) toast.error(t("repos.addDialog.errors.tooLarge"));
        else if (mode === "upload" && e.status === 409) toast.error(t("repos.addDialog.errors.exists"));
        // 兜底（2026-09-15）：后端人话 detail（如「单次最多 500 条 URL」）优先透出，
        // 无 detail 才回落状态码文案。只认 string——pydantic 校验错误的 detail 是
        // 数组形态，透出仍是天书，不如裸状态码。
        else {
          const detail = typeof (e.body as { detail?: unknown } | null)?.detail === "string"
            ? (e.body as { detail: string }).detail : "";
          toast.error(detail || t("repos.addDialog.errors.failed", { status: e.status }));
        }
      } else {
        toast.error(t("repos.addDialog.errors.network"));
        console.error(`${mode} failed:`, e);
      }
    } finally {
      setBusy(false);
      setUploadPct(null);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent onInteractOutside={(e) => e.preventDefault()} onEscapeKeyDown={(e) => { if (busy) e.preventDefault(); }}>
        <DialogHeader>
          <DialogTitle>{t("repos.addDialog.title")}</DialogTitle>
          <DialogDescription>
            {mode === "clone" ? t("repos.addDialog.desc")
              : mode === "upload" ? t("repos.addDialog.uploadDesc")
              : t("repos.addDialog.linkDirDesc")}
          </DialogDescription>
        </DialogHeader>

        {/* 模式切换：克隆 git 仓库（所有人）/ 上传 zip（所有人）/ 批量关联目录（admin-only，
            任意磁盘路径较敏感）。非 admin 可见 clone + upload 两个模式。 */}
        <div className="flex flex-wrap gap-2">
          <Button
            data-testid="mode-clone" size="sm"
            variant={mode === "clone" ? "default" : "outline"}
            onClick={() => setMode("clone")}
          >
            {t("repos.addDialog.modeClone")}
          </Button>
          <Button
            data-testid="mode-upload" size="sm"
            variant={mode === "upload" ? "default" : "outline"}
            onClick={() => setMode("upload")}
          >
            {t("repos.addDialog.modeUpload")}
          </Button>
          {isAdmin && (
            <Button
              data-testid="mode-linkdir" size="sm"
              variant={mode === "linkdir" ? "default" : "outline"}
              onClick={() => setMode("linkdir")}
            >
              {t("repos.addDialog.modeLinkDir")}
            </Button>
          )}
        </div>

        {mode === "clone" ? (
          <div className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor="repo-url">{t("repos.addDialog.urlLabel")}</Label>
              <Textarea
                id="repo-url" data-testid="repo-urls" rows={4}
                value={url} onChange={(e) => setUrl(e.target.value)}
                placeholder={t("repos.addDialog.urlPlaceholder")}
                className="font-mono min-h-0"
              />
              {badLineNos.length > 0 && (
                <div className="text-xs text-destructive">
                  {t("repos.addDialog.urlLinesError", { lines: badLineNos.join(", ") })}
                </div>
              )}
              {!urlOk && urlLines.length > 0 && badLineNos.length === 0 && (
                <div className="text-xs text-destructive">{t("repos.addDialog.urlError")}</div>
              )}
              {isBatch && (
                <div className="text-[11px] text-muted-foreground">{t("repos.addDialog.batchHint")}</div>
              )}
            </div>
            <div className="space-y-1">
              <Label htmlFor="repo-group">{t("repos.addDialog.groupLabel")}</Label>
              <Input id="repo-group" value={group} onChange={(e) => setGroup(e.target.value)} placeholder={t("repos.addDialog.groupPlaceholder")} />
            </div>
            {/* branch/commit 是单仓库精确定位字段——多行批量时无意义，隐藏 */}
            {!isBatch && (
              <div className="flex gap-2">
                <Input value={branch} onChange={(e) => setBranch(e.target.value)} placeholder={t("repos.addDialog.branchPlaceholder")} />
                <Input value={commit} onChange={(e) => setCommit(e.target.value)} placeholder={t("repos.addDialog.commitPlaceholder")} />
              </div>
            )}
          </div>
        ) : mode === "upload" ? (
          <div className="space-y-3">
            {/* 拖拽区：drag&drop + 点击选择（双入口）；仅收 .zip */}
            <div
              data-testid="upload-dropzone"
              role="button"
              tabIndex={0}
              aria-label={t("repos.addDialog.uploadDropzone")}
              className={cn(
                "flex cursor-pointer flex-col items-center justify-center gap-1 rounded-md border border-dashed px-4 py-8 text-center transition-colors",
                dragOver ? "border-cyan bg-cyan/5" : "border-border hover:bg-muted/40",
              )}
              onClick={() => fileInputRef.current?.click()}
              onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") fileInputRef.current?.click(); }}
              onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              onDrop={(e) => { e.preventDefault(); setDragOver(false); pickFiles(e.dataTransfer.files); }}
            >
              <div className="text-sm text-muted-foreground">{t("repos.addDialog.uploadDropzone")}</div>
              <div className="text-xs text-muted-foreground/60">{t("repos.addDialog.uploadHint")}</div>
            </div>
            <input
              ref={fileInputRef} data-testid="upload-file-input" type="file" accept=".zip" multiple
              className="hidden"
              onChange={(e) => { pickFiles(e.target.files); e.target.value = ""; }}
            />
            {files.length > 0 && (
              <ul data-testid="upload-file-list" className="max-h-28 space-y-1 overflow-auto rounded-md border border-border bg-muted/30 p-2">
                {files.map((f) => (
                  <li key={f.name} className="flex items-center justify-between gap-2 font-mono text-xs">
                    <span className="min-w-0 flex-1 truncate">{f.name}</span>
                    <button
                      type="button" className="text-xs text-muted-foreground hover:text-destructive"
                      aria-label={t("repos.addDialog.uploadRemove", { name: f.name })}
                      disabled={busy}
                      onClick={() => setFiles((prev) => prev.filter((x) => x !== f))}
                    >
                      ✕
                    </button>
                  </li>
                ))}
              </ul>
            )}
            {files.length === 1 && (
              <div className="space-y-1">
                <Label htmlFor="upload-name">{t("repos.addDialog.uploadNameLabel")}</Label>
                {/* 自定义仓库名（后端表单字段覆盖 zip 文件名派生）；留空 = 用文件名。
                    File.name 只读，customName 是独立 state 而非改 File。 */}
                <Input
                  id="upload-name" data-testid="upload-name" value={customName}
                  placeholder={derivedName}
                  onChange={(e) => setCustomName(e.target.value)}
                />
              </div>
            )}
            <div className="space-y-1">
              <Label htmlFor="upload-group">{t("repos.addDialog.groupLabel")}</Label>
              <Input id="upload-group" value={group} onChange={(e) => setGroup(e.target.value)} placeholder={t("repos.addDialog.groupPlaceholder")} />
            </div>
            {uploadPct !== null && (
              <div data-testid="upload-progress" className="text-xs text-muted-foreground">
                {t("repos.addDialog.uploadProgress", { pct: uploadPct })}
              </div>
            )}
          </div>
        ) : (
          <div className="space-y-2">
            <Label htmlFor="linkdir-path">{t("repos.addDialog.linkDirPathLabel")}</Label>
            <div className="flex gap-2">
              <Input data-testid="linkdir-path" id="linkdir-path" value={linkDirPath}
                     onChange={(e) => setLinkDirPath(e.target.value)}
                     placeholder={t("repos.addDialog.linkDirPathPlaceholder")} className="font-mono" />
              <FileSystemPicker value={linkDirPath} onChange={(v) => setLinkDirPath(v)}
                                triggerLabel={t("scan.fields.browse")}
                                title={t("repos.addDialog.linkDirPathLabel")} />
            </div>
          </div>
        )}

        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>{t("common.cancel")}</Button>
          <Button data-testid="submit" disabled={!canSubmit || busy} onClick={submit}>
            {mode === "clone" ? t("repos.addDialog.cloneBtn")
              : mode === "upload" ? t("repos.addDialog.uploadBtn")
              : t("repos.addDialog.linkDirBtn")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
