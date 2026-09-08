import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { X, Plus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { getUserWorkspaces, type UserRow, type UserWorkspace } from "@/api/users";
import { addMember, removeMember } from "@/api/members";
import { apiPatch, apiGet } from "@/api/client";

type WsInfo = { name: string };
type MemberOf = Record<string, "manager" | "member">;

export function UserWorkspacesPanel({ user }: { user: UserRow }) {
  const { t } = useTranslation();
  const [memberOf, setMemberOf] = useState<MemberOf>({});
  const [allWs, setAllWs] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);

  async function load() {
    setLoading(true);
    try {
      const [own, wsList] = await Promise.all([
        getUserWorkspaces(user.id),
        apiGet<WsInfo[]>("/workspaces"),
      ]);
      const map: MemberOf = {};
      own.workspaces.forEach((w: UserWorkspace) => { map[w.workspace] = w.role; });
      setMemberOf(map);
      setAllWs(wsList.map((w) => w.name));
    } catch {
      // 面内错误态：静默，loading 结束后展示空/既有
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => { void load(); }, [user.id]);

  async function onAdd(ws: string) {
    try {
      await addMember(ws, user.username, "member");
      toast.success(t("users.members.saved"));
      void load();
    } catch {
      toast.error(t("users.members.saveFailed"));
      void load();
    }
  }
  async function onRoleChange(ws: string, role: "manager" | "member") {
    try {
      await apiPatch(`/workspaces/${encodeURIComponent(ws)}/members/${encodeURIComponent(user.username)}`, { role });
      toast.success(t("users.members.saved"));
      void load();
    } catch {
      toast.error(t("users.members.saveFailed"));
      void load();
    }
  }
  async function onRemove(ws: string) {
    try {
      await removeMember(ws, user.username);
      toast.success(t("users.members.saved"));
      void load();
    } catch {
      toast.error(t("users.members.saveFailed"));
      void load();
    }
  }

  if (loading) return <Skeleton className="h-20 w-full" />;
  const assigned = Object.keys(memberOf).length;
  return (
    <div className="overflow-hidden rounded-lg border border-border bg-card" data-testid={`wsp-${user.username}`}>
      {/* 标题条：归属标题 + 已分配计数 */}
      <div className="flex items-center justify-between border-b border-border px-3 py-2">
        <span className="text-xs font-medium text-muted-foreground">{t("users.members.title")}</span>
        <Badge variant="outline" className="font-mono text-[11px] text-muted-foreground">{assigned}/{allWs.length}</Badge>
      </div>
      {/* 行：ws 名 + （已加入：角色 select + 移除） / （未加入：加入按钮），细分线分隔 */}
      <div className="divide-y divide-border">
        {allWs.length === 0 && (
          <p className="px-3 py-2 text-sm text-muted-foreground">{t("users.members.empty")}</p>
        )}
        {allWs.map((ws) => {
          const role = memberOf[ws];
          return (
            <div key={ws} className="flex items-center justify-between gap-2 px-3 py-2 text-sm">
              <span className="truncate font-mono">{ws}</span>
              <div className="flex shrink-0 items-center gap-1.5">
                {role ? (
                  <>
                    <Select value={role} onValueChange={(v) => onRoleChange(ws, v as "manager" | "member")}>
                      <SelectTrigger className="h-8 w-36"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="member">{t("users.members.wsMember")}</SelectItem>
                        <SelectItem value="manager">{t("users.members.wsManager")}</SelectItem>
                      </SelectContent>
                    </Select>
                    <Button variant="ghost" size="icon-sm" aria-label={t("users.members.remove")} title={t("users.members.remove")} onClick={() => onRemove(ws)}>
                      <X className="size-3.5" />
                    </Button>
                  </>
                ) : (
                  <Button variant="outline" size="sm" data-testid={`add-${ws}`} onClick={() => onAdd(ws)}>
                    <Plus className="size-3.5" /> {t("users.members.add")}
                  </Button>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
