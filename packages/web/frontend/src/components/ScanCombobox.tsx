import { useMemo, useState } from "react";
import { Check, ChevronsUpDown } from "lucide-react";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import {
  Command,
  CommandEmpty,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import type { ScanSummary } from "@/api/types";

export interface ScanComboboxProps {
  /** 候选任务（调用方已按业务口径过滤，组件只管展示 + 搜索） */
  scans: ScanSummary[];
  /** 选中 scan_id（"" = 未选） */
  value: string;
  onChange: (scanId: string) => void;
  /** 触发器未选中时的占位文案 */
  placeholder?: string;
  /** 搜索输入框占位文案 */
  searchPlaceholder?: string;
  /** 无候选任务时的空态文案 */
  emptyText?: string;
  /** 候选是否在加载中（加载态优先于空态展示） */
  loading?: boolean;
  /** 候选加载中文案 */
  loadingText?: string;
  /** 禁用（如未选工作区） */
  disabled?: boolean;
}

/** 任务单选可搜索下拉（与 RepoCombobox/BranchCombobox 同模式：Popover + Command +
 *  shouldFilter={false} 自管过滤，不做代码级泛化）。
 *
 * 搜索匹配 workflow_id / scan_id / repo 三路子串（大小写不敏感）；单选语义——
 * onSelect 即替换选中并收起（黑盒表单选白盒任务等场景，候选多时靠搜索定位）。 */
export function ScanCombobox({
  scans,
  value,
  onChange,
  placeholder = "Select scan",
  searchPlaceholder = "Search...",
  emptyText = "No match",
  loading = false,
  loadingText,
  disabled,
}: ScanComboboxProps) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");

  const selected = scans.find((s) => s.scan_id === value);
  const selectedLabel = selected
    ? (selected.workflow_id ?? selected.scan_id)
    : placeholder;

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return scans;
    return scans.filter((s) =>
      [s.workflow_id ?? "", s.scan_id, s.repo ?? ""]
        .some((f) => f.toLowerCase().includes(q)));
  }, [scans, query]);

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          type="button"
          variant="outline"
          role="combobox"
          aria-expanded={open}
          disabled={disabled}
          className="w-full justify-between font-normal font-mono text-xs"
        >
          <span className={cn("min-w-0 truncate", !selected && "text-muted-foreground")}>
            {selectedLabel}
          </span>
          <ChevronsUpDown className="h-4 w-4 shrink-0 opacity-50" />
        </Button>
      </PopoverTrigger>
      <PopoverContent
        className="w-[var(--radix-popover-trigger-width)] p-0"
        align="start"
      >
        <Command shouldFilter={false}>
          <CommandInput
            placeholder={searchPlaceholder}
            onValueChange={setQuery}
          />
          <CommandList>
            {loading ? (
              <div className="px-3 py-2 text-xs text-muted-foreground">
                {loadingText}
              </div>
            ) : null}
            {!loading && <CommandEmpty>{emptyText}</CommandEmpty>}
            {filtered.map((s) => {
              const isSel = s.scan_id === value;
              return (
                <CommandItem
                  key={s.scan_id}
                  value={s.scan_id}
                  onSelect={() => {
                    onChange(s.scan_id);
                    setOpen(false);
                  }}
                  className="gap-2"
                >
                  <Check
                    className={cn(
                      "h-4 w-4 shrink-0",
                      isSel ? "opacity-100" : "opacity-0",
                    )}
                  />
                  <span className="truncate font-mono text-xs">
                    {s.workflow_id ?? s.scan_id}
                  </span>
                  {s.repo && (
                    <span className="ml-auto shrink-0 truncate text-xs text-muted-foreground">
                      {s.repo}
                    </span>
                  )}
                </CommandItem>
              );
            })}
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}
