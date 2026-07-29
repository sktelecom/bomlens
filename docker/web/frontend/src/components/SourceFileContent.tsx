import { FileCode, FileSymlink, FileWarning } from "lucide-react";
import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/state";
import {
  lineCount,
  missingReason,
  type SnapshotFile,
  type SourceSnapshot,
} from "@/lib/sourceSnapshot";
import { formatBytes } from "@/lib/utils";

/**
 * How many lines render before the reader asks for the rest. A captured file can
 * be a 256 KB lockfile — thousands of DOM rows would stall the section for a
 * view nobody scrolls to the end of. Same "show more" contract the component
 * table uses.
 */
const VISIBLE_LINES = 1500;

/** The selected file's captured text, or an honest reason there is none. */
export function SourceFileContent({
  snapshot,
  file,
  linkTarget,
  path,
}: {
  snapshot: SourceSnapshot | null;
  /** The snapshot entry for `path`, when the capture included its content. */
  file: SnapshotFile | null;
  /** Where `path` points, when it is a symlink rather than a file. */
  linkTarget?: string | null;
  /** Selected tree path; null before the reader picks a file. */
  path: string | null;
}) {
  const { t } = useTranslation();
  const [expanded, setExpanded] = useState(false);

  const lines = useMemo(() => {
    if (!file) return [];
    const body = file.content.endsWith("\n")
      ? file.content.slice(0, -1)
      : file.content;
    return body.length ? body.split("\n") : [];
  }, [file]);

  if (!path) {
    return (
      <EmptyState icon={FileCode}>{t("sourceViewer.selectPrompt")}</EmptyState>
    );
  }

  // A symlink holds a destination, not content. Saying where it points is the
  // whole answer — and in a container image it is usually busybox, which is why
  // that one command appears under a hundred different names.
  if (linkTarget) {
    return (
      <div className="flex h-full flex-col">
        <FileHeader path={path}>
          <Badge variant="muted">{t("sourceViewer.symlink")}</Badge>
        </FileHeader>
        <div className="flex flex-1 items-center justify-center p-6">
          <p className="flex flex-wrap items-center justify-center gap-2 text-sm text-muted-foreground">
            <FileSymlink className="h-4 w-4 shrink-0" />
            {t("sourceViewer.symlinkTo")}
            <code className="break-all rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-foreground">
              {linkTarget}
            </code>
          </p>
        </div>
      </div>
    );
  }

  if (!file) {
    const reason = missingReason(snapshot, path);
    const key =
      reason === "binary"
        ? "sourceViewer.missingBinary"
        : reason === "budget"
          ? "sourceViewer.missingBudget"
          : "sourceViewer.missingUnknown";
    return (
      <div className="flex h-full flex-col">
        <FileHeader path={path} />
        <div className="flex flex-1 items-center justify-center p-6">
          <p className="flex items-center gap-2 text-sm text-muted-foreground">
            <FileWarning className="h-4 w-4 shrink-0" />
            {t(key)}
          </p>
        </div>
      </div>
    );
  }

  const shown = expanded ? lines : lines.slice(0, VISIBLE_LINES);
  const hidden = lines.length - shown.length;

  return (
    <div className="flex h-full flex-col">
      <FileHeader path={path}>
        <span className="shrink-0 text-xs text-muted-foreground">
          {t("sourceViewer.lines", { count: lineCount(file.content) })}
        </span>
        <span className="shrink-0 text-xs text-muted-foreground">
          {formatBytes(file.size)}
        </span>
        {file.truncated && (
          <Badge variant="muted">{t("sourceViewer.truncated")}</Badge>
        )}
      </FileHeader>

      <div className="flex-1 overflow-auto">
        <table className="w-full border-collapse font-mono text-xs">
          <tbody>
            {shown.map((line, i) => (
              <tr key={i} className="align-top">
                <td
                  className="w-[1%] select-none whitespace-nowrap border-r px-2 py-0.5 text-right text-muted-foreground"
                  aria-hidden="true"
                >
                  {i + 1}
                </td>
                <td className="whitespace-pre-wrap break-all px-3 py-0.5">
                  {line || " "}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {hidden > 0 && (
          <div className="border-t p-2 text-center">
            <Button variant="outline" size="sm" onClick={() => setExpanded(true)}>
              {t("sourceViewer.showAll", { count: hidden })}
            </Button>
          </div>
        )}
        {file.truncated && expanded && (
          <p className="border-t p-2 text-center text-xs text-muted-foreground">
            {t("sourceViewer.truncatedFoot")}
          </p>
        )}
      </div>
    </div>
  );
}

function FileHeader({
  path,
  children,
}: {
  path: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="flex items-center gap-3 border-b px-3 py-2">
      <span className="truncate font-mono text-xs" title={path}>
        {path}
      </span>
      <span className="ml-auto flex items-center gap-3">{children}</span>
    </div>
  );
}
