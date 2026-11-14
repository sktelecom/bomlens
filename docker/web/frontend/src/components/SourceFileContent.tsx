// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import {
  AlertIcon,
  FileCodeIcon,
  FileIcon,
  FileSymlinkFileIcon,
  WrapIcon,
} from "@primer/octicons-react";
import { Button, Label } from "@primer/react";
import { type ReactNode, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { languageForPath, splitHighlightedLines } from "@/lib/highlight";
import { highlightSource } from "@/lib/highlight-runtime";
import {
  lineCount,
  missingReason,
  type SnapshotFile,
  type SourceSnapshot,
} from "@/lib/sourceSnapshot";
import { formatBytes } from "@/lib/utils";

import "./source-tree.css";

/**
 * How many lines render before the reader asks for the rest. A captured file can
 * be a 256 KB lockfile: thousands of DOM rows would stall the section for a
 * view nobody scrolls to the end of. Same "show more" contract the component
 * table uses.
 */
const VISIBLE_LINES = 1500;

/**
 * The selected file's captured text, or an honest reason there is none.
 * Mount it with `key={path}` so "show the rest" and the wrap choice never carry
 * over to another file.
 */
export function SourceFileContent({
  snapshot,
  file,
  linkTarget,
  noSnapshot = false,
  path,
}: {
  snapshot: SourceSnapshot | null;
  /** The snapshot entry for `path`, when the capture included its content. */
  file: SnapshotFile | null;
  /** Where `path` points, when it is a symlink rather than a file. */
  linkTarget?: string | null;
  /** The scan stored no file contents at all (no `_source.json`), as opposed to
   *  one file missing from a snapshot that exists. */
  noSnapshot?: boolean;
  /** Selected tree path; null before the reader picks a file. */
  path: string | null;
}) {
  const { t } = useTranslation();
  const [expanded, setExpanded] = useState(false);
  // Long lines wrap by default, as they always did; the switch lets a reader
  // turn that off to scroll sideways instead.
  const [wrap, setWrap] = useState(true);

  const lines = useMemo(() => {
    if (!file) return [];
    const body = file.content.endsWith("\n") ? file.content.slice(0, -1) : file.content;
    return body.length ? body.split("\n") : [];
  }, [file]);

  // Highlighted markup, one balanced fragment per line, or null while the
  // grammar loads and for anything without one.
  const [highlighted, setHighlighted] = useState<string[] | null>(null);
  const language = path ? languageForPath(path) : null;

  useEffect(() => {
    setHighlighted(null);
    if (!file || !language || !lines.length) return;
    let cancelled = false;
    // Loaded on demand: the grammars are the bulk of the highlighter, and a
    // reader who never opens a file should not pay for them.
    void highlightSource(file.content, language).then((html) => {
      if (!cancelled && html !== null) setHighlighted(splitHighlightedLines(html));
    });
    return () => {
      cancelled = true;
    };
  }, [file, language, lines.length]);

  if (!path) {
    return (
      <div className="bl-src-empty bl-muted">
        <FileCodeIcon size={24} />
        <span>{t("sourceViewer.selectPrompt")}</span>
      </div>
    );
  }

  // A symlink holds a destination, not content. Saying where it points is the
  // whole answer; in a container image it is usually busybox, which is why
  // that one command appears under a hundred different names.
  if (linkTarget) {
    return (
      <>
        <FileHead path={path}>
          <Label variant="secondary">{t("sourceViewer.symlink")}</Label>
        </FileHead>
        <div className="bl-src-empty bl-muted">
          <FileSymlinkFileIcon size={16} />
          <span>
            {t("sourceViewer.symlinkTo")} <code className="bl-mono">{linkTarget}</code>
          </span>
        </div>
      </>
    );
  }

  if (!file && noSnapshot) {
    return (
      <>
        <FileHead path={path} />
        <div className="bl-src-empty bl-muted">
          <FileIcon size={16} />
          <span>{t("sourceViewer.noSnapshot")}</span>
        </div>
      </>
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
      <>
        <FileHead path={path} />
        <div className="bl-src-empty bl-muted">
          <AlertIcon size={16} />
          <span>{t(key)}</span>
        </div>
      </>
    );
  }

  const shown = expanded ? lines : lines.slice(0, VISIBLE_LINES);
  const hidden = lines.length - shown.length;

  return (
    <>
      <FileHead path={path}>
        <span className="bl-muted bl-small">
          {t("sourceViewer.lines", { count: lineCount(file.content) })}
        </span>
        <span className="bl-muted bl-small">{formatBytes(file.size)}</span>
        {file.truncated && <Label variant="attention">{t("sourceViewer.truncated")}</Label>}
        <Button
          size="small"
          variant="invisible"
          leadingVisual={WrapIcon}
          aria-pressed={wrap}
          onClick={() => setWrap((w) => !w)}
        >
          {t("sourceViewer.wrap")}
        </Button>
      </FileHead>

      <div className="bl-src-code-scroll">
        <table className={wrap ? "bl-src-code bl-src-wrap" : "bl-src-code"}>
          <tbody>
            {shown.map((line, i) => (
              <tr key={i}>
                <td className="bl-src-ln" aria-hidden="true">
                  {i + 1}
                </td>
                {highlighted?.[i] !== undefined ? (
                  <td
                    className="bl-src-lc"
                    // The markup is the highlighter's, whose text it already
                    // escaped; lib/highlight only rebalances the tags around it.
                    dangerouslySetInnerHTML={{ __html: highlighted[i] || " " }}
                  />
                ) : (
                  <td className="bl-src-lc">{line || " "}</td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {hidden > 0 && (
        <div className="bl-src-foot">
          <Button size="small" onClick={() => setExpanded(true)}>
            {t("sourceViewer.showAll", { count: hidden })}
          </Button>
        </div>
      )}
      {file.truncated && (expanded || hidden === 0) && (
        <p className="bl-muted bl-small bl-src-foot">{t("sourceViewer.truncatedFoot")}</p>
      )}
    </>
  );
}

function FileHead({ path, children }: { path: string; children?: ReactNode }) {
  return (
    <div className="bl-src-head">
      <FileCodeIcon size={16} />
      <span className="bl-mono bl-src-path">{path}</span>
      {children && <span className="bl-src-meta">{children}</span>}
    </div>
  );
}
