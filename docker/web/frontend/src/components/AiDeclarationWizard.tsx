// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { Check, Loader2, Plus, Trash2, TriangleAlert, X } from "lucide-react";
import {
  createContext,
  useContext,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
  type ReactNode,
} from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Disclosure } from "@/components/ui/disclosure";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import type { Spdx3Failure } from "@/lib/api";
import {
  adapterWithoutBase,
  AGENT_TYPES,
  blankDeep,
  COMMON_LICENSES,
  DATASET_MORE_FIELDS,
  dataFlowFields,
  MAX_LABEL,
  REGULATORY_FIELDS,
  ROLES,
  SERVICE_GROUPS,
  SERVICE_REQUIRED_FIELDS,
  serviceDeclared,
  SOURCE_RELATIONS,
  dateToDeclared,
  declaredToDate,
  firstOpenIn,
  formatDay,
  isEmpty,
  isHubId,
  issues as findIssues,
  judgmentFields,
  LONG_TEXT,
  MODEL_USE_FIELDS,
  modelMainFields,
  MODEL_LICENSE_FIELD,
  openByStep,
  remainingRequired,
  required as isRequired,
  saveBlockers,
  stepOf,
  stepsFor,
  summaryGroups,
  toFile,
  TRAINING_FIELDS,
  MAX_TEXT,
  modelCdxValues,
  type Agent,
  type DataFlow,
  type Declaration,
  type ExternalModelEntry,
  type DictEntry,
  type FieldIndex,
  type Issue,
  type MapField,
  type ServiceAnswer,
  type SourceEntry,
  type Spdx3Check,
  type StepId,
  type SummaryRow,
  type Value,
} from "@/lib/aiDeclaration";
import {
  flushPendingIds,
  useAiDeclaration,
  type DeclarationAction,
  type PendingId,
  type Target,
} from "@/lib/useAiDeclaration";
import { cn } from "@/lib/utils";

/** The translation namespace of a question: `aiDecl.<ns>.<field>`. */
type Ns = "document" | "model" | "dataset" | "service" | "externalModel" | "dataFlow";

/** "Is a person involved in the AI's decisions?" answers the service's
 *  autonomyType the other way round: involved is "no" (not autonomous). */
const SERVICE_AUTONOMY_ORDER = ["no", "yes", "noAssertion"];
const SERVICE_AUTONOMY_KEY = "aiDecl.service.autonomyType.option";
const SERVICE_ANSWERS: ServiceAnswer[] = ["yes", "no", "later"];
/** What kind of data flows, offered while it is typed; any words can be typed. */
const CLASSIFICATION_KEYS = ["personal", "public", "internal"];

const textAreaClass =
  "flex min-h-[4.5rem] w-full rounded-lg border border-input bg-background px-3 py-2 text-sm ring-offset-background " +
  "placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2";

const chipClass = (on: boolean) =>
  cn(
    "rounded-full border px-3 py-1 text-sm transition-colors duration-fast ease-out-soft",
    "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
    on ? "border-foreground bg-foreground text-background" : "border-input hover:bg-muted",
  );

/**
 * A row of choices. As a single choice it follows the radio-group pattern: one
 * Tab stop, the arrow keys move and select, and choosing the selected option
 * again clears it (every one of these questions may be left unanswered). As a
 * multiple choice each option is a toggle button.
 */
function Choices({
  options,
  selected,
  onPick,
  labelOf,
  multi,
  labelledBy,
  describedBy,
  hintOf,
}: {
  options: string[];
  selected: string[];
  onPick: (value: string) => void;
  labelOf: (value: string) => string;
  multi?: boolean;
  labelledBy: string;
  describedBy?: string;
  /** A short explanation of an option, shown when the pointer rests on it. */
  hintOf?: (value: string) => string | undefined;
}) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  if (multi) {
    return (
      <div role="group" aria-labelledby={labelledBy} aria-describedby={describedBy} className="flex flex-wrap gap-2">
        {options.map((o) => (
          <button
            key={o}
            type="button"
            aria-pressed={selected.includes(o)}
            title={hintOf?.(o)}
            onClick={() => onPick(o)}
            className={chipClass(selected.includes(o))}
          >
            {labelOf(o)}
          </button>
        ))}
      </div>
    );
  }
  const current = options.findIndex((o) => selected.includes(o));
  const onKey = (e: KeyboardEvent, i: number) => {
    const step = e.key === "ArrowRight" || e.key === "ArrowDown" ? 1 : e.key === "ArrowLeft" || e.key === "ArrowUp" ? -1 : 0;
    if (!step) return;
    e.preventDefault();
    const next = (i + step + options.length) % options.length;
    refs.current[next]?.focus();
    if (!selected.includes(options[next])) onPick(options[next]);
  };
  return (
    <div role="radiogroup" aria-labelledby={labelledBy} aria-describedby={describedBy} className="flex flex-wrap gap-2">
      {options.map((o, i) => {
        const on = selected.includes(o);
        return (
          <button
            key={o}
            ref={(el) => {
              refs.current[i] = el;
            }}
            type="button"
            role="radio"
            aria-checked={on}
            tabIndex={i === (current >= 0 ? current : 0) ? 0 : -1}
            title={hintOf?.(o)}
            onClick={() => onPick(o)}
            onKeyDown={(e) => onKey(e, i)}
            className={chipClass(on)}
          >
            {labelOf(o)}
          </button>
        );
      })}
    </div>
  );
}

function AgentInput({
  value,
  onChange,
  id,
  label,
  describedBy,
  required,
  types,
}: {
  value: Agent | null;
  onChange: (v: Agent) => void;
  id?: string;
  /** Used when no <label> points at the input (a second row of a list). */
  label?: string;
  describedBy?: string;
  required?: boolean;
  /** The kinds of agent the field takes; one kind leaves nothing to choose. */
  types?: string[];
}) {
  const { t } = useTranslation();
  const only = types?.length === 1 ? types[0] : undefined;
  const v = value ?? { type: only ?? "Organization", name: "" };
  return (
    <div className="flex gap-2">
      <Input
        id={id}
        aria-label={label}
        aria-describedby={describedBy}
        aria-required={required || undefined}
        value={v.name}
        placeholder={only === "Organization" ? t("aiDecl.organizationPlaceholder") : t("aiDecl.agentPlaceholder")}
        onChange={(e) => onChange({ type: only ?? (v.type || "Organization"), name: e.target.value })}
      />
      {!only && <Select
        aria-label={t("aiDecl.agentType")}
        value={v.type || "Organization"}
        onChange={(e) => onChange({ type: e.target.value, name: v.name })}
        className="h-10 shrink-0"
      >
        {AGENT_TYPES.map((a) => (
          <option key={a} value={a}>
            {t(`aiDecl.agent.${a}`)}
          </option>
        ))}
      </Select>}
    </div>
  );
}

/** Rows that can be added and removed. An empty row stays while it is being
 *  typed in; empty rows are left out when the declaration is saved. */
function ListEditor<T>({
  items,
  blank,
  onChange,
  render,
  addLabel,
  removeLabel,
}: {
  items: T[];
  blank: T;
  onChange: (items: T[]) => void;
  render: (item: T, set: (v: T) => void, i: number) => ReactNode;
  addLabel: string;
  removeLabel: (i: number) => string;
}) {
  const rows = items.length ? items : [blank];
  return (
    <div className="space-y-2">
      {rows.map((it, i) => (
        <div key={i} className="flex items-start gap-2">
          <div className="min-w-0 flex-1">{render(it, (v) => onChange(rows.map((x, j) => (j === i ? v : x))), i)}</div>
          {rows.length > 1 && (
            <Button variant="ghost" size="sm" aria-label={removeLabel(i)} onClick={() => onChange(rows.filter((_, j) => j !== i))}>
              <X className="h-4 w-4" />
            </Button>
          )}
        </div>
      ))}
      <Button variant="outline" size="sm" onClick={() => onChange([...rows, blank])}>
        <Plus className="h-3.5 w-3.5" />
        {addLabel}
      </Button>
    </div>
  );
}

/** One question: the label, its input by the field's type, and what is wrong.
 *  A problem shows once the person has left the field, not while typing. A
 *  required field left empty says so from the start, but quietly: it turns
 *  red only once the field was left or the person tried to leave the step. */
function Field({
  ns,
  where,
  field,
  value,
  problem,
  onChange,
  showProblems,
  hintKey,
  suggestions,
  warning,
  optionOrder,
  optionKey,
}: {
  ns: Ns;
  /** "document", "model" or "datasets[i]", so a jump can find the field. */
  where: string;
  field: MapField;
  value: Value | undefined;
  problem?: Issue["problem"];
  onChange: (v: Value) => void;
  /** Show the problem even if the field was not left yet (on the review step's
   *  way back here, for instance). */
  showProblems?: boolean;
  /** The hint to show instead of the field's own one. */
  hintKey?: string;
  /** Values to offer while typing (a text field only). */
  suggestions?: string[];
  /** Advice that does not stop saving, shown under the field. */
  warning?: string;
  /** The order a choice's options are offered in, when not the mapping's. */
  optionOrder?: string[];
  /** Where a choice's option labels are, when not the shared `aiDecl.enum`. */
  optionKey?: string;
}) {
  const { t } = useTranslation();
  const id = useId();
  const labelId = `${id}-label`;
  const hintId = `${id}-hint`;
  const errId = `${id}-err`;
  const listId = `${id}-list`;
  const [touched, setTouched] = useState(false);
  const key = `aiDecl.${ns}.${field.id}`;
  const label = t(`${key}.label`, { defaultValue: field.id });
  // A required field the converter writes as "unknown" when empty is not open.
  const required = isRequired(field);
  const ownHint = t(hintKey ?? `${key}.hint`, { defaultValue: "" });
  const hint = [ownHint, field.source.fallback === "noAssertion" ? t("aiDecl.fallbackHint") : ""]
    .filter(Boolean)
    .join(" ");
  const example = t(`${key}.example`, { defaultValue: "" });
  // Agents, dates and addresses have no "unknown": empty fails validation.
  const noUnknown = ["Agent", "DateTime", "anyURI"].includes(field.type);
  const showMissing = required && noUnknown && isEmpty(value);
  const loud = touched || Boolean(showProblems);
  const showProblem = Boolean(problem && problem !== "required" && loud);
  const describedBy = [hint && hintId, (showMissing || showProblem) && errId].filter(Boolean).join(" ") || undefined;
  const isList = field.max === "*" && !field.enum;
  const rowLabel = (i: number) => `${label} ${i + 1}`;

  let input: ReactNode;
  if (field.enum) {
    const opts = field.enum.filter((o) => o !== "noAssertion" || field.noAssertion);
    // The vocabulary's own "unknown" goes last, where a person looks for it.
    opts.sort((a, b) => Number(a === "noAssertion") - Number(b === "noAssertion"));
    if (optionOrder) opts.sort((a, b) => optionOrder.indexOf(a) - optionOrder.indexOf(b));
    const many = field.max === "*";
    const sel = many ? ((value as string[] | undefined) ?? []) : value ? [value as string] : [];
    input = (
      <Choices
        options={opts}
        selected={sel}
        multi={many}
        labelledBy={labelId}
        describedBy={describedBy}
        labelOf={(o) => t(`${optionKey ?? "aiDecl.enum"}.${o}`, { defaultValue: o })}
        hintOf={(o) => t(`aiDecl.enumHint.${o}`, { defaultValue: "" }) || undefined}
        onPick={(o) => {
          if (!many) return onChange(sel.includes(o) ? "" : o);
          if (o === "noAssertion") return onChange(sel.includes(o) ? [] : [o]);
          const rest = sel.filter((x) => x !== "noAssertion");
          onChange(rest.includes(o) ? rest.filter((x) => x !== o) : [...rest, o]);
        }}
      />
    );
  } else if (field.type === "DateTime") {
    input = (
      <Input
        id={id}
        type="date"
        className="max-w-[12rem]"
        aria-describedby={describedBy}
        aria-required={required || undefined}
        value={declaredToDate(value)}
        onChange={(e) => onChange(dateToDeclared(e.target.value))}
      />
    );
  } else if (field.type === "Agent" && field.max === "*") {
    input = (
      <ListEditor<Agent>
        items={(value as Agent[] | undefined) ?? []}
        blank={{ type: "Organization", name: "" }}
        addLabel={t("aiDecl.addAgent")}
        removeLabel={(i) => t("aiDecl.removeRow", { name: rowLabel(i) })}
        onChange={(v) => onChange(v)}
        render={(a, set, i) => (
          <AgentInput
            value={a}
            onChange={set}
            label={rowLabel(i)}
            describedBy={i === 0 ? describedBy : undefined}
            required={required && i === 0}
          />
        )}
      />
    );
  } else if (field.type === "Agent") {
    input = (
      <AgentInput
        id={id}
        value={(value as Agent | null) ?? null}
        onChange={(v) => onChange(v)}
        describedBy={describedBy}
        required={required}
        types={field.agentTypes}
      />
    );
  } else if (field.type === "DictionaryEntry") {
    input = (
      <ListEditor<DictEntry>
        items={(value as DictEntry[] | undefined) ?? []}
        blank={{ key: "", value: "" }}
        addLabel={t("aiDecl.addPair")}
        removeLabel={(i) => t("aiDecl.removeRow", { name: rowLabel(i) })}
        onChange={(v) => onChange(v)}
        render={(e, set, i) => (
          <div className="flex gap-2">
            <Input
              aria-label={`${rowLabel(i)}: ${t("aiDecl.pairKey")}`}
              aria-describedby={i === 0 ? describedBy : undefined}
              placeholder={t("aiDecl.pairKey")}
              value={e.key}
              onChange={(x) => set({ ...e, key: x.target.value })}
            />
            <Input
              aria-label={`${rowLabel(i)}: ${t("aiDecl.pairValue")}`}
              placeholder={t("aiDecl.pairValue")}
              value={e.value}
              onChange={(x) => set({ ...e, value: x.target.value })}
            />
          </div>
        )}
      />
    );
  } else if (field.max === "*") {
    input = (
      <ListEditor<string>
        items={(value as string[] | undefined) ?? []}
        blank=""
        addLabel={t("aiDecl.addLine")}
        removeLabel={(i) => t("aiDecl.removeRow", { name: rowLabel(i) })}
        onChange={(v) => onChange(v)}
        render={(s, set, i) => (
          <Input
            aria-label={rowLabel(i)}
            aria-describedby={i === 0 ? describedBy : undefined}
            placeholder={i === 0 && example ? t("aiDecl.examplePrefix", { example }) : undefined}
            value={s}
            onChange={(e) => set(e.target.value)}
          />
        )}
      />
    );
  } else if (LONG_TEXT.has(field.id)) {
    input = (
      <textarea
        id={id}
        className={textAreaClass}
        aria-describedby={describedBy}
        value={(value as string | undefined) ?? ""}
        placeholder={example ? t("aiDecl.examplePrefix", { example }) : undefined}
        onChange={(e) => onChange(e.target.value)}
      />
    );
  } else {
    input = (
      <>
        <Input
          id={id}
          type={field.type === "anyURI" ? "url" : "text"}
          aria-describedby={describedBy}
          aria-required={required || undefined}
          list={suggestions ? listId : undefined}
          value={(value as string | undefined) ?? ""}
          placeholder={example ? t("aiDecl.examplePrefix", { example }) : undefined}
          onChange={(e) => onChange(e.target.value)}
        />
        {suggestions && <Suggestions id={listId} values={suggestions} />}
      </>
    );
  }

  return (
    <div
      className="space-y-1.5"
      data-question={`${ns}.${field.id}`}
      data-where={where}
      onBlur={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget as Node | null)) setTouched(true);
      }}
    >
      <div className="flex items-center gap-2">
        {field.enum || isList ? (
          <span id={labelId} className="text-sm font-medium">
            {label}
          </span>
        ) : (
          <label id={labelId} htmlFor={id} className="text-sm font-medium">
            {label}
          </label>
        )}
        {required && <Badge variant="muted">{t("g7.required")}</Badge>}
      </div>
      {input}
      {hint && (
        <p id={hintId} className="text-xs text-muted-foreground">
          {hint}
        </p>
      )}
      {warning && <WarningNote>{warning}</WarningNote>}
      <div id={errId} aria-live="polite">
        {showProblem ? (
          <p className="text-xs text-risk-critical-fg">{t(`aiDecl.problem.${problem}`)}</p>
        ) : showMissing ? (
          <p
            className={cn("text-xs", loud ? "text-risk-critical-fg" : "text-muted-foreground")}
            data-missing={loud ? "shown" : "quiet"}
          >
            {t("aiDecl.requiredFailsValidation")}
          </p>
        ) : null}
      </div>
    </div>
  );
}

/** Licence ids offered while one is typed; any other id can still be typed. */
function Suggestions({ id, values }: { id: string; values: string[] }) {
  return (
    <datalist id={id}>
      {values.map((v) => (
        <option key={v} value={v} />
      ))}
    </datalist>
  );
}

function WarningNote({ children }: { children: ReactNode }) {
  return (
    <p
      role="note"
      className="flex items-start gap-1.5 rounded-md border border-warning-border/60 bg-warning-surface px-3 py-2 text-xs text-warning dark:border-warning-border/20 dark:bg-warning-surface/30"
    >
      <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
      <span>{children}</span>
    </p>
  );
}

/**
 * The questions that fill the SPDX 3.0.1 document's open fields: the base
 * models' revisions, the model, the data, and the calls only the publisher can
 * make. It asks only what the scan left open (the server's empty declaration
 * lists exactly that) and shows what the scan already filled as read-only.
 */
/**
 * The sources of one dataset: those already on record (traced from its card,
 * read-only) and those the publisher adds, by hub id (read from the hub at the
 * next scan) or named in words with the licence they know. There is no
 * "unknown" here: a licence left empty is recorded as not stated.
 */
function SourcesEditor({
  name,
  datasetIndex,
  onRecord,
  sources,
  problems,
  allowHub,
  showProblems,
  onChange,
}: {
  name: string;
  /** The dataset's place in the declaration, for adding a hub source. */
  datasetIndex: number;
  onRecord: string[];
  sources: SourceEntry[];
  problems: Issue["problem"][];
  /** Data the hub does not hold takes sources named in words only. */
  allowHub: boolean;
  showProblems?: boolean;
  onChange: (v: SourceEntry[]) => void;
}) {
  const { t } = useTranslation();
  const id = useId();
  const [touched, setTouched] = useState(false);
  const set = (i: number, v: SourceEntry) => onChange(sources.map((x, j) => (j === i ? v : x)));
  const shown = touched || showProblems ? problems : [];
  const errId = `${id}-err`;
  const row = (i: number) => i + 1;
  return (
    <div
      role="group"
      aria-labelledby={`${id}-label`}
      aria-describedby={shown.length ? errId : undefined}
      className="space-y-2 rounded-md border border-dashed p-3"
      data-sources={name}
      onBlur={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget as Node | null)) setTouched(true);
      }}
    >
      <div id={`${id}-label`} className="text-sm font-medium">
        {t("aiDecl.sources.label")}
      </div>
      <p className="text-xs text-muted-foreground">
        {onRecord.length ? t("aiDecl.sources.onRecord", { list: onRecord.join(", ") }) : t("aiDecl.sources.none")}
      </p>
      {sources.map((src, i) => (
        <div key={i} className="flex flex-wrap items-center gap-2" data-source-row={i}>
          {src.ref !== undefined ? (
            <span className="font-mono text-sm">{src.ref.replace(/^huggingface:/, "")}</span>
          ) : (
            <>
              <Input
                className="min-w-[10rem] flex-1"
                aria-label={t("aiDecl.sources.nameN", { n: row(i) })}
                aria-invalid={shown.length > 0 || undefined}
                aria-describedby={shown.length ? errId : undefined}
                placeholder={t("aiDecl.sources.name")}
                value={src.name ?? ""}
                onChange={(e) => set(i, { ...src, name: e.target.value })}
              />
              <Input
                className="w-44"
                aria-label={t("aiDecl.sources.licenseN", { n: row(i) })}
                aria-invalid={shown.length > 0 || undefined}
                aria-describedby={shown.length ? errId : undefined}
                placeholder={t("aiDecl.sources.licensePlaceholder")}
                list={`${id}-licenses`}
                value={src.license ?? ""}
                onChange={(e) => set(i, { ...src, license: e.target.value })}
              />
            </>
          )}
          <Select
            aria-label={t("aiDecl.sources.relationN", { n: row(i) })}
            value={src.relation}
            onChange={(e) => set(i, { ...src, relation: e.target.value as SourceEntry["relation"] })}
            className="h-10"
          >
            {SOURCE_RELATIONS.map((r) => (
              <option key={r} value={r}>
                {t(`aiDecl.sources.rel.${r}`)}
              </option>
            ))}
          </Select>
          <Button
            variant="ghost"
            size="sm"
            aria-label={t("aiDecl.removeRow", {
              name: src.ref?.replace(/^huggingface:/, "") || src.name || t("aiDecl.sources.nameN", { n: row(i) }),
            })}
            onClick={() => onChange(sources.filter((_, j) => j !== i))}
          >
            <X className="h-4 w-4" />
          </Button>
        </div>
      ))}
      {allowHub && (
        <AddById
          label={t("aiDecl.sources.addHub")}
          placeholder={t("aiDecl.examplePrefix", { example: "allenai/c4" })}
          button={t("aiDecl.sources.addButton")}
          toAction={(hubId) => {
            const ref = `huggingface:${hubId}`;
            const lower = hubId.toLowerCase();
            // Already a declared source, or already on record from the card.
            if (sources.some((x) => x.ref?.toLowerCase() === ref.toLowerCase())) return null;
            if (onRecord.some((x) => x.toLowerCase() === lower)) return null;
            return {
              type: "set",
              target: { kind: "dataset", index: datasetIndex },
              field: "sources",
              value: [...sources, { ref, relation: "extended" }] as unknown as Value,
            };
          }}
        />
      )}
      <Button variant="outline" size="sm" onClick={() => onChange([...sources, { name: "", license: "", relation: "other" }])}>
        <Plus className="h-3.5 w-3.5" />
        {t("aiDecl.sources.addNamed")}
      </Button>
      <Suggestions id={`${id}-licenses`} values={COMMON_LICENSES} />
      <div id={errId} aria-live="polite">
        {[...new Set(shown)].map((p) => (
          <p key={p} className="text-xs text-risk-critical-fg">
            {t(`aiDecl.problem.${p}`)}
          </p>
        ))}
      </div>
    </div>
  );
}

/** What a typed but not yet added id needs to be added on the way out of a
 *  step, or to stop the way out when it is not an id. */
type PendingEntry = PendingId & { reveal: () => void };

/** The add-by-id boxes on screen register here, so leaving the step can add
 *  what they still hold (see flushPendingIds). */
const PendingIds = createContext<{
  boxes: Map<string, () => PendingEntry>;
  dispatch: (a: DeclarationAction) => void;
} | null>(null);

/** Adds an id (a base model, a hub dataset, a hub source) from a text box.
 *  An id typed and not added is added when the step is left; one that is not
 *  an id keeps the step open and says why. */
function AddById({
  label,
  placeholder,
  button,
  toAction,
  valid,
  invalidKey = "aiDecl.problem.hubId",
  suggestions,
  hint,
}: {
  label: string;
  placeholder: string;
  button: string;
  /** What adding the id does; null when it is already there. */
  toAction: (id: string) => DeclarationAction | null;
  /** What can be added; a HuggingFace id when not given. */
  valid?: (value: string) => boolean;
  /** What to say when the typed value cannot be added. */
  invalidKey?: string;
  /** Values to offer while typing. */
  suggestions?: string[];
  hint?: string;
}) {
  const { t } = useTranslation();
  const ctx = useContext(PendingIds);
  const id = useId();
  const input = useRef<HTMLInputElement>(null);
  const [value, setValue] = useState("");
  const [held, setHeld] = useState(false);
  const v = value.trim();
  const bad = v !== "" && !(valid ?? isHubId)(v);
  const latest = useRef<PendingEntry>({ value, toAction, reveal: () => {} });
  latest.current = {
    value,
    toAction,
    valid,
    reveal: () => {
      setHeld(true);
      input.current?.focus();
    },
  };
  useEffect(() => {
    const boxes = ctx?.boxes;
    boxes?.set(id, () => latest.current);
    return () => {
      boxes?.delete(id);
    };
  }, [ctx, id]);
  const add = () => {
    if (!v || bad) return;
    const a = toAction(v);
    if (a) ctx?.dispatch(a);
    setValue("");
    setHeld(false);
  };
  return (
    <div className="space-y-1.5">
      <label htmlFor={id} className="text-sm font-medium">
        {label}
      </label>
      <div className="flex gap-2">
        <Input
          ref={input}
          id={id}
          value={value}
          placeholder={placeholder}
          aria-describedby={hint ? `${id}-hint ${id}-err` : `${id}-err`}
          aria-invalid={bad || undefined}
          list={suggestions ? `${id}-list` : undefined}
          onChange={(e) => {
            setValue(e.target.value);
            if (!e.target.value.trim()) setHeld(false);
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              add();
            }
          }}
        />
        <Button variant="outline" onClick={add} disabled={!v || bad}>
          <Plus className="h-3.5 w-3.5" />
          {button}
        </Button>
      </div>
      {suggestions && <Suggestions id={`${id}-list`} values={suggestions} />}
      {hint && (
        <p id={`${id}-hint`} className="text-xs text-muted-foreground">
          {hint}
        </p>
      )}
      <div id={`${id}-err`} aria-live="polite">
        {bad && <p className="text-xs text-risk-critical-fg">{t(invalidKey)}</p>}
        {bad && held && <p className="text-xs text-risk-critical-fg">{t("aiDecl.pendingBlocked")}</p>}
      </div>
    </div>
  );
}

type ProblemAt = (where: string, field: string) => Issue["problem"] | undefined;
type SetAnswer = (target: Target, field: string, value: Value) => void;

/**
 * The data the declared service takes in and sends out, one flow per row in
 * the shape of CycloneDX serviceData. A flow is added by saying what data it
 * is; what is typed and not added is added when the step is left.
 */
function DataFlowsEditor({
  index,
  flows,
  problemAt,
  showProblems,
  set,
  onRemove,
}: {
  index: FieldIndex;
  flows: DataFlow[];
  problemAt: ProblemAt;
  showProblems: boolean;
  set: SetAnswer;
  onRemove: (i: number) => void;
}) {
  const { t } = useTranslation();
  const fields = dataFlowFields(index);
  const suggestions = CLASSIFICATION_KEYS.map((k) => t(`aiDecl.dataFlow.suggest.${k}`));
  return (
    <div className="space-y-3" data-testid="data-flows">
      <p className="text-xs text-muted-foreground">{t("aiDecl.dataFlow.intro")}</p>
      {flows.map((d, i) => {
        const where = `service.dataFlows[${i}]`;
        const label = t("aiDecl.dataFlow.n", { n: i + 1 });
        return (
          <div key={i} data-where={where} data-flow-row={i} className="space-y-4 rounded-md border p-3">
            <div className="flex items-center justify-between gap-2">
              <span className="text-sm font-semibold">
                {label}
                {d.classification.trim() && (
                  <span className="ml-2 font-normal text-muted-foreground">{d.classification.trim()}</span>
                )}
              </span>
              <Button
                variant="ghost"
                size="sm"
                aria-label={t("aiDecl.removeRow", { name: label })}
                onClick={() => onRemove(i)}
              >
                <Trash2 className="h-4 w-4" />
                {t("aiDecl.removeLocal")}
              </Button>
            </div>
            {fields.map((f) => (
              <Field
                key={f.id}
                ns="dataFlow"
                where={where}
                field={f}
                value={(d as unknown as Record<string, Value | undefined>)[f.id]}
                problem={problemAt(where, f.id)}
                showProblems={showProblems}
                onChange={(v) => set({ kind: "dataFlow", index: i }, f.id, v)}
                optionKey={f.id === "flow" ? "aiDecl.dataFlow.flow.option" : undefined}
                suggestions={f.id === "classification" ? suggestions : undefined}
              />
            ))}
          </div>
        );
      })}
      <AddById
        label={t("aiDecl.dataFlow.add.label")}
        placeholder={t("aiDecl.examplePrefix", { example: suggestions[0] })}
        button={t("aiDecl.dataFlow.add.button")}
        hint={t("aiDecl.dataFlow.add.hint")}
        suggestions={suggestions}
        valid={(v) => [...v].length <= MAX_LABEL}
        invalidKey="aiDecl.problem.labelTooLong"
        toAction={(c) => ({ type: "addDataFlow", classification: c })}
      />
    </div>
  );
}

/**
 * The AI models the service calls through an API (a hosted model it does not
 * run itself). Only who and what they are is recorded; nothing about them is
 * read. Added by name; a name typed and not added is added when the step is
 * left.
 */
function ExternalModelsEditor({
  index,
  models,
  problemAt,
  showProblems,
  set,
  onRemove,
}: {
  index: FieldIndex;
  models: ExternalModelEntry[];
  problemAt: ProblemAt;
  showProblems: boolean;
  set: SetAnswer;
  onRemove: (i: number) => void;
}) {
  const { t } = useTranslation();
  const fields = ["name", "suppliedBy", "packageVersion", "endpoint"]
    .map((k) => index.externalModel[k])
    .filter((f): f is MapField => Boolean(f));
  return (
    <div className="space-y-3" data-testid="external-models">
      <p className="text-xs text-muted-foreground">{t("aiDecl.externalModel.intro")}</p>
      {models.map((m, i) => {
        const where = `service.externalModels[${i}]`;
        const label = m.name.trim() || t("aiDecl.externalModel.n", { n: i + 1 });
        return (
          <div key={i} data-where={where} data-external-model={i} className="space-y-4 rounded-md border p-3">
            <div className="flex items-center justify-between gap-2">
              <span className="text-sm font-semibold">{label}</span>
              <Button
                variant="ghost"
                size="sm"
                aria-label={t("aiDecl.removeRow", { name: label })}
                onClick={() => onRemove(i)}
              >
                <Trash2 className="h-4 w-4" />
                {t("aiDecl.removeLocal")}
              </Button>
            </div>
            {fields.map((f) => (
              <Field
                key={f.id}
                ns="externalModel"
                where={where}
                field={f}
                value={(m as unknown as Record<string, Value | undefined>)[f.id]}
                problem={problemAt(where, f.id)}
                showProblems={showProblems}
                onChange={(v) => set({ kind: "externalModel", index: i }, f.id, v)}
              />
            ))}
          </div>
        );
      })}
      <AddById
        label={t("aiDecl.externalModel.add.label")}
        placeholder={t("aiDecl.examplePrefix", { example: t("aiDecl.externalModel.add.example") })}
        button={t("aiDecl.externalModel.add.button")}
        valid={(v) => [...v].length <= MAX_TEXT}
        invalidKey="aiDecl.problem.tooLong"
        toAction={(name) =>
          models.some((x) => x.name.trim().toLowerCase() === name.toLowerCase())
            ? null
            : { type: "addExternalModel", name }
        }
      />
    </div>
  );
}

/** "Did this model start from another one?" in create mode. */
type Origin = "scratch" | "base";
const ORIGINS: Origin[] = ["scratch", "base"];

export function AiDeclarationWizard({
  title,
  index,
  initial,
  initialStep,
  check,
  onCancel,
  onSave,
  onDraft,
  mode = "fill",
  authorFromScan: authorGiven,
  declaredScan = false,
  startNote,
}: {
  title: string;
  index: FieldIndex;
  initial: Declaration;
  /** Where to reopen an answer set kept from an earlier visit. */
  initialStep?: StepId;
  check: Spdx3Check | null;
  onCancel: () => void;
  /** Resolves null when saved, or the failure to show. */
  onSave: (file: Declaration) => Promise<Spdx3Failure | null>;
  /** Called with the answers as they change, so leaving the section and coming
   *  back does not lose them. */
  onDraft?: (decl: Declaration, step: StepId) => void;
  /** "fill": the open fields of a finished scan. "create": a model described
   *  from the declaration alone, before any scan (base models and datasets
   *  are added here, and saving starts the scan). */
  mode?: "fill" | "create";
  /** The scan names the document's author itself (--sbom-author), so the
   *  question is not asked. Read from the check when not given. */
  authorFromScan?: boolean;
  /** When set, the final action is disabled and this note is shown under it
   *  (the read-only demo, which cannot start a scan). */
  startNote?: ReactNode;
  /** Filling a model that was itself described from a declaration (its
   *  licence takes effect at its next scan). */
  declaredScan?: boolean;
}) {
  const { t, i18n } = useTranslation();
  const create = mode === "create";
  const firstSteps = useMemo(() => stepsFor(index, initial, create), [index, initial, create]);
  const [state, dispatch] = useAiDeclaration(
    initial,
    initialStep && firstSteps.includes(initialStep) ? initialStep : firstSteps[0],
  );
  const { decl, step } = state;
  // The steps follow the answers: once the model runs in a declared service,
  // the decisions step no longer asks the model's autonomy and may go.
  const steps = useMemo(() => stepsFor(index, decl, create), [index, decl, create]);
  const [saving, setSaving] = useState(false);
  const [failure, setFailure] = useState<Spdx3Failure | null>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const headingId = useId();
  // The add-by-id boxes on screen, read when the step is left.
  const [pending] = useState(() => ({ boxes: new Map<string, () => PendingEntry>(), dispatch }));
  // An open item to put the cursor on once its step is shown.
  const focusTarget = useRef<Issue | null>(null);
  // Create mode: from scratch or from a base model. Reopening a saved
  // declaration with base models answers it already.
  const [origin, setOrigin] = useState<Origin | null>(() =>
    initial.model?.baseModels?.length ? "base" : create && initialStep === "preview" ? "scratch" : null,
  );

  // Each step (and the flow's opening) moves focus to its question, so a
  // screen reader announces it and the keyboard starts at the top; a jump to
  // an open item goes to that item instead.
  useEffect(() => {
    const target = focusTarget.current;
    focusTarget.current = null;
    if (target && focusIssue(target)) return;
    heading.current?.focus();
  }, [step]);

  useEffect(() => {
    onDraft?.(decl, step);
  }, [decl, step, onDraft]);

  const authorFromScan =
    authorGiven ??
    check?.elements.find((e) => e.type === "CreationInfo")?.fields.find((f) => f.id === "createdBy")?.status === "auto";
  const all = findIssues(index, decl, authorFromScan);
  const blockers = saveBlockers(all);
  const remaining = remainingRequired(all);
  const totalRequired = Math.max(remaining, remainingRequired(findIssues(index, initial, authorFromScan)));
  const openIn = openByStep(all);
  const problemAt = (where: string, field: string) => all.find((i) => i.where === where && i.field === field)?.problem;
  const hasIssueIn = (where: string, fields: string[]) => all.some((i) => i.where === where && fields.includes(i.field));
  const hasIssueUnder = (prefix: string) => all.some((i) => i.where.startsWith(prefix));
  const set = (target: Target, field: string, value: Value) => dispatch({ type: "set", target, field, value });
  // Back from the review step, show every problem at once.
  const [reviewed, setReviewed] = useState(false);
  // Steps the person has left: their empty required fields now show as errors.
  const [left, setLeft] = useState<StepId[]>([]);
  const loud = reviewed || left.includes(step);

  /** Add what the add-by-id boxes still hold; false (and the box says why)
   *  when one holds something that is not an id. */
  const flush = () => {
    const entries = [...pending.boxes.values()].map((get) => get());
    const r = flushPendingIds(state, entries);
    if (r.blocked >= 0) {
      entries[r.blocked].reveal();
      return null;
    }
    r.actions.forEach(dispatch);
    return r.state;
  };

  const stepIndex = steps.indexOf(step);
  const go = (s: StepId, focus?: Issue) => {
    if (!flush()) return;
    if (step === "preview") setReviewed(true);
    if (!left.includes(step)) setLeft([...left, step]);
    focusTarget.current = focus ?? null;
    dispatch({ type: "step", step: s });
  };

  const modelField = (id: string) => {
    const f = index.ai_AIPackage[id];
    return f ? (
      <Field
        key={id}
        ns="model"
        where="model"
        field={f}
        value={decl.model?.[id] as Value | undefined}
        problem={problemAt("model", id)}
        showProblems={loud}
        onChange={(v) => set({ kind: "model" }, id, v)}
        warning={
          id === "weightsScope" && adapterWithoutBase(decl)
            ? t(create ? "aiDecl.adapterNoBase.create" : "aiDecl.adapterNoBase.fill")
            : undefined
        }
      />
    ) : null;
  };

  const autoOf = (key: string | undefined, id: string) =>
    check?.elements.find((e) => e.declarationKey === key)?.fields.find((f) => f.id === id && f.display)?.display;

  const save = async () => {
    const flushed = flush();
    if (!flushed) return;
    setSaving(true);
    setFailure(null);
    const res = await onSave(toFile(flushed.decl, create));
    setSaving(false);
    if (res) setFailure(res);
  };

  const stepName = (s: StepId) => t(`aiDecl.step.${s}`);

  let body: ReactNode;
  let why: string;
  if (step === "base") {
    why = create ? "baseCreate" : "base";
    const showBases = !create || origin === "base";
    body = (
      <div className="space-y-3">
        {create && (
          <Choices
            options={ORIGINS}
            selected={origin ? [origin] : []}
            labelledBy={headingId}
            labelOf={(o) => t(`aiDecl.origin.${o}`)}
            onPick={(o) => {
              const next = origin === o ? null : (o as Origin);
              setOrigin(next);
              if (next === "scratch") dispatch({ type: "clearBases" });
            }}
          />
        )}
        {create && origin === "scratch" && (
          <p className="text-sm text-muted-foreground" data-testid="origin-scratch">
            {t("aiDecl.origin.scratchNote")}
          </p>
        )}
        {create && origin === "base" && (
          <Card>
            <CardContent className="p-4">
              <AddById
                label={t("aiDecl.base.add.label")}
                placeholder={t("aiDecl.examplePrefix", { example: "Qwen/Qwen2.5-0.5B" })}
                button={t("aiDecl.base.add.button")}
                toAction={(ref) => ({ type: "addBase", ref })}
              />
              <p className="mt-1.5 text-xs text-muted-foreground">{t("aiDecl.base.add.hint")}</p>
            </CardContent>
          </Card>
        )}
        {showBases &&
          (decl.model?.baseModels ?? []).map((b, i) => (
            <Card key={b.ref} data-base={b.ref} data-where={`model.baseModels[${i}]`}>
              <CardContent className="space-y-2 p-4">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-medium">{b.ref}</span>
                    {create ? (
                      <Badge tone="info">{t("spdx3.status.declared")}</Badge>
                    ) : (
                      <Badge tone="low">{t("spdx3.status.auto")}</Badge>
                    )}
                  </div>
                  {create && (
                    <Button
                      variant="ghost"
                      size="sm"
                      aria-label={t("aiDecl.removeRow", { name: b.ref })}
                      onClick={() => {
                        dispatch({ type: "removeBase", index: i });
                        heading.current?.focus();
                      }}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  )}
                </div>
                <label className="block text-sm font-medium" htmlFor={`base-rev-${i}`}>
                  {t("aiDecl.base.revision.label")}
                </label>
                <Input
                  id={`base-rev-${i}`}
                  aria-describedby={`base-rev-${i}-hint`}
                  value={b.revision}
                  placeholder={t("aiDecl.base.revision.example")}
                  onChange={(e) => set({ kind: "base", index: i }, "revision", e.target.value)}
                />
                <p id={`base-rev-${i}-hint`} className="text-xs text-muted-foreground">
                  {t("aiDecl.base.revision.hint")}
                </p>
                <div aria-live="polite">
                  {problemAt(`model.baseModels[${i}]`, "revision") && (
                    <p className="text-xs text-risk-critical-fg">{t("aiDecl.problem.revision")}</p>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
      </div>
    );
  } else if (step === "model") {
    why = "model";
    const useFields = MODEL_USE_FIELDS.filter((k) => decl.model && k in decl.model);
    const regFields = REGULATORY_FIELDS.filter((k) => decl.model && k in decl.model && index.ai_AIPackage[k]);
    body = (
      <Card>
        <CardContent className="space-y-5 p-4">
          {!authorFromScan && (
            <Field
              ns="document"
              where="document"
              field={index.document.createdBy}
              value={decl.document.createdBy}
              problem={problemAt("document", "createdBy")}
              showProblems={loud}
              onChange={(v) => set({ kind: "document" }, "createdBy", v)}
            />
          )}
          {modelMainFields(index, decl).map(modelField)}
          {decl.model && "license" in decl.model && (
            <Field
              ns="model"
              where="model"
              field={MODEL_LICENSE_FIELD}
              value={decl.model.license}
              problem={problemAt("model", "license")}
              showProblems={loud}
              hintKey={
                create
                  ? "aiDecl.model.license.hintCreate"
                  : declaredScan
                    ? "aiDecl.model.license.hintDeclared"
                    : "aiDecl.model.license.hint"
              }
              suggestions={COMMON_LICENSES}
              onChange={(v) => set({ kind: "model" }, "license", v)}
            />
          )}
          {useFields.length > 0 && (
            <Disclosure
              defaultOpen={hasIssueIn("model", useFields)}
              summary={<span className="text-sm font-medium">{t("aiDecl.group.use")}</span>}
            >
              <div className="mt-3 space-y-5">{useFields.map(modelField)}</div>
            </Disclosure>
          )}
          {regFields.length > 0 && (
            <Disclosure
              defaultOpen={hasIssueIn("model", regFields)}
              summary={<span className="text-sm font-medium">{t("aiDecl.group.regulatory")}</span>}
            >
              <div className="mt-3 space-y-5" data-testid="regulatory-fields">
                <p className="text-xs text-muted-foreground">{t("aiDecl.group.regulatoryNote")}</p>
                {regFields.map(modelField)}
              </div>
            </Disclosure>
          )}
        </CardContent>
      </Card>
    );
  } else if (step === "data") {
    why = "data";
    const trainFields = TRAINING_FIELDS.filter((k) => decl.model && k in decl.model);
    body = (
      <div className="space-y-3">
        {decl.datasets.map((d, i) => {
          const where = `datasets[${i}]`;
          const local = d.local !== undefined;
          const keys = Object.keys(d).filter((k) => index.dataset_DatasetPackage[k] && k !== "name");
          const main = keys.filter((k) => !DATASET_MORE_FIELDS.includes(k));
          const more = keys.filter((k) => DATASET_MORE_FIELDS.includes(k));
          const field = (k: string) => (
            <Field
              key={k}
              ns="dataset"
              where={where}
              field={index.dataset_DatasetPackage[k]}
              value={d[k] as Value | undefined}
              problem={problemAt(where, k)}
              showProblems={loud}
              onChange={(v) => set({ kind: "dataset", index: i }, k, v)}
            />
          );
          const supplier = autoOf(d.ref, "suppliedBy");
          const download = autoOf(d.ref, "downloadLocation");
          return (
            <Card key={d.ref ?? `local-${i}`} data-dataset={d.ref ?? "local"} data-where={where}>
              <CardContent className="space-y-4 p-4">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div className="min-w-0">
                    {local ? (
                      <span className="text-sm font-semibold">{t("aiDecl.localTitle")}</span>
                    ) : (
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-sm font-semibold">{d.ref?.replace(/^huggingface:/, "")}</span>
                        {create ? (
                          <Badge tone="info">{t("aiDecl.readAtScan")}</Badge>
                        ) : (
                          <Badge tone="low">{t("spdx3.status.auto")}</Badge>
                        )}
                      </div>
                    )}
                    {(supplier || download) && (
                      <p className="mt-1 break-all text-xs text-muted-foreground">
                        {[supplier && t("aiDecl.autoSupplier", { value: supplier }), download].filter(Boolean).join(", ")}
                      </p>
                    )}
                  </div>
                  {(local || create) && (
                    <Button
                      variant="ghost"
                      size="sm"
                      aria-label={t("aiDecl.removeRow", {
                        name: local ? (d.name as string) || t("aiDecl.localTitle") : d.ref?.replace(/^huggingface:/, ""),
                      })}
                      onClick={() => {
                        dispatch({ type: local ? "removeLocal" : "removeHub", index: i });
                        // The button is gone; the question heading keeps the keyboard in the step.
                        heading.current?.focus();
                      }}
                    >
                      <Trash2 className="h-4 w-4" />
                      {t("aiDecl.removeLocal")}
                    </Button>
                  )}
                </div>
                {"role" in d && (
                  <div className="space-y-1.5">
                    <span id={`role-${i}`} className="text-sm font-medium">
                      {t("aiDecl.role.label")}
                    </span>
                    <Choices
                      options={[...ROLES]}
                      selected={d.role ? [d.role] : []}
                      labelledBy={`role-${i}`}
                      describedBy={`role-${i}-hint`}
                      labelOf={(o) => t(`aiDecl.role.${o}`)}
                      onPick={(o) => set({ kind: "dataset", index: i }, "role", d.role === o ? "" : o)}
                    />
                    <p id={`role-${i}-hint`} className="text-xs text-muted-foreground">
                      {t("aiDecl.role.hint")}
                    </p>
                  </div>
                )}
                {local && (
                  <div className="space-y-1.5">
                    <label htmlFor={`local-name-${i}`} className="flex items-center gap-2 text-sm font-medium">
                      {t("aiDecl.dataset.name.label")}
                      <Badge variant="muted">{t("g7.required")}</Badge>
                    </label>
                    <Input
                      id={`local-name-${i}`}
                      aria-required
                      value={(d.name as string | undefined) ?? ""}
                      placeholder={t("aiDecl.examplePrefix", { example: t("aiDecl.dataset.name.example") })}
                      onChange={(e) => set({ kind: "dataset", index: i }, "name", e.target.value)}
                    />
                  </div>
                )}
                {main.map(field)}
                <SourcesEditor
                  name={d.ref ?? `local-${i}`}
                  datasetIndex={i}
                  onRecord={
                    check?.relationships
                      .filter((r) => r.type === "descendantOf" && r.fromLabel && r.fromLabel === d.ref?.replace(/^huggingface:/, ""))
                      .map((r) => r.toLabel ?? "")
                      .filter(Boolean) ?? []
                  }
                  sources={d.sources ?? []}
                  problems={all.filter((x) => x.where === where && x.field === "sources").map((x) => x.problem)}
                  allowHub={!local}
                  showProblems={loud}
                  onChange={(v) => set({ kind: "dataset", index: i }, "sources", v as unknown as Value)}
                />
                {more.length > 0 && (
                  <Disclosure
                    defaultOpen={hasIssueIn(where, more)}
                    summary={<span className="text-sm font-medium">{t("aiDecl.group.moreData")}</span>}
                  >
                    <div className="mt-3 space-y-5">{more.map(field)}</div>
                  </Disclosure>
                )}
                {problemAt(where, "local") && (
                  <p className="text-xs text-risk-critical-fg">{t("aiDecl.problem.localIncomplete")}</p>
                )}
              </CardContent>
            </Card>
          );
        })}
        {create && (
          <Card>
            <CardContent className="p-4">
              <AddById
                label={t("aiDecl.hub.add.label")}
                placeholder={t("aiDecl.examplePrefix", { example: "HuggingFaceH4/ultrachat_200k" })}
                button={t("aiDecl.hub.add.button")}
                toAction={(id) => ({ type: "addHub", index, id })}
              />
            </CardContent>
          </Card>
        )}
        {decl.model && (
          <Button variant="outline" size="sm" onClick={() => dispatch({ type: "addLocal", index })}>
            <Plus className="h-3.5 w-3.5" />
            {t("aiDecl.addLocal")}
          </Button>
        )}
        {trainFields.length > 0 && (
          <Card>
            <CardContent className="p-4">
              <Disclosure
                defaultOpen={hasIssueIn("model", trainFields)}
                summary={<span className="text-sm font-medium">{t("aiDecl.group.training")}</span>}
              >
                <div className="mt-3 space-y-5">{trainFields.map(modelField)}</div>
              </Disclosure>
            </CardContent>
          </Card>
        )}
      </div>
    );
  } else if (step === "service") {
    why = "service";
    const answer = decl.serviceAnswer ?? null;
    const svc = decl.service ?? {};
    const serviceField = (id: string) => {
      const f = index.service[id];
      if (!f) return null;
      const autonomy = id === "autonomyType";
      return (
        <Field
          key={id}
          ns="service"
          where="service"
          field={f}
          value={svc[id] as Value | undefined}
          problem={problemAt("service", id)}
          showProblems={loud}
          onChange={(v) => set({ kind: "service" }, id, v)}
          optionOrder={autonomy ? SERVICE_AUTONOMY_ORDER : undefined}
          optionKey={autonomy ? SERVICE_AUTONOMY_KEY : undefined}
        />
      );
    };
    const groupOpen = (fields: string[]) =>
      fields.some((f) =>
        f === "dataFlows"
          ? hasIssueUnder("service.dataFlows")
          : f === "externalModels"
            ? hasIssueUnder("service.externalModels")
            : hasIssueIn("service", [f]),
      );
    body = (
      <div className="space-y-3">
        <Card>
          <CardContent className="space-y-2 p-4">
            <Choices
              options={SERVICE_ANSWERS}
              selected={answer ? [answer] : []}
              labelledBy={headingId}
              describedBy={`${headingId}-hint`}
              labelOf={(o) => t(`aiDecl.serviceAnswer.${o}`)}
              onPick={(o) =>
                dispatch({ type: "serviceAnswer", answer: answer === o ? null : (o as ServiceAnswer) })
              }
            />
            {answer && answer !== "yes" && (
              <p className="text-sm text-muted-foreground" data-testid="service-answer-note">
                {t(`aiDecl.serviceAnswer.${answer}Note`)}
              </p>
            )}
          </CardContent>
        </Card>
        {answer === "yes" && (
          <>
            <Card data-testid="service-required">
              <CardContent className="space-y-5 p-4">{SERVICE_REQUIRED_FIELDS.map(serviceField)}</CardContent>
            </Card>
            <Card>
              <CardContent className="space-y-4 p-4">
                {SERVICE_GROUPS.map((g) => (
                  <Disclosure
                    key={g.id}
                    defaultOpen={groupOpen(g.fields)}
                    summary={
                      <span className="text-sm font-medium" data-service-group={g.id}>
                        {t(`aiDecl.serviceGroup.${g.id}`)}
                      </span>
                    }
                  >
                    <div className="mt-3 space-y-5">
                      {g.id === "flows" ? (
                        <DataFlowsEditor
                          index={index}
                          flows={svc.dataFlows ?? []}
                          problemAt={problemAt}
                          showProblems={loud}
                          set={set}
                          onRemove={(i) => {
                            dispatch({ type: "removeDataFlow", index: i });
                            heading.current?.focus();
                          }}
                        />
                      ) : g.id === "external" ? (
                        <ExternalModelsEditor
                          index={index}
                          models={svc.externalModels ?? []}
                          problemAt={problemAt}
                          showProblems={loud}
                          set={set}
                          onRemove={(i) => {
                            dispatch({ type: "removeExternalModel", index: i });
                            heading.current?.focus();
                          }}
                        />
                      ) : (
                        g.fields.map(serviceField)
                      )}
                    </div>
                  </Disclosure>
                ))}
              </CardContent>
            </Card>
          </>
        )}
      </div>
    );
  } else if (step === "legal") {
    why = "legal";
    const viaService =
      decl.serviceAnswer === "yes" &&
      decl.model !== undefined &&
      "autonomyType" in decl.model &&
      !judgmentFields(index, decl).includes("autonomyType");
    body = (
      <Card>
        <CardContent className="space-y-5 p-4">
          {judgmentFields(index, decl).map(modelField)}
          {viaService && (
            <p className="text-xs text-muted-foreground" data-testid="autonomy-in-service">
              {t("aiDecl.autonomyInService")}
            </p>
          )}
        </CardContent>
      </Card>
    );
  } else {
    why = "preview";
    const groups = summaryGroups(index, decl, steps);
    const valueText = (r: SummaryRow) => formatValue(r, t, i18n.language);
    body = (
      <div className="space-y-3">
        <Card>
          <CardContent className="space-y-1 p-4 text-sm">
            {all.length === 0 ? (
              <p className="flex items-center gap-2 text-success">
                <Check className="h-4 w-4" />
                {t("aiDecl.preview.complete")}
              </p>
            ) : (
              <>
                <p>{t("aiDecl.preview.open", { count: all.length })}</p>
                <p className="text-xs text-muted-foreground">
                  {blockers.length ? t("aiDecl.preview.blocked") : t("aiDecl.preview.draftOk")}
                </p>
              </>
            )}
            {/* The model's own values that also go into the CycloneDX SBOM; a
                declared service says so in its own group below. */}
            {!serviceDeclared(decl) && modelCdxValues(decl) && (
              <p className="text-xs text-muted-foreground" data-testid="cdx-note">
                {t(create ? "aiDecl.preview.modelCreate" : "aiDecl.preview.modelFill")}
              </p>
            )}
          </CardContent>
        </Card>
        {steps
          .filter((s) => s !== "preview")
          .map((s) => {
            const open = openIn[s] ?? 0;
            const mine = groups.filter((g) => g.step === s);
            return (
              <Card key={s} data-summary={s}>
                <CardContent className="space-y-2 p-4 text-sm">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h3 className="font-semibold">{stepName(s)}</h3>
                    {open > 0 ? (
                      <button
                        type="button"
                        aria-label={`${stepName(s)}: ${t("aiDecl.preview.openInStep", { count: open })}`}
                        className="inline-flex items-center gap-1 rounded text-xs font-medium text-brand-strong underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                        onClick={() => go(s, firstOpenIn(s, all))}
                      >
                        <TriangleAlert className="h-3.5 w-3.5" aria-hidden />
                        {t("aiDecl.preview.openInStep", { count: open })}
                      </button>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
                        <Check className="h-3.5 w-3.5" aria-hidden />
                        {t("aiDecl.preview.stepDone")}
                      </span>
                    )}
                  </div>
                  {s === "base" && (
                    <BaseSummary
                      bases={decl.model?.baseModels ?? []}
                      scratch={create && origin === "scratch"}
                    />
                  )}
                  {mine.map((g, gi) => {
                    const ds = g.datasetIndex !== undefined ? decl.datasets[g.datasetIndex] : undefined;
                    const extra: { label: string; value: string }[] = [];
                    if (ds?.role) extra.push({ label: t("aiDecl.preview.role"), value: t(`aiDecl.role.${ds.role}`) });
                    const srcs = (ds?.sources ?? []).map((x) => x.ref?.replace(/^huggingface:/, "") || x.name || "").filter(Boolean);
                    if (srcs.length) extra.push({ label: t("aiDecl.sources.label"), value: srcs.join(", ") });
                    const after: { label: string; value: string }[] = [];
                    if (g.step === "service") {
                      const flows = (decl.service?.dataFlows ?? []).filter((d) => !blankDeep(d));
                      if (flows.length)
                        after.push({
                          label: t("aiDecl.serviceGroup.flows"),
                          value: flows
                            .map((d) =>
                              [d.flow ? t(`aiDecl.dataFlow.flow.option.${d.flow}`, { defaultValue: d.flow }) : "", d.classification.trim()]
                                .filter(Boolean)
                                .join(": "),
                            )
                            .join("\n"),
                        });
                      const ext = (decl.service?.externalModels ?? []).filter((m) => !blankDeep(m));
                      if (ext.length)
                        after.push({
                          label: t("aiDecl.serviceGroup.external"),
                          value: ext
                            .map((m) => (m.suppliedBy?.name?.trim() ? `${m.name.trim()} (${m.suppliedBy.name.trim()})` : m.name.trim()))
                            .join("\n"),
                        });
                    }
                    const empty = g.rows.length === 0 && extra.length === 0 && after.length === 0;
                    return (
                      <div key={gi} className="space-y-1">
                        {g.title && <div className="font-mono text-xs font-semibold">{g.title}</div>}
                        {g.datasetIndex === undefined && s === "data" && (
                          <div className="text-xs font-semibold">{t("aiDecl.group.training")}</div>
                        )}
                        {empty ? (
                          <p className="text-xs text-muted-foreground">{t("aiDecl.preview.nothing")}</p>
                        ) : (
                          <dl className="grid grid-cols-[minmax(8rem,14rem)_minmax(0,1fr)] gap-x-3 gap-y-1 text-xs">
                            {extra.map((x) => (
                              <SummaryLine key={x.label} label={x.label} value={x.value} />
                            ))}
                            {g.rows.map((r) => (
                              <SummaryLine
                                key={`${r.where}.${r.field.id}`}
                                label={t(`aiDecl.${r.ns}.${r.field.id}.label`, { defaultValue: r.field.id })}
                                value={valueText(r)}
                              />
                            ))}
                            {after.map((x) => (
                              <SummaryLine key={x.label} label={x.label} value={x.value} />
                            ))}
                          </dl>
                        )}
                      </div>
                    );
                  })}
                  {s === "service" && (
                    <p className="text-xs text-muted-foreground" data-testid="service-summary-note">
                      {serviceDeclared(decl)
                        ? t(create ? "aiDecl.preview.serviceCreate" : "aiDecl.preview.serviceFill")
                        : t(`aiDecl.preview.service.${decl.serviceAnswer ?? "none"}`)}
                    </p>
                  )}
                  {s !== "base" && s !== "service" && mine.length === 0 && (
                    <p className="text-xs text-muted-foreground">{t("aiDecl.preview.nothing")}</p>
                  )}
                </CardContent>
              </Card>
            );
          })}
        <Disclosure summary={<span className="text-sm font-medium">{t("aiDecl.preview.file")}</span>}>
          <pre className="mt-2 max-h-80 overflow-auto rounded-md border bg-muted/40 p-3 text-xs">
            {JSON.stringify(toFile(decl, create), null, 2)}
          </pre>
        </Disclosure>
        {failure && (
          <div
            role="alert"
            className="space-y-1 rounded-md border border-risk-critical/40 bg-risk-critical/10 p-3 text-xs text-risk-critical-fg"
          >
            <div className="font-medium">
              {failure.status === 422
                ? t("aiDecl.saveRefused")
                : failure.status === 409
                  ? t("aiDecl.saveBusy")
                  : t("aiDecl.saveFailed")}
            </div>
            {failure.reasons && (
              <ul className="list-disc space-y-0.5 pl-5 font-mono">
                {failure.reasons.slice(0, 10).map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
            )}
          </div>
        )}
      </div>
    );
  }

  return (
    <PendingIds.Provider value={pending}>
      <div className="grid gap-6 lg:grid-cols-[12rem_minmax(0,1fr)_16rem]" data-testid="ai-declaration">
        <nav aria-label={t("aiDecl.stepsLabel")} className="space-y-4">
          <div className="truncate text-xs text-muted-foreground">{title}</div>
          <ol className="space-y-2">
            {steps.map((s, i) => {
              const visited = i < stepIndex || left.includes(s);
              const open = s === "preview" ? 0 : openIn[s] ?? 0;
              const done = visited && open === 0 && s !== step;
              const warn = visited && open > 0 && s !== step;
              return (
                <li key={s}>
                  <button
                    type="button"
                    onClick={() => go(s)}
                    aria-current={s === step ? "step" : undefined}
                    // The count is a description, so the button keeps the step's name.
                    aria-label={stepName(s)}
                    aria-describedby={open > 0 ? `${headingId}-open-${s}` : undefined}
                    data-step={s}
                    className={cn(
                      "flex w-full items-center gap-2 rounded-md px-1 py-1 text-left text-sm",
                      "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                      s === step ? "font-semibold" : "text-muted-foreground hover:text-foreground",
                    )}
                  >
                    <span
                      className={cn(
                        "flex h-5 w-5 shrink-0 items-center justify-center rounded-full border text-[0.7rem]",
                        done && "border-foreground bg-foreground text-background",
                        warn && "border-warning-border bg-warning-surface text-warning",
                      )}
                      aria-hidden
                    >
                      {done ? <Check className="h-3 w-3" /> : warn ? <TriangleAlert className="h-3 w-3" /> : i + 1}
                    </span>
                    <span className="min-w-0 flex-1">{stepName(s)}</span>
                    {open > 0 && (
                      <span
                        id={`${headingId}-open-${s}`}
                        className="shrink-0 text-xs font-normal text-muted-foreground"
                        data-open={open}
                      >
                        {t("aiDecl.preview.openInStep", { count: open })}
                      </span>
                    )}
                  </button>
                </li>
              );
            })}
          </ol>
          <div className="space-y-1.5">
            <div className="text-xs text-muted-foreground" aria-live="polite">
              {t("aiDecl.remaining", { count: remaining })}
            </div>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted" aria-hidden>
              <div
                className="h-full bg-foreground"
                style={{ width: `${totalRequired ? ((totalRequired - remaining) / totalRequired) * 100 : 100}%` }}
              />
            </div>
          </div>
        </nav>

        <div className="min-w-0 space-y-4">
          <div>
            <h2 ref={heading} id={headingId} tabIndex={-1} className="text-xl font-semibold focus:outline-none">
              {t(create && step === "base" ? "aiDecl.questionCreate.base" : `aiDecl.question.${step}`)}
            </h2>
            <p id={`${headingId}-hint`} className="mt-1 text-sm text-muted-foreground">
              {t(create ? `aiDecl.questionHintCreate.${step}` : `aiDecl.questionHint.${step}`)}
            </p>
          </div>
          {body}
          <div className="flex flex-wrap items-center justify-between gap-2 pt-2">
            <Button variant="ghost" onClick={onCancel}>
              {t("aiDecl.cancel")}
            </Button>
            <div className="flex gap-2">
              {stepIndex > 0 && (
                <Button variant="outline" onClick={() => go(steps[stepIndex - 1])}>
                  {t("aiDecl.prev")}
                </Button>
              )}
              {step === "preview" ? (
                <Button onClick={save} disabled={saving || blockers.length > 0 || Boolean(startNote)}>
                  {saving && <Loader2 className="h-4 w-4 animate-spin" />}
                  {create ? t("aiDecl.startScan") : t("aiDecl.save")}
                </Button>
              ) : (
                <Button onClick={() => go(steps[stepIndex + 1])}>
                  {t("aiDecl.next", { step: stepName(steps[stepIndex + 1]) })}
                </Button>
              )}
            </div>
          </div>
          {startNote && step === "preview" && (
            <p className="text-right text-xs text-muted-foreground" data-testid="declare-demo-note">
              {startNote}
            </p>
          )}
        </div>

        <aside className="space-y-3">
          {decl.model?.baseModels?.length ? (
            <Card>
              <CardContent className="space-y-1.5 p-4 text-sm">
                <div className="font-semibold">{t("aiDecl.side.baseTitle")}</div>
                {decl.model.baseModels.map((b) => (
                  <div key={b.ref} className="font-mono text-xs">
                    {b.ref}
                  </div>
                ))}
                <p className="text-xs text-muted-foreground">{t("aiDecl.side.baseNote")}</p>
              </CardContent>
            </Card>
          ) : null}
          <Card>
            <CardContent className="space-y-1.5 p-4 text-sm">
              <div className="font-semibold">{t("aiDecl.whyTitle")}</div>
              <p className="text-xs text-muted-foreground">{t(`aiDecl.why.${why}`)}</p>
            </CardContent>
          </Card>
        </aside>
      </div>
    </PendingIds.Provider>
  );
}

/** Put the cursor on an open item of the step now shown: its field, or the
 *  card it belongs to. True when something took focus. */
function focusIssue(issue: Issue): boolean {
  const root = document.querySelector('[data-testid="ai-declaration"]');
  if (!root) return false;
  const esc = (s: string) => s.replace(/["\\]/g, "\\$&");
  const box =
    root.querySelector(`[data-where="${esc(issue.where)}"][data-question$=".${esc(issue.field)}"]`) ??
    root.querySelector(`[data-where="${esc(issue.where)}"]`);
  const el = box?.querySelector<HTMLElement>(
    'input:not([type="hidden"]), textarea, select, [role="radio"][tabindex="0"], button[aria-pressed]',
  );
  if (!el) return false;
  el.focus();
  el.scrollIntoView?.({ block: "center" });
  return true;
}

function SummaryLine({ label, value }: { label: string; value: string }) {
  return (
    <>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 whitespace-pre-line break-words">{value}</dd>
    </>
  );
}

function BaseSummary({ bases, scratch }: { bases: { ref: string; revision: string }[]; scratch: boolean }) {
  const { t } = useTranslation();
  if (!bases.length) {
    return (
      <p className="text-xs text-muted-foreground">
        {scratch ? t("aiDecl.origin.scratch") : t("aiDecl.preview.noBase")}
      </p>
    );
  }
  return (
    <ul className="space-y-0.5 text-xs">
      {bases.map((b) => (
        <li key={b.ref}>
          <span className="font-mono">{b.ref}</span>
          <span className="text-muted-foreground">
            {", "}
            {b.revision.trim()
              ? t("aiDecl.preview.revision", { revision: b.revision.trim() })
              : t("aiDecl.preview.noRevision")}
          </span>
        </li>
      ))}
    </ul>
  );
}

/** One saved answer as words: names for people and organizations, dates in
 *  the reader's locale, the labels the questions use for a choice. */
function formatValue(r: SummaryRow, t: (k: string, o?: Record<string, unknown>) => string, lang: string): string {
  const v = r.value;
  const one = (x: unknown): string => {
    if (x === null || x === undefined) return "";
    if (typeof x === "object" && "name" in (x as Agent)) return (x as Agent).name;
    if (typeof x === "object" && "key" in (x as DictEntry)) {
      const e = x as DictEntry;
      return e.value ? `${e.key} = ${e.value}` : e.key;
    }
    const s = String(x);
    if (r.ns === "service" && r.field.id === "autonomyType") return t(`${SERVICE_AUTONOMY_KEY}.${s}`, { defaultValue: s });
    if (r.field.enum) return t(`aiDecl.enum.${s}`, { defaultValue: s });
    if (r.field.type === "DateTime") return formatDay(s, lang);
    return s;
  };
  const list = Array.isArray(v) ? (v as unknown[]).filter((x) => !isEmpty(x)) : [v];
  return list.map(one).join(", ");
}

