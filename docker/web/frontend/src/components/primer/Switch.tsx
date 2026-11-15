// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * An on/off switch drawn like Primer's ToggleSwitch (same geometry and the same
 * control variables) but built as `<button role="switch" aria-checked>`.
 *
 * Primer's ToggleSwitch renders a toggle button (`aria-pressed`), so assistive
 * technology announces "toggle button, pressed" instead of "switch, on", and
 * every instance writes the same literal id ("loadingLabel") into the page.
 *
 * Two kinds of "cannot change":
 * - `disabled` (native): the form is busy. Dimmed, out of the Tab order.
 * - `locked`: the form fixed the value (the security report is on because deep
 *   CVE matching is). It stays in the Tab order with `aria-disabled`, so a
 *   keyboard reader reaches it and hears why (the reason is shown beside the
 *   bar). Primer's own disabled look is a grey track that no longer says on or
 *   off; a locked switch here keeps its on/off colours and only the pointer
 *   changes, because its value still matters.
 *
 * The visible name is a separate element referenced with `labelledBy`; the
 * description likewise with `describedBy`. A `<label htmlFor={id}>` around the
 * name and description makes them clickable.
 */
export function Switch({
  id,
  checked,
  onChange,
  disabled,
  locked,
  labelledBy,
  describedBy,
}: {
  id?: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
  locked?: boolean;
  labelledBy: string;
  describedBy?: string;
}) {
  return (
    <button
      id={id}
      type="button"
      role="switch"
      className="bl-switch"
      aria-checked={checked}
      aria-labelledby={labelledBy}
      aria-describedby={describedBy}
      aria-disabled={locked || undefined}
      disabled={disabled}
      onClick={() => {
        if (!locked) onChange(!checked);
      }}
    >
      <span className="bl-switch-icons" aria-hidden>
        <span className="bl-switch-line">
          <svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor">
            <path fillRule="evenodd" d="M8 2a.75.75 0 0 1 .75.75v11.5a.75.75 0 0 1-1.5 0V2.75A.75.75 0 0 1 8 2Z" />
          </svg>
        </span>
        <span className="bl-switch-circle">
          <svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor">
            <path fillRule="evenodd" d="M8 12.5a4.5 4.5 0 1 0 0-9 4.5 4.5 0 0 0 0 9ZM8 14A6 6 0 1 0 8 2a6 6 0 0 0 0 12Z" />
          </svg>
        </span>
      </span>
      <span className="bl-switch-knob" aria-hidden />
    </button>
  );
}
