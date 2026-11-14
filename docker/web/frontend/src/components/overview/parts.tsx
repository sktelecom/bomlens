// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ChevronRightIcon } from "@primer/octicons-react";
import { useId, type ElementType, type ReactNode } from "react";

/**
 * A bordered section with a muted head: the Overview's one container. The head
 * holds the title (an h2), then whatever else the caller puts beside it.
 */
export function OvBox({
  title,
  icon: Icon,
  head,
  children,
  testId,
}: {
  title: ReactNode;
  icon?: ElementType;
  /** More in the head, after the title. */
  head?: ReactNode;
  children: ReactNode;
  testId?: string;
}) {
  const id = useId();
  return (
    <section className="bl-box" aria-labelledby={id} data-testid={testId}>
      <div className="bl-box-head">
        {Icon && (
          <span className="bl-ovrow-icon">
            <Icon size={16} />
          </span>
        )}
        <h2 id={id}>{title}</h2>
        {head}
      </div>
      {children}
    </section>
  );
}

/**
 * One row of a Box list: an icon, the text, an optional trailing figure and a
 * chevron. A link when `href` is given, plain otherwise.
 */
export function OvRow({
  href,
  icon: Icon,
  iconColor,
  children,
  end,
  label,
}: {
  href?: string;
  icon?: ElementType;
  iconColor?: string;
  children: ReactNode;
  end?: ReactNode;
  label?: string;
}) {
  const body = (
    <>
      {Icon && (
        <span className="bl-ovrow-icon" style={iconColor ? { color: iconColor } : undefined}>
          <Icon size={16} />
        </span>
      )}
      <span className="bl-ovrow-text">{children}</span>
      {end}
      {href && (
        <span className="bl-ovrow-chev">
          <ChevronRightIcon size={16} />
        </span>
      )}
    </>
  );
  return href ? (
    <a className="bl-ovrow" href={href} aria-label={label}>
      {body}
    </a>
  ) : (
    <div className="bl-ovrow">{body}</div>
  );
}
