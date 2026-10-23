// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Shared sizes for the controls in a table toolbar (search field, selects,
 * menus, export buttons, segmented switches): one height (36px) and one corner
 * radius (--radius), so a row of mixed controls lines up. Outside a toolbar the
 * components keep their own defaults (pill buttons, 40px form fields).
 */

/** Search field, select, menu button or button placed in a toolbar. */
export const TOOLBAR_CONTROL = "h-9 rounded-md";

/** The outlined frame of a segmented switch (density, layout, graph or tree). */
export const SEGMENT_GROUP = "inline-flex h-9 shrink-0 items-stretch rounded-md border p-0.5";

/** One segment inside SEGMENT_GROUP; it fills the frame's height. */
export const SEGMENT = "inline-flex items-center gap-1 rounded-sm border border-transparent px-2.5";
