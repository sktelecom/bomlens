// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Class sets for anything that can be picked and tabbed to: tiles, segmented
 * switches, filter chips. Five states, five different looks:
 *
 *   default   quiet border, muted label
 *   hover     a hint of fill (and a darker border on tiles)
 *   selected  a FILL and a dark border, no ring
 *   focus     the brand-red ring with a gap (focus-visible only)
 *   disabled  faded, not clickable
 *
 * Selection used to be a dark ring with an offset, which is exactly how the
 * keyboard focus ring looked, so a focused control and a chosen control could
 * not be told apart. The ring now belongs to focus alone (FOCUS_RING, colour
 * from --ring). Selection never uses `ring-*`; a test pins both.
 */

/** The one keyboard-focus treatment. Compose it into every pickable control. */
export const FOCUS_RING =
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background";

/** Keyboard focus on a text field or select: the field's own outline turns
 *  dark and doubles to 2px (an outlined-field focus style). A field takes focus
 *  on its own (autoFocus, a click), and the brand-red ring there sat next to
 *  the red required marks and read as an error. The red ring stays on buttons,
 *  links and pickable controls. Foreground on the page clears the 3:1 non-text
 *  floor in both themes, so focus stays plainly visible (WCAG 2.4.7). */
export const FIELD_FOCUS =
  "focus-visible:outline-none focus-visible:border-foreground focus-visible:ring-1 focus-visible:ring-foreground focus-visible:ring-offset-0";

/** Selected tile or card: pale fill plus a dark 1px border. */
export const SELECTED_TILE = "border-foreground bg-muted font-medium text-foreground";

/** Selected segment or chip in a compact control: the solid fill from
 *  --selected (near-black in light, a quieter raised grey in dark) with the
 *  foreground border every selected control carries. */
export const SELECTED_SOLID =
  "border-foreground bg-selected text-selected-foreground hover:bg-selected/90 hover:text-selected-foreground";

/** Selected pill that wraps a coloured badge: the border darkens, nothing else
 *  moves, so the badge keeps its own colours and contrast. */
export const SELECTED_OUTLINE = "border-foreground";

/** Resting border for a pill that is pressable but not selected. */
export const UNSELECTED_OUTLINE = "border-border";
