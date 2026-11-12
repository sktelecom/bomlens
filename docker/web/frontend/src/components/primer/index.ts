// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * BomLens display pieces built on Primer (@primer/react) for what Primer has no
 * component for: the severity Label, the licence tier Label and the package
 * coordinate.
 *
 * Primer components whose visible text is fixed in English are not used,
 * because the UI is English and Korean and i18n:check cannot see those strings.
 * Table.Pagination ("Previous", "Next", "1-25 of 71") is one; build the control
 * from Primer parts with strings from the locale files instead. Check any other
 * Primer component's built-in text (Dialog, TextInput, Spinner and similar
 * accessible labels) before using it, and pass a translated label where the
 * component accepts one.
 */
export { PrimerRoot } from "./PrimerRoot";
export { SeverityLabel } from "./SeverityLabel";
export { LicenseTierLabel, LicenseTierMark } from "./LicenseTierLabel";
export { PackageCoordinate } from "./PackageCoordinate";
export * from "./display";
