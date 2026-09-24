/**
 * All formatting here uses the browser's built-in Intl APIs - no date/number
 * library dependency is needed for the formatting this dashboard requires.
 */

const numberFormatter = new Intl.NumberFormat("en-US");
const compactNumberFormatter = new Intl.NumberFormat("en-US", {
  notation: "compact",
  maximumFractionDigits: 1,
});
const timeFormatter = new Intl.DateTimeFormat("en-US", {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});
const dateTimeFormatter = new Intl.DateTimeFormat("en-US", {
  month: "short",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});
const relativeTimeFormatter = new Intl.RelativeTimeFormat("en-US", { numeric: "auto" });

export function formatNumber(value: number): string {
  return numberFormatter.format(value);
}

export function formatCompactNumber(value: number): string {
  return compactNumberFormatter.format(value);
}

export function formatRiskScore(value: number): string {
  return value.toFixed(2);
}

export function formatPercentage(value: number, fractionDigits = 1): string {
  return `${value.toFixed(fractionDigits)}%`;
}

export function formatTrend(value: number): string {
  const sign = value > 0 ? "+" : "";
  return `${sign}${value.toFixed(1)}%`;
}

export function formatTime(isoTimestamp: string): string {
  return timeFormatter.format(new Date(isoTimestamp));
}

/** Date + time, for records that can span days (e.g. persisted security events). */
export function formatDateTime(isoTimestamp: string): string {
  return dateTimeFormatter.format(new Date(isoTimestamp));
}

export function formatRelativeTime(isoTimestamp: string): string {
  const diffMs = new Date(isoTimestamp).getTime() - Date.now();
  const diffMinutes = Math.round(diffMs / 60000);

  if (Math.abs(diffMinutes) < 1) {
    return "just now";
  }
  if (Math.abs(diffMinutes) < 60) {
    return relativeTimeFormatter.format(diffMinutes, "minute");
  }
  const diffHours = Math.round(diffMinutes / 60);
  return relativeTimeFormatter.format(diffHours, "hour");
}
