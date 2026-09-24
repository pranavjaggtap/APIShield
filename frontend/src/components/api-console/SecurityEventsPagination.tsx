import { ChevronLeft, ChevronRight } from "lucide-react";
import { formatNumber } from "../../lib/formatters";
import { SECURITY_EVENTS_MAX_PAGE_SIZE } from "../../services/apiRequestService";

const PAGE_SIZES = [10, 20, 50, SECURITY_EVENTS_MAX_PAGE_SIZE];

interface SecurityEventsPaginationProps {
  /** Zero-based, as returned by the API. */
  page: number;
  size: number;
  totalElements: number;
  totalPages: number;
  shownCount: number;
  disabled: boolean;
  onPageChange: (page: number) => void;
  onSizeChange: (size: number) => void;
}

export function SecurityEventsPagination({
  page,
  size,
  totalElements,
  totalPages,
  shownCount,
  disabled,
  onPageChange,
  onSizeChange,
}: SecurityEventsPaginationProps) {
  const firstShown = shownCount === 0 ? 0 : page * size + 1;
  const lastShown = page * size + shownCount;
  const hasPrevious = page > 0;
  const hasNext = page + 1 < totalPages;

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-text-secondary">
      <span>
        {shownCount === 0
          ? `${formatNumber(totalElements)} events`
          : `Showing ${formatNumber(firstShown)}–${formatNumber(lastShown)} of ${formatNumber(totalElements)}`}
      </span>

      <div className="flex items-center gap-3">
        <label className="flex items-center gap-1.5 text-text-muted">
          Per page
          <select
            value={size}
            disabled={disabled}
            onChange={(event) => onSizeChange(Number(event.target.value))}
            className="rounded-md border border-border bg-surface-raised px-1.5 py-1 text-xs text-text-primary outline-none focus:border-primary/40 disabled:opacity-50"
          >
            {PAGE_SIZES.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </label>

        <div className="flex items-center gap-1">
          <button
            type="button"
            onClick={() => onPageChange(page - 1)}
            disabled={disabled || !hasPrevious}
            aria-label="Previous page"
            className="flex h-7 w-7 items-center justify-center rounded-md border border-border bg-surface-raised text-text-secondary transition-colors hover:border-primary/40 hover:text-text-primary disabled:cursor-not-allowed disabled:opacity-40"
          >
            <ChevronLeft className="h-3.5 w-3.5" />
          </button>
          <span className="min-w-[88px] text-center text-text-muted">
            Page {formatNumber(page + 1)} of {formatNumber(Math.max(totalPages, 1))}
          </span>
          <button
            type="button"
            onClick={() => onPageChange(page + 1)}
            disabled={disabled || !hasNext}
            aria-label="Next page"
            className="flex h-7 w-7 items-center justify-center rounded-md border border-border bg-surface-raised text-text-secondary transition-colors hover:border-primary/40 hover:text-text-primary disabled:cursor-not-allowed disabled:opacity-40"
          >
            <ChevronRight className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
}
