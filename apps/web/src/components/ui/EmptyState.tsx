import React from "react";
import { Button } from "./Button";
import { ShieldIcon } from "./Icons";

export interface EmptyStateProps {
  title: string;
  description: string;
  icon?: React.ReactNode;
  actionLabel?: string;
  onAction?: () => void;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  title,
  description,
  icon,
  actionLabel,
  onAction,
}) => {
  return (
    <div className="flex flex-col items-center justify-center p-10 text-center border border-dashed border-zinc-800/90 rounded-xl bg-zinc-950/60">
        <div className="mb-3 flex h-11 w-11 items-center justify-center rounded-xl border border-[var(--brand-border)] bg-zinc-900 text-[var(--brand)] shadow-sm">
          {icon ?? <ShieldIcon size={20} />}
        </div>
        <h4 className="text-base font-semibold text-zinc-100 font-display">{title}</h4>
        <p className="text-xs text-zinc-400 max-w-sm mt-1.5 mb-5 leading-relaxed">{description}</p>
        {actionLabel && onAction && (
          <Button variant="outline" size="sm" onClick={onAction}>
            {actionLabel}
          </Button>
        )}
      </div>
      );
};
