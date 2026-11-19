import React, { useEffect, useRef } from "react";

export interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children: React.ReactNode;
  footer?: React.ReactNode;
  maxWidth?: "sm" | "md" | "lg" | "xl";
}

const maxWidthMap = {
  sm: "max-w-sm",
  md: "max-w-md",
  lg: "max-w-lg",
  xl: "max-w-2xl",
};

export const Modal: React.FC<ModalProps> = ({
  isOpen,
  onClose,
  title,
  description,
  children,
  footer,
  maxWidth = "md",
}) => {
  const modalRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!isOpen) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        onClose();
      }
    };

    document.addEventListener("keydown", handleKeyDown);
    document.body.style.overflow = "hidden";

    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      document.body.style.overflow = "unset";
    };
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-150"
      role="dialog"
      aria-modal="true"
      aria-labelledby="modal-title"
      aria-describedby={description ? "modal-description" : undefined}
      onClick={(e) => {
        if (e.target === e.currentTarget) {
          onClose();
        }
      }}
    >
      <div
        ref={modalRef}
        className={`w-full ${maxWidthMap[maxWidth]} surface-card gold-hairline-top rounded-2xl border-zinc-700/80 shadow-[0_24px_70px_rgba(0,0,0,0.85)] p-6 text-zinc-100 focus-visible:outline-none`}
        tabIndex={-1}
      >
        <div className="flex items-start justify-between pb-3.5 border-b border-zinc-800/80">
          <div>
            <h2 id="modal-title" className="text-base font-semibold text-zinc-100 font-display tracking-tight">
              {title}
            </h2>
            {description && (
              <p id="modal-description" className="text-xs text-zinc-400 mt-1 font-sans">
                {description}
              </p>
            )}
          </div>
          <div className="flex items-center gap-2 ml-4">
            <kbd className="hidden sm:inline-block rounded border border-zinc-800 bg-zinc-950 px-1.5 py-0.5 text-[10px] font-mono text-zinc-500">
              ESC
            </kbd>
            <button
              type="button"
              onClick={onClose}
              className="text-zinc-400 hover:text-zinc-100 transition-colors rounded-lg p-1.5 hover:bg-zinc-800/80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#d4c9a8]"
              aria-label="Close dialog"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                <path d="M18 6 6 18" />
                <path d="m6 6 12 12" />
              </svg>
            </button>
          </div>
        </div>

        <div className="py-4 text-sm">{children}</div>

        {footer && (
          <div className="flex items-center justify-end gap-2.5 pt-3.5 border-t border-zinc-800/80">
            {footer}
          </div>
        )}
      </div>
    </div>
  );
};
