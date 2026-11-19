import React, { type ButtonHTMLAttributes, forwardRef } from "react";

export type ButtonVariant = "primary" | "secondary" | "danger" | "ghost" | "outline";
export type ButtonSize = "sm" | "md" | "lg";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  isLoading?: boolean;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
}

const variantStyles: Record<ButtonVariant, string> = {
  primary:
  "bg-gradient-to-b from-[var(--brand-btn-from)] to-[var(--brand-btn-to)] hover:opacity-95 text-[var(--brand-btn-fg)] font-semibold tracking-wide shadow-sm border border-[var(--brand-btn-border)] focus-visible:ring-[var(--brand)] active:scale-[0.99]",
  secondary:
  "bg-zinc-900 hover:bg-zinc-850 text-zinc-200 font-medium border border-zinc-700 hover:border-[var(--brand-border)] shadow-xs focus-visible:ring-[var(--brand)]",
  danger:
  "bg-red-950/90 hover:bg-red-900/90 text-red-300 font-medium border border-red-800/80 hover:border-red-600 focus-visible:ring-red-500",
  ghost:
  "bg-transparent hover:bg-zinc-800/70 text-zinc-300 hover:text-[var(--brand-text)] border border-transparent focus-visible:ring-[var(--brand)]",
  outline:
  "bg-[var(--brand-bg)] hover:opacity-90 text-[var(--brand-text)] border border-[var(--brand-border)] hover:border-[var(--brand)] font-medium focus-visible:ring-[var(--brand)]",
};

const sizeStyles: Record<ButtonSize, string> = {
  sm: "px-3 py-1.5 text-xs gap-1.5 rounded-lg",
  md: "px-4 py-2 text-xs sm:text-sm gap-2 rounded-lg",
  lg: "px-5 py-2.5 text-sm gap-2.5 rounded-xl",
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      variant = "primary",
      size = "md",
      isLoading = false,
      leftIcon,
      rightIcon,
      children,
      disabled,
      className = "",
      ...props
    },
    ref,
  ) => {
    return (
      <button
        ref={ref}
        disabled={disabled || isLoading}
        className={`inline-flex items-center justify-center silk-transition silk-press font-sans cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-offset-zinc-950 whitespace-nowrap ${variantStyles[variant]} ${sizeStyles[size]} ${className}`}
        {...props}
      >
        {isLoading && (
          <svg
            className="animate-spin -ml-0.5 h-3.5 w-3.5 text-current"
            xmlns="http://www.w3.org/2000/svg"
            fill="none"
            viewBox="0 0 24 24"
            aria-hidden="true"
          >
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path
              className="opacity-75"
              fill="currentColor"
              d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
            />
          </svg>
        )}
        {!isLoading && leftIcon}
        <span>{children}</span>
        {!isLoading && rightIcon}
      </button>
    );
  },
);

Button.displayName = "Button";
