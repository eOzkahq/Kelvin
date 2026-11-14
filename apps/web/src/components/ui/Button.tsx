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
    "bg-[#f0eeea] hover:bg-[#d4c9a8] text-[#0c0c0c] font-bold tracking-wider uppercase shadow-[0_0_20px_rgba(212,201,168,0.15)] border border-[#d4c9a8] focus-visible:ring-[#d4c9a8]",
  secondary:
    "bg-zinc-900/90 hover:bg-zinc-800 text-zinc-200 font-semibold tracking-wider uppercase border border-zinc-700/80 hover:border-[#d4c9a8]/50 focus-visible:ring-[#d4c9a8]",
  danger:
    "bg-red-950/80 hover:bg-red-900 text-red-200 font-semibold tracking-wider uppercase border border-red-800 focus-visible:ring-red-500",
  ghost:
    "bg-transparent hover:bg-zinc-800/60 text-zinc-300 hover:text-[#d4c9a8] border border-transparent focus-visible:ring-[#d4c9a8]",
  outline:
    "bg-transparent hover:bg-[#d4c9a8]/10 text-[#d4c9a8] border border-[#d4c9a8]/60 hover:border-[#d4c9a8] font-semibold tracking-wider uppercase focus-visible:ring-[#d4c9a8]",
};

const sizeStyles: Record<ButtonSize, string> = {
  sm: "px-2.5 py-1 text-xs gap-1.5 rounded",
  md: "px-3.5 py-1.5 text-sm gap-2 rounded-md",
  lg: "px-5 py-2.5 text-base gap-2.5 rounded-lg",
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
        className={`inline-flex items-center justify-center transition-colors font-sans duration-150 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-offset-zinc-950 ${variantStyles[variant]} ${sizeStyles[size]} ${className}`}
        {...props}
      >
        {isLoading && (
          <svg
            className="animate-spin -ml-0.5 h-4 w-4 text-current"
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
