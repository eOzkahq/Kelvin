import { type InputHTMLAttributes, forwardRef, useId } from "react";

export interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  helperText?: string;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ label, error, helperText, id, className = "", ...props }, ref) => {
    const generatedId = useId();
    const inputId = id ?? generatedId;
    const errorId = `${inputId}-error`;
    const helperId = `${inputId}-helper`;

    return (
      <div className="flex flex-col gap-1.5 w-full">
        {label && (
            <label htmlFor={inputId} className="text-[13px] font-semibold text-zinc-200 tracking-wide">
              {label}
              {props.required && <span className="text-red-400 ml-1">*</span>}
            </label>
        )}
            <input
              ref={ref}
              id={inputId}
              aria-invalid={Boolean(error)}
              aria-describedby={error ? errorId : helperText ? helperId : undefined}
              className={`w-full bg-zinc-950/90 border rounded-lg px-3.5 py-2.5 text-[14px] text-zinc-100 placeholder-zinc-500 shadow-inner transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-1 focus-visible:ring-offset-zinc-950 ${
                error
                  ? "border-red-500 focus-visible:ring-red-500"
                  : "border-zinc-700/80 hover:border-[var(--brand-border)] focus-visible:ring-[var(--brand)] focus-visible:border-[var(--brand)]"
              } ${className}`}
              {...props}
            />
        {error && (
          <p id={errorId} className="text-xs font-medium text-red-400 flex items-center gap-1">
            {error}
          </p>
        )}
        {!error && helperText && (
          <p id={helperId} className="text-xs text-zinc-400">
            {helperText}
          </p>
        )}
      </div>
    );
  },
);

Input.displayName = "Input";
