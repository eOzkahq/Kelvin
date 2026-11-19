import React from "react";

export interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: "default" | "elevated" | "accent";
}

export const Card: React.FC<CardProps> = ({
  variant = "default",
  className = "",
  children,
  ...props
}) => {
  const variantStyles = {
    default:
    "surface-card silk-spring-hover hover:border-[var(--brand-border)]",
    elevated:
    "surface-card gold-hairline-top border-zinc-700/80 shadow-md silk-spring-hover hover:border-[var(--brand-border)]",
    accent:
    "surface-card gold-hairline-top border-[var(--brand-border)] shadow-md silk-spring-hover hover:border-[var(--brand)]",
  };

  return (
    <div
      className={`rounded-xl p-5 text-zinc-100 ${variantStyles[variant]} ${className}`}
      {...props}
    >
      {children}
    </div>
  );
};

export const CardHeader: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({
  className = "",
  children,
  ...props
}) => (
  <div
    className={`flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3.5 border-b border-zinc-800/80 mb-4 ${className}`}
    {...props}
  >
    {children}
  </div>
);

export const CardTitle: React.FC<React.HTMLAttributes<HTMLHeadingElement>> = ({
  className = "",
  children,
  ...props
}) => (
  <h3 className={`text-sm sm:text-base font-semibold text-zinc-100 tracking-tight font-display ${className}`} {...props}>
    {children}
  </h3>
);

export const CardDescription: React.FC<React.HTMLAttributes<HTMLParagraphElement>> = ({
  className = "",
  children,
  ...props
}) => (
  <p className={`text-xs text-zinc-400 mt-0.5 leading-relaxed ${className}`} {...props}>
    {children}
  </p>
);
