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
    default: "bg-zinc-900/90 border border-zinc-800 shadow-sm",
    elevated: "bg-zinc-900 border border-zinc-700/80 shadow-md shadow-black/40",
    accent: "bg-gradient-to-b from-zinc-900 to-zinc-950 border border-cyan-800/40 shadow-sm",
  };

  return (
    <div
      className={`rounded-lg p-5 text-zinc-100 transition-colors ${variantStyles[variant]} ${className}`}
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
  <div className={`flex items-center justify-between pb-3 border-b border-zinc-800 mb-4 ${className}`} {...props}>
    {children}
  </div>
);

export const CardTitle: React.FC<React.HTMLAttributes<HTMLHeadingElement>> = ({
  className = "",
  children,
  ...props
}) => (
  <h3 className={`text-base font-semibold text-zinc-100 tracking-tight ${className}`} {...props}>
    {children}
  </h3>
);

export const CardDescription: React.FC<React.HTMLAttributes<HTMLParagraphElement>> = ({
  className = "",
  children,
  ...props
}) => (
  <p className={`text-xs text-zinc-400 mt-0.5 ${className}`} {...props}>
    {children}
  </p>
);
