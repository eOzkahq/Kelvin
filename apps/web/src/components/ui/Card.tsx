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
    default: "bg-zinc-900/90 border border-zinc-800/90 shadow-sm backdrop-blur-sm hover:border-[#d4c9a8]/30 transition-all duration-200",
    elevated: "bg-zinc-900/95 border border-zinc-700/80 shadow-lg shadow-black/50 hover:border-[#d4c9a8]/40 hover:shadow-[0_0_25px_rgba(212,201,168,0.06)] transition-all duration-200",
    accent: "bg-gradient-to-b from-zinc-900 to-zinc-950 border border-[#d4c9a8]/35 shadow-md shadow-black/40 hover:border-[#d4c9a8]/60 hover:shadow-[0_0_30px_rgba(212,201,168,0.1)] transition-all duration-200",
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
