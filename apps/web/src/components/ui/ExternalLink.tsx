import React from "react";

export interface ExternalLinkProps extends React.AnchorHTMLAttributes<HTMLAnchorElement> {
  href: string;
  children: React.ReactNode;
  showIcon?: boolean;
}

export const ExternalLink: React.FC<ExternalLinkProps> = ({
  href,
  children,
  className = "",
  showIcon = true,
  ...props
}) => {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className={`inline-flex items-center gap-1 text-cyan-400 hover:text-cyan-300 hover:underline ${className}`}
      {...props}
    >
      <span>{children}</span>
      {showIcon && (
        <span className="text-[10px] text-zinc-500" aria-label="(opens in a new tab)">
          ↗
        </span>
      )}
    </a>
  );
};
