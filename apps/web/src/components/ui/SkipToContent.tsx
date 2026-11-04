import React from "react";

export interface SkipToContentProps {
  targetId?: string;
  label?: string;
}

export const SkipToContent: React.FC<SkipToContentProps> = ({
  targetId = "main-content",
  label = "Skip to main content",
}) => {
  return (
    <a
      href={`#${targetId}`}
      className="sr-only focus:not-sr-only focus:fixed focus:top-3 focus:left-3 focus:z-50 focus:rounded-md focus:bg-cyan-500 focus:px-4 focus:py-2 focus:text-xs focus:font-semibold focus:text-black focus:shadow-lg focus:outline-none focus:ring-2 focus:ring-white"
    >
      {label}
    </a>
  );
};
