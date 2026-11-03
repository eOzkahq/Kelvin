import React from "react";

export interface SkeletonProps extends React.HTMLAttributes<HTMLDivElement> {
  lines?: number;
}

export const SkeletonLoader: React.FC<SkeletonProps> = ({
  lines = 1,
  className = "",
  ...props
}) => {
  return (
    <div className="flex flex-col gap-2 w-full animate-pulse" role="status" aria-label="Loading content">
      {Array.from({ length: lines }).map((_, i) => (
        <div
          key={i}
          className={`h-4 bg-zinc-800/80 rounded ${className}`}
          {...props}
        />
      ))}
      <span className="sr-only">Loading...</span>
    </div>
  );
};
