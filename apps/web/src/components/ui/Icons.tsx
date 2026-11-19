import React from "react";

export interface IconProps extends React.SVGProps<SVGSVGElement> {
  size?: number;
}

const baseProps = (size: number, className?: string): React.SVGProps<SVGSVGElement> => ({
  width: size,
  height: size,
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.6,
  strokeLinecap: "round",
  strokeLinejoin: "round",
  className: `shrink-0 ${className ?? ""}`.trim(),
  "aria-hidden": true,
});

export const ShieldIcon: React.FC<IconProps> = ({ size = 16, className, ...rest }) => (
  <svg {...baseProps(size, className)} {...rest}>
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    <path d="m9 12 2 2 4-4" />
  </svg>
);

export const RadarIcon: React.FC<IconProps> = ({ size = 16, className, ...rest }) => (
  <svg {...baseProps(size, className)} {...rest}>
    <path d="M19.07 4.93A10 10 0 0 0 6.99 3.34" />
    <path d="M4 6h.01" />
    <path d="M2.29 9.62A10 10 0 1 0 21.31 8.35" />
    <path d="M16.24 7.76A6 6 0 1 0 8.23 16.67" />
    <path d="M12 18h.01" />
    <path d="M17.99 11.66A6 6 0 0 1 15.77 16.67" />
    <circle cx="12" cy="12" r="2" />
    <path d="m13.41 10.59 5.66-5.66" />
  </svg>
);

export const SearchIcon: React.FC<IconProps> = ({ size = 16, className, ...rest }) => (
  <svg {...baseProps(size, className)} {...rest}>
    <circle cx="11" cy="11" r="7" />
    <path d="m20 20-3.5-3.5" />
  </svg>
);

export const WrenchIcon: React.FC<IconProps> = ({ size = 16, className, ...rest }) => (
  <svg {...baseProps(size, className)} {...rest}>
    <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" />
  </svg>
);

export const TargetIcon: React.FC<IconProps> = ({ size = 16, className, ...rest }) => (
  <svg {...baseProps(size, className)} {...rest}>
    <circle cx="12" cy="12" r="9" />
    <circle cx="12" cy="12" r="5" />
    <circle cx="12" cy="12" r="1.5" fill="currentColor" stroke="none" />
  </svg>
);

export const FileTextIcon: React.FC<IconProps> = ({ size = 16, className, ...rest }) => (
  <svg {...baseProps(size, className)} {...rest}>
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
    <path d="M14 2v6h6" />
    <path d="M8 13h8" />
    <path d="M8 17h5" />
  </svg>
);

export const ScaleIcon: React.FC<IconProps> = ({ size = 16, className, ...rest }) => (
  <svg {...baseProps(size, className)} {...rest}>
    <path d="m16 16 3-8 3 8c-.87.65-1.92 1-3 1s-2.13-.35-3-1Z" />
    <path d="m2 16 3-8 3 8c-.87.65-1.92 1-3 1s-2.13-.35-3-1Z" />
    <path d="M7 21h10" />
    <path d="M12 3v18" />
    <path d="M3 7h2c2 0 5-1 7-2 2 1 5 2 7 2h2" />
  </svg>
);

export const ScrollIcon: React.FC<IconProps> = ({ size = 16, className, ...rest }) => (
  <svg {...baseProps(size, className)} {...rest}>
    <path d="M8 21h12a2 2 0 0 0 2-2v-2H10v2a2 2 0 1 1-4 0V5a2 2 0 1 0-4 0v3h4" />
    <path d="M19 17V5a2 2 0 0 0-2-2H4" />
    <path d="M10 8h5" />
    <path d="M10 12h5" />
  </svg>
);

export const BuildingIcon: React.FC<IconProps> = ({ size = 16, className, ...rest }) => (
  <svg {...baseProps(size, className)} {...rest}>
    <rect x="4" y="2" width="16" height="20" rx="2" />
    <path d="M9 22v-4h6v4" />
    <path d="M8 6h.01" />
    <path d="M16 6h.01" />
    <path d="M12 6h.01" />
    <path d="M12 10h.01" />
    <path d="M12 14h.01" />
    <path d="M16 10h.01" />
    <path d="M16 14h.01" />
    <path d="M8 10h.01" />
    <path d="M8 14h.01" />
  </svg>
);

export const UsersIcon: React.FC<IconProps> = ({ size = 16, className, ...rest }) => (
  <svg {...baseProps(size, className)} {...rest}>
    <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
    <circle cx="9" cy="7" r="4" />
    <path d="M22 21v-2a4 4 0 0 0-3-3.87" />
    <path d="M16 3.13a4 4 0 0 1 0 7.75" />
  </svg>
);

export const LockIcon: React.FC<IconProps> = ({ size = 16, className, ...rest }) => (
  <svg {...baseProps(size, className)} {...rest}>
    <rect x="3" y="11" width="18" height="11" rx="2" />
    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
  </svg>
);

export const PlugIcon: React.FC<IconProps> = ({ size = 16, className, ...rest }) => (
  <svg {...baseProps(size, className)} {...rest}>
    <path d="M12 22v-5" />
    <path d="M9 8V2" />
    <path d="M15 8V2" />
    <path d="M18 8v5a4 4 0 0 1-4 4h-4a4 4 0 0 1-4-4V8Z" />
  </svg>
);

export const SlidersIcon: React.FC<IconProps> = ({ size = 16, className, ...rest }) => (
  <svg {...baseProps(size, className)} {...rest}>
    <line x1="4" y1="21" x2="4" y2="14" />
    <line x1="4" y1="10" x2="4" y2="3" />
    <line x1="12" y1="21" x2="12" y2="12" />
    <line x1="12" y1="8" x2="12" y2="3" />
    <line x1="20" y1="21" x2="20" y2="16" />
    <line x1="20" y1="12" x2="20" y2="3" />
    <line x1="2" y1="14" x2="6" y2="14" />
    <line x1="10" y1="8" x2="14" y2="8" />
    <line x1="18" y1="16" x2="22" y2="16" />
  </svg>
);

export const TerminalIcon: React.FC<IconProps> = ({ size = 16, className, ...rest }) => (
  <svg {...baseProps(size, className)} {...rest}>
    <polyline points="4 17 10 11 4 5" />
    <line x1="12" y1="19" x2="20" y2="19" />
  </svg>
);

export const BellIcon: React.FC<IconProps> = ({ size = 16, className, ...rest }) => (
  <svg {...baseProps(size, className)} {...rest}>
    <path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9" />
    <path d="M10.3 21a1.94 1.94 0 0 0 3.4 0" />
  </svg>
);

export const SparklesIcon: React.FC<IconProps> = ({ size = 16, className, ...rest }) => (
  <svg {...baseProps(size, className)} {...rest}>
    <path d="m12 3-1.91 5.81a2 2 0 0 1-1.28 1.28L3 12l5.81 1.91a2 2 0 0 1 1.28 1.28L12 21l1.91-5.81a2 2 0 0 1 1.28-1.28L21 12l-5.81-1.91a2 2 0 0 1-1.28-1.28L12 3Z" />
  </svg>
);

export const CheckCircleIcon: React.FC<IconProps> = ({ size = 16, className, ...rest }) => (
  <svg {...baseProps(size, className)} {...rest}>
    <circle cx="12" cy="12" r="10" />
    <path d="m9 12 2 2 4-4" />
  </svg>
);

export const AlertTriangleIcon: React.FC<IconProps> = ({ size = 16, className, ...rest }) => (
  <svg {...baseProps(size, className)} {...rest}>
    <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
    <path d="M12 9v4" />
    <path d="M12 17h.01" />
  </svg>
);

export const RefreshIcon: React.FC<IconProps> = ({ size = 16, className, ...rest }) => (
  <svg {...baseProps(size, className)} {...rest}>
    <path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8" />
    <path d="M21 3v5h-5" />
  </svg>
);

export const PlusIcon: React.FC<IconProps> = ({ size = 16, className, ...rest }) => (
  <svg {...baseProps(size, className)} {...rest}>
    <path d="M12 5v14" />
    <path d="M5 12h14" />
  </svg>
);

export const DownloadIcon: React.FC<IconProps> = ({ size = 16, className, ...rest }) => (
  <svg {...baseProps(size, className)} {...rest}>
    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
    <polyline points="7 10 12 15 17 10" />
    <line x1="12" y1="15" x2="12" y2="3" />
  </svg>
);

export const ArrowRightIcon: React.FC<IconProps> = ({ size = 16, className, ...rest }) => (
  <svg {...baseProps(size, className)} {...rest}>
    <path d="M5 12h14" />
    <path d="m12 5 7 7-7 7" />
  </svg>
);

export const ChevronRightIcon: React.FC<IconProps> = ({ size = 16, className, ...rest }) => (
  <svg {...baseProps(size, className)} {...rest}>
    <path d="m9 18 6-6-6-6" />
  </svg>
);

export const KeyIcon: React.FC<IconProps> = ({ size = 16, className, ...rest }) => (
  <svg {...baseProps(size, className)} {...rest}>
    <circle cx="7.5" cy="15.5" r="5.5" />
    <path d="m21 2-9.6 9.6" />
    <path d="m15.5 7.5 3 3L22 7l-3-3" />
  </svg>
);

export const ActivityIcon: React.FC<IconProps> = ({ size = 16, className, ...rest }) => (
  <svg {...baseProps(size, className)} {...rest}>
    <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
  </svg>
);

export const CopyIcon: React.FC<IconProps> = ({ size = 14, className, ...rest }) => (
  <svg {...baseProps(size, className)} {...rest}>
    <rect x="9" y="9" width="13" height="13" rx="2" />
    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
  </svg>
);

export const NavIcon: React.FC<{ route: string; className?: string; size?: number }> = ({
  route,
  className,
  size = 16,
}) => {
  switch (route) {
    case "/dashboard":
      return <ActivityIcon size={size} className={className} />;
    case "/assessments":
      return <RadarIcon size={size} className={className} />;
    case "/findings":
      return <SearchIcon size={size} className={className} />;
    case "/remediation":
      return <WrenchIcon size={size} className={className} />;
    case "/targets":
      return <TargetIcon size={size} className={className} />;
    case "/reports":
      return <FileTextIcon size={size} className={className} />;
    case "/compare":
      return <ScaleIcon size={size} className={className} />;
    case "/audit":
      return <ScrollIcon size={size} className={className} />;
    case "/admin/org":
      return <BuildingIcon size={size} className={className} />;
    case "/admin/team":
      return <UsersIcon size={size} className={className} />;
    case "/admin/roles":
      return <LockIcon size={size} className={className} />;
    case "/admin/integrations":
      return <PlugIcon size={size} className={className} />;
    case "/admin/settings":
      return <SlidersIcon size={size} className={className} />;
    default:
      return <ShieldIcon size={size} className={className} />;
  }
};

