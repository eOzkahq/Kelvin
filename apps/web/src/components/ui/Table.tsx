import React from "react";

export const Table: React.FC<React.TableHTMLAttributes<HTMLTableElement>> = ({
  className = "",
  children,
  ...props
}) => (
  <div className="w-full overflow-x-auto rounded-xl surface-card">
    <table className={`w-full text-left text-sm text-zinc-300 ${className}`} {...props}>
      {children}
    </table>
  </div>
);

export const TableHeader: React.FC<React.HTMLAttributes<HTMLTableSectionElement>> = ({
  className = "",
  children,
  ...props
}) => (
  <thead
    className={`bg-zinc-950/90 text-[10px] uppercase font-mono tracking-wider font-medium text-zinc-400 border-b border-zinc-800/80 ${className}`}
    {...props}
  >
    {children}
  </thead>
);

export const TableBody: React.FC<React.HTMLAttributes<HTMLTableSectionElement>> = ({
  className = "",
  children,
  ...props
}) => (
  <tbody className={`divide-y divide-zinc-800/60 ${className}`} {...props}>
    {children}
  </tbody>
);

export const TableRow: React.FC<React.HTMLAttributes<HTMLTableRowElement>> = ({
  className = "",
  children,
  ...props
}) => (
  <tr className={`transition-colors hover:bg-zinc-800/35 ${className}`} {...props}>
    {children}
  </tr>
);

export const TableHead: React.FC<React.ThHTMLAttributes<HTMLTableCellElement>> = ({
  className = "",
  children,
  ...props
}) => (
  <th className={`px-4 py-3 font-semibold tracking-wider ${className}`} {...props}>
    {children}
  </th>
);

export const TableCell: React.FC<React.TdHTMLAttributes<HTMLTableCellElement>> = ({
  className = "",
  children,
  ...props
}) => (
  <td className={`px-4 py-3 align-middle ${className}`} {...props}>
    {children}
  </td>
);
