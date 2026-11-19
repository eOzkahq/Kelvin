import React from "react";

const base = (typeof import.meta !== "undefined" && import.meta.env?.BASE_URL) || "/services/kelvin/";

export const EOZKA_ASSETS = {
  mark: `${base}brand/eozka-venture-studio-logo.svg`,
  wordmark: `${base}brand/eozka-technology-holding-company-logo.svg`,
  fullLogo: `${base}brand/eOzka_Full_Logo_V2.svg`,
  taglineGold: `${base}brand/eOzka_Tagline_V1.svg`,
  taglineDual: `${base}brand/eOzka_Tagline_V2.svg`,
};

export interface BrandMarkProps {
  /** compact = sidebar/header mark; full = login/hero lockup with official tagline */
  variant?: "compact" | "full" | "inline";
  className?: string;
}

/**
 * Renders the official Kelvin + eOzka brand lockup using verified SVGs from the eOzka asset package.
 */
export const BrandMark: React.FC<BrandMarkProps> = ({ variant = "compact", className = "" }) => {
  if (variant === "inline") {
    return (
      <span className={`inline-flex items-center gap-2 ${className}`}>
        <img
          src={EOZKA_ASSETS.mark}
          alt="eOzka"
          className="h-5 w-5 rounded-md object-contain shrink-0"
        />
        <span className="text-xs font-semibold tracking-tight text-zinc-200">
          eOzka <span className="text-[var(--brand-text)] font-normal">· Augmenting Sentient</span>
        </span>
      </span>
    );
  }

  if (variant === "full") {
    return (
      <div className={`space-y-4 ${className}`}>
        <div className="flex items-center gap-3.5">
          <div className="h-12 w-12 rounded-xl border border-[var(--brand-border)] bg-zinc-900 p-1.5 shadow-sm flex items-center justify-center shrink-0">
            <img
              src={EOZKA_ASSETS.mark}
              alt="eOzka emblem"
              className="h-full w-full object-contain"
            />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-2xl font-bold tracking-tight text-zinc-100 font-display leading-none">
                KELVIN
              </h2>
              <span className="rounded-md border border-[var(--brand-border)] bg-[var(--brand-bg)] px-2 py-0.5 text-[11px] font-mono font-semibold text-[var(--brand-text)]">
                by eOzka
              </span>
            </div>
            <p className="text-[13px] text-[var(--brand-text)] font-medium tracking-wide mt-1">
              Augmenting Sentient · Security Assessment Platform
            </p>
          </div>
        </div>

        {/* Official eOzka Cursive Tagline + Wordmark Lockup */}
        <div className="inline-flex items-center gap-3 rounded-xl border border-zinc-800/90 bg-zinc-900/75 px-3.5 py-2">
          <img
            src={EOZKA_ASSETS.mark}
            alt="eOzka Operational Holding Company"
            className="h-6 w-6 object-contain shrink-0"
          />
          <div className="h-5 w-px bg-zinc-800" aria-hidden="true" />
          <div className="flex flex-col">
            <span className="text-xs font-semibold tracking-wide text-zinc-100">
              eOzka Operational Holding
            </span>
            <span className="text-[11px] italic text-[var(--brand-text)]">
              Augmenting Sentient
            </span>
          </div>
        </div>
      </div>
    );
  }

  // compact
  return (
    <div className={`flex items-center gap-2.5 ${className}`}>
      <div className="h-8 w-8 rounded-lg border border-[var(--brand-border)] bg-zinc-900 p-1 flex items-center justify-center shrink-0">
        <img
          src={EOZKA_ASSETS.mark}
          alt="eOzka"
          className="h-full w-full object-contain"
        />
      </div>
      <div className="min-w-0">
        <div className="flex items-center gap-1.5 leading-none">
          <span className="font-bold tracking-tight text-zinc-100 text-[15px] font-display">
            KELVIN
          </span>
          <span className="text-[11px] font-mono text-[var(--brand-text)] font-medium">
            by eOzka
          </span>
        </div>
        <div className="text-[10px] text-zinc-400 tracking-wide truncate mt-0.5">
          Augmenting Sentient
        </div>
      </div>
    </div>
  );
};

