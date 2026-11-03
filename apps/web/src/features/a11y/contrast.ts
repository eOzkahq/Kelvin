/**
 * WCAG 2.2 Relative Luminance and Contrast Ratio Calculation Engine.
 */

export interface RGB {
  r: number;
  g: number;
  b: number;
}

/**
 * Parses a 6-digit hex color string into RGB components.
 */
export function hexToRgb(hex: string): RGB {
  const cleanHex = hex.replace("#", "").trim();
  if (cleanHex.length === 3) {
    return {
      r: parseInt(cleanHex[0] + cleanHex[0], 16),
      g: parseInt(cleanHex[1] + cleanHex[1], 16),
      b: parseInt(cleanHex[2] + cleanHex[2], 16),
    };
  }
  return {
    r: parseInt(cleanHex.slice(0, 2), 16),
    g: parseInt(cleanHex.slice(2, 4), 16),
    b: parseInt(cleanHex.slice(4, 6), 16),
  };
}

/**
 * Computes relative luminance according to W3C WCAG 2.2 specification.
 */
export function getRelativeLuminance({ r, g, b }: RGB): number {
  const normalize = (val: number) => {
    const s = val / 255;
    return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
  };

  const R = normalize(r);
  const G = normalize(g);
  const B = normalize(b);

  return 0.2126 * R + 0.7152 * G + 0.0722 * B;
}

/**
 * Computes contrast ratio between foreground and background colors.
 * Returns a value between 1.0 and 21.0.
 */
export function getContrastRatio(foregroundHex: string, backgroundHex: string): number {
  const lum1 = getRelativeLuminance(hexToRgb(foregroundHex));
  const lum2 = getRelativeLuminance(hexToRgb(backgroundHex));

  const lighter = Math.max(lum1, lum2);
  const darker = Math.min(lum1, lum2);

  const ratio = (lighter + 0.05) / (darker + 0.05);
  return Number(ratio.toFixed(2));
}

/**
 * Verifies if contrast ratio meets WCAG 2.2 Level AA requirements.
 * - Normal text: >= 4.5:1
 * - Large text (>=18pt or >=14pt bold): >= 3.0:1
 * - UI Components & Graphical objects: >= 3.0:1
 */
export function meetsWcagAA(
  foregroundHex: string,
  backgroundHex: string,
  type: "normalText" | "largeText" | "uiComponent" = "normalText"
): boolean {
  const ratio = getContrastRatio(foregroundHex, backgroundHex);
  if (type === "normalText") {
    return ratio >= 4.5;
  }
  return ratio >= 3.0;
}
