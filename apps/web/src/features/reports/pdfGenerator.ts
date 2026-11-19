import { buildStructuredReport } from "./reportModel";
import type { ReportItem } from "./types";

type RGB = [number, number, number];

// Official eOzka Editorial Print Palette (Royal Indigo #211a57, Warm Gold #b38a2b, Ivory #faf8f5, Deep Ink #0f1423)
const INK = {
  black: [15 / 255, 20 / 255, 35 / 255] as RGB,
  indigo: [33 / 255, 26 / 255, 87 / 255] as RGB,
  gold: [179 / 255, 138 / 255, 43 / 255] as RGB,
  ivory: [250 / 255, 248 / 255, 245 / 255] as RGB,
  body: [24 / 255, 28 / 255, 40 / 255] as RGB,
  sub: [82 / 255, 82 / 255, 91 / 255] as RGB,
  muted: [107 / 255, 98 / 255, 82 / 255] as RGB,
  ruleDark: [33 / 255, 26 / 255, 87 / 255] as RGB,
  ruleMid: [179 / 255, 138 / 255, 43 / 255] as RGB,
  ruleLight: [231 / 255, 225 / 255, 212 / 255] as RGB,
  tintSoft: [250 / 255, 248 / 255, 245 / 255] as RGB,
  tintMed: [246 / 255, 245 / 255, 250 / 255] as RGB,
  white: [1, 1, 1] as RGB,

  critText: [153 / 255, 27 / 255, 27 / 255] as RGB,
  critBg: [254 / 255, 242 / 255, 242 / 255] as RGB,
  critBorder: [252 / 255, 165 / 255, 165 / 255] as RGB,

  highText: [154 / 255, 52 / 255, 18 / 255] as RGB,
  highBg: [255 / 255, 247 / 255, 237 / 255] as RGB,
  highBorder: [253 / 255, 186 / 255, 116 / 255] as RGB,

  medText: [146 / 255, 64 / 255, 14 / 255] as RGB,
  medBg: [255 / 255, 251 / 255, 235 / 255] as RGB,
  medBorder: [252 / 255, 211 / 255, 77 / 255] as RGB,

  lowText: [51 / 255, 65 / 255, 85 / 255] as RGB,
  lowBg: [248 / 255, 250 / 255, 252 / 255] as RGB,
  lowBorder: [203 / 255, 213 / 255, 225 / 255] as RGB,

  passText: [22 / 255, 101 / 255, 52 / 255] as RGB,
  passBg: [240 / 255, 253 / 255, 244 / 255] as RGB,
  passBorder: [134 / 255, 239 / 255, 172 / 255] as RGB,
};

function esc(text: string): string {
  return text
    .replace(/[^\x20-\x7E]/g, "-")
    .replace(/\\/g, "\\\\")
    .replace(/\(/g, "\\(")
    .replace(/\)/g, "\\)");
}

function rgbFill(c: RGB): string {
  return `${c[0].toFixed(3)} ${c[1].toFixed(3)} ${c[2].toFixed(3)} rg`;
}

function rgbStroke(c: RGB): string {
  return `${c[0].toFixed(3)} ${c[1].toFixed(3)} ${c[2].toFixed(3)} RG`;
}

function wrapLines(text: string, maxChars: number): string[] {
  const paragraphs = text.split("\n");
  const out: string[] = [];
  for (const para of paragraphs) {
    const words = para.split(/\s+/).filter(Boolean);
    if (words.length === 0) continue;
    let cur = "";
    for (const w of words) {
      if (!cur) {
        cur = w.length > maxChars ? w.slice(0, maxChars) : w;
      } else if (cur.length + 1 + w.length <= maxChars) {
        cur += ` ${w}`;
      } else {
        out.push(cur);
        cur = w.length > maxChars ? w.slice(0, maxChars) : w;
      }
    }
    if (cur) out.push(cur);
  }
  return out;
}

function tagColors(sev: string): { text: RGB; bg: RGB; border: RGB } {
  switch (sev.toUpperCase()) {
    case "CRITICAL":
    case "FAIL":
      return { text: INK.critText, bg: INK.critBg, border: INK.critBorder };
    case "HIGH":
      return { text: INK.highText, bg: INK.highBg, border: INK.highBorder };
    case "MEDIUM":
    case "WARN":
      return { text: INK.medText, bg: INK.medBg, border: INK.medBorder };
    case "PASS":
      return { text: INK.passText, bg: INK.passBg, border: INK.passBorder };
    default:
      return { text: INK.lowText, bg: INK.lowBg, border: INK.lowBorder };
  }
}

export function buildSecurityReportPdfBlob(report: ReportItem): Blob {
  const doc = buildStructuredReport(report);
  const pageW = 612;
  const pageH = 792;
  const marginX = 44;
  const contentW = pageW - marginX * 2;
  const bottomLimit = 56;

  const pages: string[][] = [[]];
  let curPage = pages[0];
  let y = pageH - 42;

  const newPage = () => {
    curPage = [];
    pages.push(curPage);
    y = pageH - 48;
    // eOzka indigo top bar on continuation pages
    curPage.push(`${rgbStroke(INK.indigo)} 1.5 w ${marginX} ${y + 14} m ${pageW - marginX} ${y + 14} l S`);
  };

  const ensureSpace = (needed: number) => {
    if (y - needed < bottomLimit) {
      newPage();
    }
  };

  const drawText = (
    x: number,
    yPos: number,
    text: string,
    font: "F1" | "F2" | "F3",
    size: number,
    color: RGB,
  ) => {
    curPage.push(`${rgbFill(color)} BT /${font} ${size} Tf 1 0 0 1 ${x.toFixed(1)} ${yPos.toFixed(1)} Tm (${esc(text)}) Tj ET`);
  };

  const drawLine = (x1: number, y1: number, x2: number, y2: number, color: RGB, width = 0.6) => {
    curPage.push(`${rgbStroke(color)} ${width} w ${x1.toFixed(1)} ${y1.toFixed(1)} m ${x2.toFixed(1)} ${y2.toFixed(1)} l S`);
  };

  const fillRect = (x: number, bottomY: number, w: number, h: number, color: RGB) => {
    curPage.push(`${rgbFill(color)} ${x.toFixed(1)} ${bottomY.toFixed(1)} ${w.toFixed(1)} ${h.toFixed(1)} re f`);
  };

  const strokeRect = (x: number, bottomY: number, w: number, h: number, color: RGB, width = 0.6) => {
    curPage.push(`${rgbStroke(color)} ${width} w ${x.toFixed(1)} ${bottomY.toFixed(1)} ${w.toFixed(1)} ${h.toFixed(1)} re S`);
  };

  const sectionHeading = (title: string) => {
    ensureSpace(32);
    y -= 8;
    drawText(marginX, y, title.toUpperCase(), "F2", 9.5, INK.indigo);
    y -= 5;
    drawLine(marginX, y, pageW - marginX, y, INK.indigo, 1.1);
    y -= 14;
  };

  // --- eOzka Official Editorial Masthead ---
  const mastH = 76;
  const mastBottom = y - mastH + 14;
  drawLine(marginX, y + 14, pageW - marginX, y + 14, INK.indigo, 2.5);
  fillRect(marginX, mastBottom, contentW, mastH, INK.ivory);
  strokeRect(marginX, mastBottom, contentW, mastH, INK.ruleLight, 0.6);

  // Platform & Brand Header Line
  drawText(
    marginX + 12,
    y - 2,
    `EOZKA - KELVIN SECURITY PLATFORM - AUGMENTING SENTIENT - ${doc.planLabel.toUpperCase()}`,
    "F2",
    8.5,
    INK.indigo,
  );

  y -= 23;
  const titleLines = wrapLines(report.title, 56);
  titleLines.slice(0, 1).forEach((line) => {
    drawText(marginX + 12, y, line, "F2", 14.5, INK.black);
  });

  drawText(
    marginX + 12,
    mastBottom + 8,
    `Target: ${report.targetHost}   |   Ref: ${report.assessmentId}   |   Redaction: ${report.redacted ? "Enforced" : "Unmasked"}`,
    "F3",
    7.6,
    INK.muted,
  );
  y = mastBottom - 2;
  drawLine(marginX, y, pageW - marginX, y, INK.gold, 1.8);
  y -= 12;

  // --- Hairline-Ruled 4-Column Metric Strip ---
  const stripH = 44;
  ensureSpace(stripH + 14);
  const stripTop = y;
  const cellW = contentW / 4;
  drawLine(marginX, stripTop - stripH, pageW - marginX, stripTop - stripH, INK.ruleLight, 0.8);

  doc.kpis.forEach((k, idx) => {
    const cx = marginX + idx * cellW + (idx === 0 ? 0 : 10);
    if (idx > 0) {
      drawLine(marginX + idx * cellW, stripTop, marginX + idx * cellW, stripTop - stripH, INK.ruleLight, 0.6);
    }
    const toneColor =
      k.tone === "danger"
        ? INK.critText
        : k.tone === "warn"
          ? INK.medText
          : k.tone === "success"
            ? INK.passText
            : INK.indigo;

    drawText(cx, stripTop - 10, k.label.toUpperCase().slice(0, 22), "F3", 7, INK.muted);
    drawText(cx, stripTop - 25, k.value.slice(0, 18), "F2", 11.5, toneColor);
    drawText(cx, stripTop - 37, k.sub.slice(0, 24), "F1", 7.5, INK.sub);
  });
  y = stripTop - stripH - 12;

  // --- Executive Overview & Scope Delta ---
  sectionHeading("Executive Overview & Scope Delta");
  wrapLines(doc.executiveSummary, 94).forEach((l) => {
    ensureSpace(14);
    drawText(marginX, y, l, "F1", 9, INK.body);
    y -= 13;
  });

  // --- Assessment Marking & Posture Scorecard ---
  sectionHeading(`Assessment Marking & Posture Scorecard (${doc.postureScore} / 100 · Grade ${doc.postureGrade})`);
  const scoreCols = ["Security Domain", "Score", "Assessment Notes", "Status"];
  const scoreX = [marginX, marginX + 170, marginX + 225, marginX + 465];
  ensureSpace(22 + doc.scoringRubric.length * 18);
  scoreCols.forEach((c, i) => drawText(scoreX[i], y - 2, c.toUpperCase(), "F3", 7.5, INK.indigo));
  y -= 8;
  drawLine(marginX, y, pageW - marginX, y, INK.gold, 0.9);
  y -= 13;

  doc.scoringRubric.forEach((sc) => {
    ensureSpace(20);
    drawText(scoreX[0], y, sc.category.slice(0, 32), "F2", 8.2, INK.body);
    drawText(scoreX[1], y, `${sc.earned} / ${sc.max}`, "F3", 8.2, INK.body);
    drawText(scoreX[2], y, sc.deductions.slice(0, 44), "F1", 8, INK.sub);
    const tc = tagColors(sc.status);
    fillRect(scoreX[3], y - 3, 46, 11, tc.bg);
    strokeRect(scoreX[3], y - 3, 46, 11, tc.border, 0.5);
    drawText(scoreX[3] + 6, y, sc.status, "F2", 7, tc.text);
    y -= 6;
    drawLine(marginX, y, pageW - marginX, y, INK.ruleLight, 0.5);
    y -= 12;
  });

  // --- Tier Scope Delta & Recon Tables ---
  for (const tbl of doc.tables) {
    sectionHeading(tbl.heading);
    const colCount = tbl.columns.length;
    const colW = contentW / colCount;
    ensureSpace(34);
    tbl.columns.forEach((col, ci) => {
      drawText(marginX + ci * colW, y - 2, col.toUpperCase().slice(0, Math.floor(colW / 5)), "F3", 7.5, INK.indigo);
    });
    y -= 8;
    drawLine(marginX, y, pageW - marginX, y, INK.gold, 0.9);
    y -= 13;

    tbl.rows.forEach((row) => {
      ensureSpace(19);
      row.forEach((cell, ci) => {
        const maxC = Math.max(12, Math.floor((colW - 10) / 4.8));
        drawText(marginX + ci * colW, y, (cell ?? "").slice(0, maxC), ci === 0 ? "F3" : "F1", 8, INK.body);
      });
      y -= 6;
      drawLine(marginX, y, pageW - marginX, y, INK.ruleLight, 0.5);
      y -= 12;
    });
  }

  // --- Tier-Segregated Findings ---
  sectionHeading(`Detailed Findings & Remediation Guidance (${doc.findings.length})`);

  for (const grp of doc.tierGroups) {
    ensureSpace(34);
    fillRect(marginX, y - 16, contentW, 20, INK.tintMed);
    fillRect(marginX, y - 16, 3, 20, INK.indigo);
    drawText(marginX + 10, y - 9, grp.heading.slice(0, 88), "F2", 8.5, INK.indigo);
    y -= 26;

    for (const f of grp.findings) {
      const descLines = wrapLines(f.description, 92);
      const evLines = wrapLines(f.evidence, 84);
      const remLines = wrapLines(f.remediation, 88);

      const evH = evLines.length * 10.5 + 14;
      const remH = remLines.length * 11 + 14;
      const needed = 46 + descLines.length * 12 + evH + remH + 14;

      ensureSpace(Math.min(needed, 220));

      const tc = tagColors(f.severity);
      drawText(marginX, y, f.id, "F3", 8.5, INK.black);
      const sevW = Math.max(44, f.severity.length * 5.2 + 12);
      fillRect(marginX + 52, y - 3, sevW, 12, tc.bg);
      strokeRect(marginX + 52, y - 3, sevW, 12, tc.border, 0.5);
      drawText(marginX + 57, y + 0.2, f.severity, "F2", 7, tc.text);

      const deltaText = f.deltaStatus === "NEW" ? "NEW" : f.deltaStatus === "INHERITED" ? "INHERITED" : "BASELINE";
      const dX = marginX + 52 + sevW + 6;
      const dW = deltaText.length * 4.8 + 10;
      fillRect(dX, y - 3, dW, 12, f.deltaStatus === "NEW" ? INK.indigo : INK.ivory);
      strokeRect(dX, y - 3, dW, 12, f.deltaStatus === "NEW" ? INK.indigo : INK.gold, 0.5);
      drawText(dX + 5, y + 0.2, deltaText, "F2", 6.6, f.deltaStatus === "NEW" ? INK.white : INK.gold);

      drawText(dX + dW + 8, y, `CVSS ${f.cvss.toFixed(1)} · ${f.cwe} · ${f.scanner}`.slice(0, 56), "F3", 7.8, INK.sub);
      y -= 15;

      drawText(marginX, y, f.title.slice(0, 86), "F2", 10.5, INK.black);
      y -= 12;
      drawText(marginX, y, `Target: ${f.endpoint}`.slice(0, 96), "F3", 8, INK.indigo);
      y -= 13;

      descLines.forEach((l) => {
        ensureSpace(14);
        drawText(marginX, y, l, "F1", 8.5, INK.body);
        y -= 12;
      });
      y -= 2;

      ensureSpace(evH + 6);
      const evBottom = y - evH;
      fillRect(marginX, evBottom, contentW, evH, INK.tintSoft);
      fillRect(marginX, evBottom, 2, evH, INK.gold);
      drawText(marginX + 10, y - 10, "EVIDENCE OBSERVED", "F3", 6.8, INK.muted);
      evLines.forEach((l, i) => {
        drawText(marginX + 10, y - 21 - i * 10.5, l, "F3", 7.8, INK.body);
      });
      y = evBottom - 6;

      ensureSpace(remH + 8);
      const remBottom = y - remH;
      fillRect(marginX, remBottom, contentW, remH, INK.tintMed);
      fillRect(marginX, remBottom, 2, remH, INK.indigo);
      drawText(marginX + 10, y - 10, "RECOMMENDED FIX", "F3", 6.8, INK.indigo);
      remLines.forEach((l, i) => {
        drawText(marginX + 10, y - 21 - i * 11, l, "F1", 8.2, INK.body);
      });
      y = remBottom - 10;

      drawLine(marginX, y, pageW - marginX, y, INK.ruleLight, 0.6);
      y -= 14;
    }
  }

  // --- Compliance Control Alignment ---
  sectionHeading("Compliance Control Alignment");
  const compCols = ["Control", "Requirement", "Evidence", "Status"];
  const compX = [marginX, marginX + 95, marginX + 275, marginX + 465];
  ensureSpace(30 + doc.complianceRows.length * 18);
  compCols.forEach((c, i) => drawText(compX[i], y - 2, c.toUpperCase(), "F3", 7.5, INK.indigo));
  y -= 8;
  drawLine(marginX, y, pageW - marginX, y, INK.gold, 0.9);
  y -= 13;

  doc.complianceRows.forEach((row) => {
    ensureSpace(20);
    drawText(compX[0], y, row.control.slice(0, 18), "F2", 8.2, INK.body);
    drawText(compX[1], y, row.requirement.slice(0, 34), "F1", 8, INK.body);
    drawText(compX[2], y, row.evidence.slice(0, 36), "F3", 7.8, INK.sub);
    const tc = tagColors(row.status);
    fillRect(compX[3], y - 3, 46, 11, tc.bg);
    strokeRect(compX[3], y - 3, 46, 11, tc.border, 0.5);
    drawText(compX[3] + 6, y, row.status, "F2", 7, tc.text);
    y -= 6;
    drawLine(marginX, y, pageW - marginX, y, INK.ruleLight, 0.5);
    y -= 12;
  });

  // --- Cryptographic Seal Footer ---
  ensureSpace(46);
  y -= 10;
  drawLine(marginX, y, pageW - marginX, y, INK.indigo, 1.25);
  y -= 13;
  drawText(marginX, y, "CRYPTOGRAPHIC SEAL VERIFICATION", "F2", 8.5, INK.indigo);
  y -= 12;
  drawText(marginX, y, `SHA-256 Digest: ${report.sha256Digest}`.slice(0, 94), "F3", 7.5, INK.sub);
  y -= 11;
  drawText(
    marginX,
    y,
    `Kelvin by eOzka · Augmenting Sentient · Generated ${new Date(report.createdAt).toUTCString()}`,
    "F1",
    7.5,
    INK.muted,
  );

  // Page numbers on all pages
  const totalPages = pages.length;
  pages.forEach((cmds, idx) => {
    cmds.push(`${rgbFill(INK.muted)} BT /F3 7.5 Tf 1 0 0 1 ${marginX} 26 Tm (${esc(`Kelvin by eOzka · CONFIDENTIAL · ${report.id}`)}) Tj ET`);
    cmds.push(`${rgbFill(INK.muted)} BT /F3 7.5 Tf 1 0 0 1 ${pageW - marginX - 54} 26 Tm (${esc(`Page ${idx + 1} of ${totalPages}`)}) Tj ET`);
  });

  // Serialize valid PDF 1.4 binary
  const objects: string[] = [];
  const pageObjNums = pages.map((_, i) => 6 + i * 2);

  objects.push(`1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n`);
  objects.push(`2 0 obj\n<< /Type /Pages /Kids [${pageObjNums.map((n) => `${n} 0 R`).join(" ")}] /Count ${totalPages} >>\nendobj\n`);
  objects.push(`3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n`);
  objects.push(`4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n`);
  objects.push(`5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj\n`);

  pages.forEach((cmds, idx) => {
    const stream = cmds.join("\n");
    const pageObj = 6 + idx * 2;
    const contentObj = pageObj + 1;
    objects.push(
      `${pageObj} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${pageW} ${pageH}] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents ${contentObj} 0 R >>\nendobj\n`,
    );
    objects.push(
      `${contentObj} 0 obj\n<< /Length ${stream.length} >>\nstream\n${stream}\nendstream\nendobj\n`,
    );
  });

  let pdf = "%PDF-1.4\n";
  const offsets: number[] = [0];
  for (const obj of objects) {
    offsets.push(pdf.length);
    pdf += obj;
  }
  const xrefOffset = pdf.length;
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (let i = 1; i < offsets.length; i++) {
    pdf += `${offsets[i].toString().padStart(10, "0")} 00000 n \n`;
  }
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF`;

  return new Blob([pdf], { type: "application/pdf" });
}
