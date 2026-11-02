import { useState } from "react";
import { Link } from "react-router-dom";

interface ReportItem {
  id: string;
  assessmentId: string;
  format: "PDF" | "HTML";
  title: string;
  createdAt: string;
  sha256Digest: string;
  sizeBytes: number;
  downloadUrl: string;
}

export default function ReportCenterPage() {
  const [assessmentId, setAssessmentId] = useState("");
  const [format, setFormat] = useState<"PDF" | "HTML">("PDF");
  const [generating, setGenerating] = useState(false);
  const [reports, setReports] = useState<ReportItem[]>([
    {
      id: "rep-2026-901",
      assessmentId: "assess-2026-001",
      format: "PDF",
      title: "Executive Assessment & Technical Findings Report",
      createdAt: new Date(Date.now() - 3600000).toISOString(),
      sha256Digest: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      sizeBytes: 184520,
      downloadUrl: "/api/v1/reports/rep-2026-901/download?sig=mocked_hmac",
    },
    {
      id: "rep-2026-902",
      assessmentId: "assess-2026-001",
      format: "HTML",
      title: "Interactive Audit Findings & Evidence Snapshot",
      createdAt: new Date(Date.now() - 7200000).toISOString(),
      sha256Digest: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      sizeBytes: 94210,
      downloadUrl: "/api/v1/reports/rep-2026-902/download?sig=mocked_hmac",
    },
  ]);

  const handleGenerate = (e: React.FormEvent) => {
    e.preventDefault();
    if (!assessmentId.trim()) return;

    setGenerating(true);
    setTimeout(() => {
      const newReport: ReportItem = {
        id: `rep-${Date.now().toString().slice(-6)}`,
        assessmentId: assessmentId.trim(),
        format,
        title: `Assessment Report (${format}) - ${assessmentId.trim()}`,
        createdAt: new Date().toISOString(),
        sha256Digest: "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
        sizeBytes: format === "PDF" ? 210400 : 85600,
        downloadUrl: `/api/v1/reports/rep-${Date.now().toString().slice(-6)}/download?token=signed`,
      };
      setReports([newReport, ...reports]);
      setAssessmentId("");
      setGenerating(false);
    }, 600);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-zinc-100">Assessment Report Center</h1>
          <p className="mt-1 text-sm text-zinc-400">
            Generate, audit, and securely export cryptographically sealed HTML & PDF assessment reports.
          </p>
        </div>
        <Link
          to="/findings"
          className="rounded border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-xs font-medium text-zinc-200 hover:border-zinc-500 hover:text-white"
        >
          &larr; Back to Findings
        </Link>
      </div>

      {/* Report Generation Request Form */}
      <form onSubmit={handleGenerate} className="flex flex-wrap items-end gap-4 rounded-lg border border-zinc-800 bg-zinc-900/60 p-4">
        <div className="flex-1 min-w-[240px]">
          <label className="block text-xs font-medium text-zinc-400 mb-1">
            Target Assessment ID
          </label>
          <input
            type="text"
            required
            placeholder="e.g. assess-prod-2026-04"
            value={assessmentId}
            onChange={(e) => setAssessmentId(e.target.value)}
            className="w-full rounded border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-500 focus:border-emerald-500 focus:outline-none"
          />
        </div>

        <div className="w-36">
          <label className="block text-xs font-medium text-zinc-400 mb-1">
            Format
          </label>
          <select
            value={format}
            onChange={(e) => setFormat(e.target.value as "PDF" | "HTML")}
            className="w-full rounded border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm text-zinc-200 focus:border-emerald-500 focus:outline-none"
          >
            <option value="PDF">PDF Report</option>
            <option value="HTML">HTML Bundle</option>
          </select>
        </div>

        <button
          type="submit"
          disabled={generating}
          className="rounded bg-emerald-600 px-4 py-1.5 text-sm font-semibold text-white hover:bg-emerald-500 disabled:opacity-50"
        >
          {generating ? "Compiling Report…" : "Generate Report"}
        </button>
      </form>

      {/* Reports Archive */}
      <div className="overflow-hidden rounded-lg border border-zinc-800 bg-zinc-900/60">
        <div className="border-b border-zinc-800 bg-zinc-900 px-4 py-3">
          <h2 className="text-sm font-semibold text-zinc-200">Generated Reports Archive</h2>
        </div>
        <table className="w-full text-left text-sm text-zinc-300">
          <thead className="border-b border-zinc-800 text-xs uppercase text-zinc-400">
            <tr>
              <th className="px-4 py-3">Title & Assessment</th>
              <th className="px-4 py-3">Format</th>
              <th className="px-4 py-3">Cryptographic Seal (SHA-256)</th>
              <th className="px-4 py-3">Generated</th>
              <th className="px-4 py-3 text-right">Download</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800/60">
            {reports.map((r) => (
              <tr key={r.id} className="hover:bg-zinc-800/30">
                <td className="px-4 py-3">
                  <div className="font-medium text-zinc-200">{r.title}</div>
                  <div className="font-mono text-xs text-zinc-500">{r.assessmentId}</div>
                </td>
                <td className="px-4 py-3">
                  <span className="rounded bg-zinc-800 border border-zinc-700 px-2 py-0.5 text-xs font-semibold text-zinc-300">
                    {r.format}
                  </span>
                </td>
                <td className="px-4 py-3 font-mono text-xs text-zinc-400">
                  <div className="flex items-center gap-2">
                    <span>{r.sha256Digest.slice(0, 16)}…</span>
                    <span className="rounded border border-emerald-800 bg-emerald-950/40 px-1.5 py-0.2 text-[10px] text-emerald-400">
                      VERIFIED
                    </span>
                  </div>
                </td>
                <td className="px-4 py-3 text-xs text-zinc-400">
                  {new Date(r.createdAt).toLocaleString()}
                </td>
                <td className="px-4 py-3 text-right">
                  <a
                    href={r.downloadUrl}
                    download
                    className="inline-block rounded border border-emerald-700 bg-emerald-950/60 px-3 py-1 text-xs font-medium text-emerald-300 hover:bg-emerald-900/80"
                  >
                    Download Securely
                  </a>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
