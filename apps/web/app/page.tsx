"use client";
import { useState } from "react";

export default function Home() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  async function scan(event: React.FormEvent) {
    event.preventDefault(); setLoading(true); setResult(null);
    try { const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000"}/api/v1/analyze/url`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url }) }); setResult(await response.json()); } catch { setResult({ error: "The analysis service is unavailable." }); } finally { setLoading(false); }
  }
  return <main><nav><strong>GUARDIFY</strong><span>Understand threats before you trust them.</span></nav><section className="hero"><p className="eyebrow">EVIDENCE-FIRST SECURITY ANALYSIS</p><h1>Check before you trust.</h1><p>Analyze URLs with transparent threat intelligence. Unknown evidence stays unknown.</p><form onSubmit={scan}><input aria-label="URL to analyze" required type="url" placeholder="https://example.com" value={url} onChange={e => setUrl(e.target.value)} /><button disabled={loading}>{loading ? "ANALYZING…" : "ANALYZE URL"}</button></form>{result && <article><h2>{result.data?.verdict ?? "ERROR"}</h2><p>{result.data?.citizen?.summary ?? result.error}</p>{result.data && <small>Scan {result.data.scan_id} · Evidence: {result.data.analyst.evidence}</small>}</article>}</section><footer>Guardify provides automated analysis using available evidence. No automated analysis guarantees complete safety.</footer></main>
}
