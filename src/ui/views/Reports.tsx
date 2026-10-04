import { motion } from 'motion/react';
import { Braces, Download, FileText, Globe, Printer } from 'lucide-react';
import { useMemo } from 'react';
import { useStore } from '../store.tsx';
import { PageTitle } from '../Shell.tsx';
import { Card } from '../common.tsx';
import { download, reportHtml, reportJson } from '../report.ts';

export function Reports() {
  const { a } = useStore();
  const base = a.fileName.replace(/\.(pcapng|pcap|cap)$/i, '');
  const json = useMemo(() => JSON.stringify(reportJson(a), null, 2), [a]);
  const html = useMemo(() => reportHtml(a), [a]);

  const printPdf = () => {
    const w = window.open('', '_blank');
    if (!w) return;
    w.document.write(html);
    w.document.close();
    w.onload = () => w.print();
    setTimeout(() => w.print(), 600);
  };

  const outputs = [
    { icon: Braces, t: 'JSON', d: 'Machine-readable forensic output: sessions, TLS parameters, certificates, AI scores, evidence frames — ready for SIEM / SOAR ingestion.', size: json.length, act: () => download(`${base}.securemailscope.json`, json, 'application/json'), cta: 'Download JSON', c: '#5b8def' },
    { icon: Globe, t: 'HTML', d: 'Self-contained, shareable investigation report with posture, prioritised findings, causal mapping and session inventory.', size: html.length, act: () => download(`${base}.securemailscope.html`, html, 'text/html'), cta: 'Download HTML', c: '#9b8cf0' },
    { icon: FileText, t: 'PDF', d: 'Formal investigation artefact. Opens the print-optimised report — choose “Save as PDF”.', size: 0, act: printPdf, cta: 'Generate PDF', c: '#d99ab8' },
  ];

  return (
    <>
      <PageTitle kicker="Forensic outputs" title="Reports & Export" sub="All outputs are generated locally from the analysed evidence. Cleartext credentials are masked." />
      <div className="grid gap-4 lg:grid-cols-3">
        {outputs.map((o, i) => (
          <Card key={o.t} delay={i * 0.06} className="overflow-hidden">
            <div className="relative">
              <div className="grid h-12 w-12 place-items-center rounded-2xl" style={{ background: `${o.c}1a`, color: o.c }}><o.icon size={24} /></div>
              <div className="mt-4 text-xl font-bold text-white">{o.t} report</div>
              <p className="mt-1.5 min-h-[60px] text-sm text-zinc-400">{o.d}</p>
              {o.size > 0 && <div className="mt-2 font-mono text-[11px] text-zinc-500">{(o.size / 1024).toFixed(1)} KB</div>}
              <button onClick={o.act} className="mt-4 inline-flex items-center gap-2 rounded-xl px-4 py-2 text-sm font-semibold text-ink-950 transition hover:brightness-110" style={{ background: o.c }}>
                {o.t === 'PDF' ? <Printer size={16} /> : <Download size={16} />}{o.cta}
              </button>
            </div>
          </Card>
        ))}
      </div>
      <div className="mt-4 grid gap-4 xl:grid-cols-2">
        <Card title="HTML report preview" icon={<Globe size={15} />}>
          <motion.iframe initial={{ opacity: 0 }} animate={{ opacity: 1 }} srcDoc={html} title="report" className="h-[560px] w-full rounded-xl bg-white" />
        </Card>
        <Card title="JSON preview" icon={<Braces size={15} />}>
          <pre className="h-[560px] overflow-auto rounded-xl bg-black/50 p-4 font-mono text-[11.5px] leading-5 text-zinc-100 ring-1 ring-white/5">{json.slice(0, 9000)}{json.length > 9000 ? '\n…' : ''}</pre>
        </Card>
      </div>
    </>
  );
}
