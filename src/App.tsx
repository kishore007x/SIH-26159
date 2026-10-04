import { useCallback, useMemo, useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import { analyze, type StageId } from './engine/analyze.ts';
import type { Analysis } from './engine/types.ts';
import { Landing } from './ui/Landing.tsx';
import { PipelineOverlay } from './ui/Pipeline.tsx';
import { Shell } from './ui/Shell.tsx';
import { StoreCtx, type Store, type View } from './ui/store.tsx';

export interface RunState { file: string; size: number; done: Partial<Record<StageId, string>>; active?: StageId; error?: string }

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

export default function App() {
  const [a, setA] = useState<Analysis | null>(null);
  const [run, setRun] = useState<RunState | null>(null);
  const [view, setView] = useState<View>('overview');
  const [session, setSession] = useState<string | null>(null);
  const [finding, setFinding] = useState<string | null>(null);
  const [resolved, setResolved] = useState<Set<string>>(new Set());

  const start = useCallback(async (buf: ArrayBuffer, name: string) => {
    setRun({ file: name, size: buf.byteLength, done: {}, active: 'parse' });
    await wait(350);
    try {
      const order: StageId[] = ['parse', 'tcp', 'email', 'tls', 'rules', 'drift', 'ml', 'posture'];
      const result = await analyze(buf, name, async (stage, metric) => {
        const next = order[order.indexOf(stage) + 1];
        setRun((r) => r && { ...r, done: { ...r.done, [stage]: metric }, active: next });
        await wait(260); // pace the visual pipeline so each stage is legible
      });
      await wait(650);
      setA(result); setView('overview'); setSession(null); setFinding(null); setResolved(new Set());
      setRun(null);
    } catch (e) {
      setRun((r) => r && { ...r, error: (e as Error).message });
    }
  }, []);

  const store: Store | null = useMemo(() => a && ({
    a, view, go: (v) => { setView(v); window.scrollTo({ top: 0 }); }, session,
    openSession: (id) => { setSession(id); if (id) setView('sessions'); },
    finding, openFinding: (id) => { setFinding(id); if (id) setView('findings'); },
    resolved, setResolved, reset: () => { setA(null); },
  }), [a, view, session, finding, resolved]);

  return (
    <>
      <AnimatePresence mode="wait">
        {store ? (
          <motion.div key="app" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="h-full">
            <StoreCtx.Provider value={store}><Shell /></StoreCtx.Provider>
          </motion.div>
        ) : (
          <motion.div key="landing" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0, scale: 0.98 }}>
            <Landing onFile={start} />
          </motion.div>
        )}
      </AnimatePresence>
      <AnimatePresence>{run && <PipelineOverlay run={run} onClose={() => setRun(null)} />}</AnimatePresence>
    </>
  );
}
