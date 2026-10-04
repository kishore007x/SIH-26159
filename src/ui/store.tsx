import { createContext, useContext } from 'react';
import type { Analysis } from '../engine/types.ts';

export type View = 'overview' | 'sessions' | 'findings' | 'graph' | 'drift' | 'simulator' | 'reports';

export interface Store {
  a: Analysis;
  view: View;
  go: (v: View) => void;
  session: string | null;
  openSession: (id: string | null) => void;
  finding: string | null;
  openFinding: (id: string | null) => void;
  resolved: Set<string>;
  setResolved: (s: Set<string>) => void;
  reset: () => void;
}

export const StoreCtx = createContext<Store | null>(null);
export const useStore = () => {
  const s = useContext(StoreCtx);
  if (!s) throw new Error('store missing');
  return s;
};
