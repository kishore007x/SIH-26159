// Components adapted from React Bits (reactbits.dev — MIT + Commons Clause), tuned to a restrained, professional palette:
// SpotlightCard, DecryptedText, SplitText, CountUp, RotatingText, DotGrid, LogoLoop, AnimatedContent, AnimatedList.
import { AnimatePresence, motion, useInView, useMotionValue, useSpring } from 'motion/react';
import { useEffect, useRef, useState, type CSSProperties, type ReactNode } from 'react';

export const cx = (...c: (string | false | undefined | null)[]) => c.filter(Boolean).join(' ');

/** React Bits SpotlightCard — a soft neutral light follows the cursor. */
export function SpotlightCard({ children, className = '', spotlight = 'rgba(255,255,255,0.05)', onClick, as = 'div' }: { children: ReactNode; className?: string; spotlight?: string; onClick?: () => void; as?: 'div' | 'button' }) {
  const ref = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState({ x: 0, y: 0 });
  const [op, setOp] = useState(0);
  const Comp = as as 'div';
  return (
    <Comp ref={ref} onClick={onClick}
      onMouseMove={(e) => { const r = ref.current!.getBoundingClientRect(); setPos({ x: e.clientX - r.left, y: e.clientY - r.top }); }}
      onMouseEnter={() => setOp(1)} onMouseLeave={() => setOp(0)}
      className={cx('surface relative overflow-hidden rounded-xl text-left transition-colors duration-200', className)}>
      <div className="pointer-events-none absolute inset-0 transition-opacity duration-500" style={{ opacity: op, background: `radial-gradient(500px circle at ${pos.x}px ${pos.y}px, ${spotlight}, transparent 60%)` }} />
      {children}
    </Comp>
  );
}

/** React Bits DecryptedText — characters resolve from cipher noise, revealed in order. */
export function DecryptedText({ text, speed = 35, className = '', encryptedClassName = 'text-zinc-600', delay = 0 }: { text: string; speed?: number; className?: string; encryptedClassName?: string; delay?: number }) {
  const ref = useRef<HTMLSpanElement>(null);
  const inView = useInView(ref, { once: true });
  const [revealed, setRevealed] = useState(0);
  const [tick, setTick] = useState(0);
  const chars = '0123456789abcdef!#$%&*+=?';
  useEffect(() => {
    if (!inView) return;
    let i = 0;
    let id: ReturnType<typeof setInterval>;
    const start = setTimeout(() => {
      id = setInterval(() => { i += 0.5; setRevealed(Math.floor(i)); setTick((t) => t + 1); if (i >= text.length) clearInterval(id); }, speed);
    }, delay * 1000);
    return () => { clearTimeout(start); clearInterval(id); };
  }, [inView, text, speed, delay]);
  void tick;
  return (
    <span ref={ref} className={className} aria-label={text}>
      {text.split('').map((c, i) => (
        <span key={i} aria-hidden className={i >= revealed && c !== ' ' ? encryptedClassName : undefined}>
          {i < revealed || c === ' ' ? c : chars[Math.floor(Math.random() * chars.length)]}
        </span>
      ))}
    </span>
  );
}

/** React Bits SplitText — words rise in with a stagger. */
export function SplitText({ text, className = '', delay = 0, stagger = 0.045 }: { text: string; className?: string; delay?: number; stagger?: number }) {
  return (
    <span className={className} aria-label={text}>
      {text.split(' ').map((w, i) => (
        <span key={i} aria-hidden className="inline-block overflow-hidden pb-[0.08em] align-bottom">
          <motion.span className="inline-block" initial={{ y: '105%' }} animate={{ y: 0 }} transition={{ duration: 0.7, delay: delay + i * stagger, ease: [0.16, 1, 0.3, 1] }}>
            {w}&nbsp;
          </motion.span>
        </span>
      ))}
    </span>
  );
}

/** React Bits CountUp — spring-driven number. */
export function CountUp({ to, decimals = 0, className = '', style, duration = 1.4 }: { to: number; decimals?: number; className?: string; style?: CSSProperties; duration?: number }) {
  const ref = useRef<HTMLSpanElement>(null);
  const mv = useMotionValue(0);
  const spring = useSpring(mv, { damping: 40, stiffness: 100 / duration });
  const inView = useInView(ref, { once: true });
  useEffect(() => { if (inView) mv.set(to); }, [inView, to, mv]);
  useEffect(() => spring.on('change', (v) => {
    if (ref.current) ref.current.textContent = v.toLocaleString(undefined, { minimumFractionDigits: decimals, maximumFractionDigits: decimals });
  }), [spring, decimals]);
  return <span ref={ref} className={cx('tabular-nums', className)} style={style}>0</span>;
}

/** React Bits RotatingText — cycles through words. */
export function RotatingText({ words, interval = 2200, className = '' }: { words: string[]; interval?: number; className?: string }) {
  const [i, setI] = useState(0);
  useEffect(() => { const t = setInterval(() => setI((x) => (x + 1) % words.length), interval); return () => clearInterval(t); }, [words.length, interval]);
  return (
    <span className={cx('relative inline-flex overflow-hidden align-bottom', className)}>
      <AnimatePresence mode="popLayout" initial={false}>
        <motion.span key={words[i]} initial={{ y: '100%', opacity: 0 }} animate={{ y: 0, opacity: 1 }} exit={{ y: '-100%', opacity: 0 }} transition={{ type: 'spring', damping: 30, stiffness: 400 }}>
          {words[i]}
        </motion.span>
      </AnimatePresence>
    </span>
  );
}

/** React Bits DotGrid — a calm dot field that brightens near the cursor. */
export function DotGrid({ className = '', gap = 26, size = 1.6, base = [63, 63, 70], active = [161, 161, 170], radius = 140 }: { className?: string; gap?: number; size?: number; base?: number[]; active?: number[]; radius?: number }) {
  const canvas = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const c = canvas.current!;
    const ctx = c.getContext('2d')!;
    let mx = -9999, my = -9999, raf = 0;
    const resize = () => { const r = c.parentElement!.getBoundingClientRect(); c.width = r.width * devicePixelRatio; c.height = r.height * devicePixelRatio; c.style.width = `${r.width}px`; c.style.height = `${r.height}px`; };
    const draw = () => {
      ctx.clearRect(0, 0, c.width, c.height);
      const g = gap * devicePixelRatio, rr = radius * devicePixelRatio;
      for (let y = g / 2; y < c.height; y += g) for (let x = g / 2; x < c.width; x += g) {
        const d = Math.hypot(x - mx, y - my);
        const t = Math.max(0, 1 - d / rr);
        const col = base.map((b, k) => Math.round(b + (active[k] - b) * t));
        ctx.fillStyle = `rgb(${col[0]},${col[1]},${col[2]})`;
        ctx.beginPath(); ctx.arc(x, y, size * devicePixelRatio * (1 + t * 0.6), 0, Math.PI * 2); ctx.fill();
      }
      raf = requestAnimationFrame(draw);
    };
    const move = (e: PointerEvent) => { const r = c.getBoundingClientRect(); mx = (e.clientX - r.left) * devicePixelRatio; my = (e.clientY - r.top) * devicePixelRatio; };
    resize(); draw();
    window.addEventListener('resize', resize);
    window.addEventListener('pointermove', move);
    return () => { cancelAnimationFrame(raf); window.removeEventListener('resize', resize); window.removeEventListener('pointermove', move); };
  }, [gap, size, radius, base, active]);
  return <canvas ref={canvas} className={cx('pointer-events-none absolute inset-0', className)} />;
}

/** React Bits LogoLoop — infinite horizontal loop with edge fade. */
export function LogoLoop({ items, className = '' }: { items: ReactNode[]; className?: string }) {
  return (
    <div className={cx('overflow-hidden [mask-image:linear-gradient(to_right,transparent,black_10%,black_90%,transparent)]', className)}>
      <div className="animate-marquee flex w-max gap-10 hover:[animation-play-state:paused]">
        {[...items, ...items].map((it, i) => <div key={i} className="shrink-0">{it}</div>)}
      </div>
    </div>
  );
}

/** React Bits AnimatedContent — fade/slide in when scrolled into view. */
export function AnimatedContent({ children, delay = 0, distance = 24, className = '' }: { children: ReactNode; delay?: number; distance?: number; className?: string }) {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: '-60px' });
  return (
    <motion.div ref={ref} className={className} initial={{ opacity: 0, y: distance }} animate={inView ? { opacity: 1, y: 0 } : undefined}
      transition={{ duration: 0.7, delay, ease: [0.16, 1, 0.3, 1] }}>
      {children}
    </motion.div>
  );
}

/** React Bits AnimatedList item — scales in as it enters the viewport. */
export function AnimatedItem({ children, delay = 0, className = '' }: { children: ReactNode; delay?: number; className?: string }) {
  const ref = useRef(null);
  const inView = useInView(ref, { amount: 0.3, once: true });
  return (
    <motion.div ref={ref} className={className} initial={{ scale: 0.96, opacity: 0 }} animate={inView ? { scale: 1, opacity: 1 } : undefined} transition={{ duration: 0.25, delay }}>
      {children}
    </motion.div>
  );
}

export function Button({ children, onClick, variant = 'primary', className = '', disabled }: { children: ReactNode; onClick?: () => void; variant?: 'primary' | 'secondary' | 'ghost'; className?: string; disabled?: boolean }) {
  const v = {
    primary: 'bg-zinc-50 text-zinc-950 hover:bg-zinc-200 border border-transparent',
    secondary: 'bg-ink-800 text-zinc-100 border border-white/10 hover:bg-ink-700 hover:border-white/15',
    ghost: 'text-zinc-300 hover:bg-white/[0.05] border border-transparent',
  }[variant];
  return (
    <button onClick={onClick} disabled={disabled} className={cx('inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2 text-[15px] font-bold transition-colors disabled:opacity-50', v, className)}>
      {children}
    </button>
  );
}
