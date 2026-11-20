import { resolve } from 'node:path';

/** @type {import('tailwindcss').Config} */
export default {
  content: [resolve(import.meta.dirname, 'apps/web/index.html'), resolve(import.meta.dirname, 'apps/web/src/**/*.{ts,tsx}')],
  theme: {
    extend: {
      colors: {
        ink: { 950: '#070b10', 900: '#0b1118', 850: '#0f1720', 800: '#141e29', 700: '#1d2a37' },
        signal: { cyan: '#22d3ee', teal: '#2dd4bf', amber: '#fbbf24', red: '#fb7185', green: '#34d399' },
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'SFMono-Regular', 'Consolas', 'monospace'],
      },
      boxShadow: { panel: '0 1px 0 rgba(255,255,255,0.04), 0 12px 30px rgba(0,0,0,0.25)' },
      keyframes: {
        scan: { '0%': { transform: 'translateX(-100%)' }, '100%': { transform: 'translateX(300%)' } },
        blink: { '0%,100%': { opacity: '1' }, '50%': { opacity: '0.25' } },
      },
      animation: { scan: 'scan 2.4s linear infinite', blink: 'blink 1.6s ease-in-out infinite' },
    },
  },
  plugins: [],
};
