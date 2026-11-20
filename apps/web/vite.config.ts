import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'node:path';

export default defineConfig({
  root: resolve(import.meta.dirname),
  plugins: [react()],
  resolve: {
    alias: {
      '@': resolve(import.meta.dirname, 'src'),
      '@sentinel/shared': resolve(import.meta.dirname, '../../packages/shared/src/index.ts'),
    },
  },
  server: { port: 5173, host: '127.0.0.1' },
  build: {
    outDir: resolve(import.meta.dirname, 'dist'),
    emptyOutDir: true,
    chunkSizeWarningLimit: 700,
    rollupOptions: {
      output: {
        manualChunks: {
          charts: ['recharts'],
          graph: ['@xyflow/react'],
        },
      },
    },
  },
});
