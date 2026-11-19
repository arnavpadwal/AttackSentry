import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import path from 'path';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    host: true,
    port: 5173,
    proxy: {
      '/api': 'http://localhost:8000',
      '/auth': 'http://localhost:8000',
      '/health': 'http://localhost:8000',
      '/ws': {
        target: 'ws://localhost:8000',
        ws: true,
      },
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test-setup.ts'],
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    chunkSizeWarningLimit: 1500,
    rollupOptions: {
      output: {
        manualChunks: (id: string) => {
          if (id.includes('react-dom') || id.includes('react-router')) return 'react-vendor';
          if (id.includes('react/')) return 'react-vendor';
          if (id.includes('@tanstack') || id.includes('axios') || id.includes('zustand')) return 'query-vendor';
          if (id.includes('recharts') || id.includes('uplot')) return 'chart-vendor';
          if (id.includes('react-markdown') || id.includes('remark')) return 'markdown-vendor';
          if (id.includes('lucide-react')) return 'icon-vendor';
        },
      },
    },
  },
});
