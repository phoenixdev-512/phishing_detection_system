import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
    plugins: [react()],
    server: {
        port: 5173,
        proxy: {
            '/api': {
                target: 'http://localhost:8000',
                changeOrigin: true,
                secure: false,
            },
        },
    },
    build: {
        outDir: 'dist',
        sourcemap: false,
        rollupOptions: {
            output: {
                manualChunks(id) {
                    if (id.includes('node_modules')) {
                        if (id.includes('react') || id.includes('react-dom')) {
                            return 'react-vendor';
                        }
                        if (id.includes('react-force-graph-2d')) {
                            return 'graph-vendor';
                        }
                        if (id.includes('recharts')) {
                            return 'chart-vendor';
                        }
                        return 'vendor';
                    }
                }
            },
        },
    },
    define: {
        'process.env': {},
    },
});
