import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // Forward /api to the FastAPI backend (src/api/app.py, default :8000) so
    // dev requests stay same-origin. Override the target via VITE_API_BASE_URL
    // if the backend runs elsewhere (see frontend/.env.example).
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
})
