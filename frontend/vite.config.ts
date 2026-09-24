import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      // Forwards future dashboard API calls to the APIShield gateway during local
      // development, so the browser sees same-origin requests and no backend CORS
      // configuration is required. Inert today - no /api/dashboard/* endpoints exist
      // yet on the backend; this just prepares the wiring for when they do.
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
})
