import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      // Forwards gateway API calls (e.g. /api/users/1, used by the API Console) to
      // APIShield during local development, so the browser sees same-origin
      // requests and no backend CORS configuration is required. Deliberately keyed
      // on "/api/" WITH the trailing slash, not "/api" - Vite's proxy does a plain
      // string-prefix match, and without the slash this would also incorrectly
      // intercept the unrelated /api-console frontend route (a real bug caught by
      // testing a direct navigation to /api-console, not just the sidebar link).
      '/api/': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
})
