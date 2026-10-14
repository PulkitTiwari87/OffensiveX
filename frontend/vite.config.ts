/// <reference types="vitest/config" />
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The backend serves the built app at /dashboard (same origin as /api, so the
// HttpOnly SameSite=Strict session cookie works with no CORS). `npm run dev`
// proxies /api to a local backend instead.
export default defineConfig({
  base: "/dashboard/",
  plugins: [react()],
  server: { proxy: { "/api": "http://127.0.0.1:8000" } },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test-setup.ts"],
  },
});
