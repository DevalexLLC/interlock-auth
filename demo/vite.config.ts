import { readFileSync } from "node:fs";
import { fileURLToPath, URL } from "node:url";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  root: fileURLToPath(new URL(".", import.meta.url)),
  plugins: [react()],
  resolve: {
    alias: {
      "@devalexllc/interlock-auth/react": fileURLToPath(
        new URL("../src/react/index.ts", import.meta.url),
      ),
    },
  },
  server: {
    host: true,
    port: 5173,
    strictPort: true,
    https: {
      cert: readFileSync(
        process.env.DEMO_TLS_CERT ?? "../infralytics-stack/certs/dev.home.arpa.crt",
      ),
      key: readFileSync(process.env.DEMO_TLS_KEY ?? "../infralytics-stack/certs/dev.home.arpa.key"),
    },
    allowedHosts: ["demo.dev.home.arpa"],
  },
});
