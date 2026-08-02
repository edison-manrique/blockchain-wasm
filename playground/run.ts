import { serve } from "bun";
import { join } from "path";

const PORT = Number(process.env.PORT) || 3000;
const PROJECT_ROOT = join(import.meta.dir, "..");

console.log(`\n🚀 [BlockchainWasm Playground Server]`);
console.log(`⚡ Powered by Bun v${Bun.version}`);
console.log(`🌐 Dashboard running at: http://localhost:${PORT}/playground/index.html`);
console.log(`📁 Project Root: ${PROJECT_ROOT}\n`);

serve({
  port: PORT,
  fetch(req) {
    const url = new URL(req.url);
    let pathname = url.pathname;

    // Redirección por defecto
    if (pathname === "/" || pathname === "/playground" || pathname === "/playground/") {
      pathname = "/playground/index.html";
    }

    // Ruta física completa
    const targetFile = join(PROJECT_ROOT, pathname);
    const file = Bun.file(targetFile);

    if (file.size > 0) {
      // Determinación de MIME Type para .wasm, .js, .css, .html
      const headers: Record<string, string> = {
        "Access-Control-Allow-Origin": "*",
        "Cache-Control": "no-cache"
      };

      if (pathname.endsWith(".wasm")) {
        headers["Content-Type"] = "application/wasm";
      } else if (pathname.endsWith(".js")) {
        headers["Content-Type"] = "text/javascript; charset=utf-8";
      } else if (pathname.endsWith(".css")) {
        headers["Content-Type"] = "text/css; charset=utf-8";
      } else if (pathname.endsWith(".html")) {
        headers["Content-Type"] = "text/html; charset=utf-8";
      }

      return new Response(file, { headers });
    }

    return new Response(`404 Not Found: ${pathname}`, {
      status: 404,
      headers: { "Content-Type": "text/plain" }
    });
  }
});
