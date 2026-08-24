import { serve } from "bun"
import { join } from "path"
import { createServer } from "net"

const BASE_PORT = Number(process.env.PORT) || 3000
const PROJECT_ROOT = join(import.meta.dir, "..")

/** Returns true if the port is available */
function isPortFree(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const server = createServer()
    server.once("error", () => resolve(false))
    server.once("listening", () => {
      server.close()
      resolve(true)
    })
    server.listen(port, "127.0.0.1")
  })
}

/** Finds the first free port starting from `from` */
async function findFreePort(from: number, max = 20): Promise<number> {
  for (let i = 0; i < max; i++) {
    if (await isPortFree(from + i)) return from + i
  }
  throw new Error(`No free port found in range ${from}–${from + max - 1}`)
}

const PORT = await findFreePort(BASE_PORT)
if (PORT !== BASE_PORT) {
  console.warn(`⚠️  Port ${BASE_PORT} is in use — using ${PORT} instead`)
}

console.log(`\n🚀 [BlockchainWasm Playground Server]`)
console.log(`⚡ Powered by Bun v${Bun.version}`)
console.log(`🌐 Dashboard:  http://localhost:${PORT}/playground/index.html`)
console.log(`🔬 Anvil Lab:  http://localhost:${PORT}/playground/anvil.html`)
console.log(`📁 Root:       ${PROJECT_ROOT}\n`)

const MIME: Record<string, string> = {
  ".wasm": "application/wasm",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".ico": "image/x-icon",
  ".png": "image/png",
  ".svg": "image/svg+xml"
}

serve({
  port: PORT,
  fetch(req) {
    const url = new URL(req.url)
    let pathname = url.pathname

    if (pathname === "/" || pathname === "/playground" || pathname === "/playground/") {
      pathname = "/playground/index.html"
    }

    const targetFile = join(PROJECT_ROOT, pathname)
    const file = Bun.file(targetFile)

    if (file.size > 0) {
      const ext = pathname.slice(pathname.lastIndexOf("."))
      const headers: Record<string, string> = {
        "Access-Control-Allow-Origin": "*",
        "Cache-Control": "no-cache"
      }
      if (MIME[ext]) headers["Content-Type"] = MIME[ext]
      return new Response(file, { headers })
    }

    return new Response(`404 Not Found: ${pathname}`, {
      status: 404,
      headers: { "Content-Type": "text/plain" }
    })
  }
})
