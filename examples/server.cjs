const http = require('http')
const fs   = require('fs')
const path = require('path')

const ROOT = path.join(__dirname, '..')
const PORT = 4242

const MIME = {
  html: 'text/html; charset=utf-8',
  css:  'text/css',
  js:   'application/javascript',
  wasm: 'application/wasm',
  ts:   'application/javascript',
  json: 'application/json',
  map:  'application/json',
}

http.createServer((req, res) => {
  let url = req.url.split('?')[0]
  if (url === '/') url = '/examples/index.html'

  const fp = path.join(ROOT, url)
  try {
    const data = fs.readFileSync(fp)
    const ext  = fp.split('.').pop()
    res.writeHead(200, {
      'Content-Type': MIME[ext] || 'text/plain',
      'Access-Control-Allow-Origin': '*',
    })
    res.end(data)
  } catch (e) {
    res.writeHead(404)
    res.end('Not found: ' + url + '\n' + e.message)
  }
}).listen(PORT, () => {
  console.log('BlockchainWasm examples server running at:')
  console.log('  http://localhost:' + PORT + '/examples/index.html')
})
