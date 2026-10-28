// node server.js  ->  http://localhost:8080   (Node 18+, no npm install needed)
// 1) serves gods-eye.html  2) proxies ADS-B with CORS + cache + rate-limit queue
// 3) serves Cesium from the same origin (downloaded once from jsdelivr into .cache/)
const http=require('http'),fs=require('fs'),path=require('path');
const PORT=process.env.PORT||8080,ROOT=__dirname,CC=path.join(ROOT,'.cache','cesium');
const CDN='https://cdn.jsdelivr.net/npm/cesium@1.120.0/Build/Cesium/';
const MIME={'.html':'text/html','.js':'text/javascript','.css':'text/css','.json':'application/json','.png':'image/png','.jpg':'image/jpeg','.svg':'image/svg+xml','.wasm':'application/wasm','.woff':'font/woff','.woff2':'font/woff2','.xml':'application/xml','.gltf':'model/gltf+json','.glb':'model/gltf-binary'};
const UP=['https://api.adsb.lol/v2','https://api.airplanes.live/v2'];
const cache=new Map(),sleep=ms=>new Promise(r=>setTimeout(r,ms));let chain=Promise.resolve();
function upstream(p){const hit=cache.get(p);if(hit&&Date.now()-hit.t<30000)return Promise.resolve(hit.b);
 const job=chain.then(async()=>{const h=cache.get(p);if(h&&Date.now()-h.t<30000)return h.b;
  for(const base of UP){try{const r=await fetch(base+p,{headers:{'user-agent':'eye-globe/0.2'}});if(r.ok){const b=await r.text();cache.set(p,{t:Date.now(),b});await sleep(700);return b}}catch(e){}await sleep(300)}
  throw new Error('all ADS-B upstreams failed or rate-limited')});
 chain=job.catch(()=>{});return job}
http.createServer(async(req,res)=>{const u=new URL(req.url,'http://x');
 try{
  if(u.pathname==='/api/adsb'){const p=u.searchParams.get('p')||'';
   if(!/^\/(mil|point\/-?[\d.]+\/-?[\d.]+\/\d+)$/.test(p)){res.writeHead(400);return res.end('bad path')}
   const b=await upstream(p);res.writeHead(200,{'content-type':'application/json'});return res.end(b)}
  if(u.pathname.startsWith('/cesium/')){const rel=path.normalize(decodeURIComponent(u.pathname.slice(8)));const f=path.join(CC,rel);
   if(!f.startsWith(CC)){res.writeHead(403);return res.end()}
   if(!fs.existsSync(f)){const r=await fetch(CDN+rel.split(path.sep).join('/'));if(!r.ok){res.writeHead(404);return res.end()}
    fs.mkdirSync(path.dirname(f),{recursive:true});fs.writeFileSync(f,Buffer.from(await r.arrayBuffer()))}
   res.writeHead(200,{'content-type':MIME[path.extname(f)]||'application/octet-stream'});return fs.createReadStream(f).pipe(res)}
  if(u.pathname==='/'||u.pathname==='/gods-eye.html'){res.writeHead(200,{'content-type':'text/html'});return fs.createReadStream(path.join(ROOT,'gods-eye.html')).pipe(res)}
  res.writeHead(404);res.end()}
 catch(e){res.writeHead(502);res.end(String(e.message))}}).listen(PORT,()=>console.log('Eye running at http://localhost:'+PORT));
