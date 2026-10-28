// node server.js  ->  http://localhost:8080   (Node 18+, no npm install needed)
const http=require('http'),fs=require('fs'),path=require('path');
const PORT=process.env.PORT||8080,ROOT=__dirname,CC=path.join(ROOT,'.cache','cesium');
const CDN='https://cdn.jsdelivr.net/npm/cesium@1.120.0/Build/Cesium/';
const MIME={'.html':'text/html','.js':'text/javascript','.css':'text/css','.json':'application/json','.png':'image/png','.jpg':'image/jpeg','.svg':'image/svg+xml','.wasm':'application/wasm','.woff':'font/woff','.woff2':'font/woff2','.xml':'application/xml','.gltf':'model/gltf+json','.glb':'model/gltf-binary'};
const UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

/* ---- provider health tracking ---- */
const PH={};
function phOk(n){PH[n]={fails:0,until:0}}
function phFail(n){const h=PH[n]||{fails:0,until:0};h.fails++;if(h.fails>=3)h.until=Date.now()+Math.min(5*60000,60000*h.fails);PH[n]=h;console.log('provider',n,'fails',h.fails,'cooldown until',new Date(h.until).toISOString())}
function phBlocked(n){const h=PH[n];return h&&Date.now()<h.until}

/* ---- ADS-B path transform for adsb.fi v3 ---- */
function toAdsbFi(pointPath){
  // /point/{lat}/{lon}/{dist}  ->  /v3/lat/{lat}/lon/{lon}/dist/{dist}
  const m=pointPath.match(/^\/point\/(-?[\d.]+)\/(-?[\d.]+)\/(\d+)$/);
  if(!m)return null;
  return `/v3/lat/${m[1]}/lon/${m[2]}/dist/${m[3]}`;
}

/* ---- concurrency gate ---- */
let act=0;const waiters=[];
function gate(){return new Promise(res=>{waiters.push(res);drain()})}
function drain(){while(act<6&&waiters.length){const next=waiters.shift();act++;next(()=>{act--;drain()})}}

function mergeAircraftRows(rows){
 const byHex=new Map();
 for(const a of rows){
  if(!a||!(a.hex||a.icao))continue;
  const id=String(a.hex||a.icao).toLowerCase(),old=byHex.get(id);
  if(!old){byHex.set(id,{...a});continue}
  const freshness=x=>Number.isFinite(+x.seen_pos)?+x.seen_pos:Number.isFinite(+x.seen)?+x.seen:1e9;
  const quality=x=>Object.values(x).filter(v=>v!==null&&v!==undefined&&v!=='').length;
  const best=freshness(a)<freshness(old)||(freshness(a)===freshness(old)&&quality(a)>quality(old))?a:old;
  const other=best===a?old:a,merged={...other,...best};
  for(const [k,v] of Object.entries(other))if((merged[k]===null||merged[k]===undefined||merged[k]==='')&&v!==null&&v!==undefined&&v!=='')merged[k]=v;
  byHex.set(id,merged);
 }
 return [...byHex.values()];
}

const cache=new Map();
async function upstream(p){
  const hit=cache.get(p),freshMs=45000;
  if(hit&&hit.b&&Date.now()-hit.t<freshMs)return hit.b;
  if(hit&&hit.flight)return hit.b||hit.flight;

  // /mil only supported by adsb.lol and airplanes.live; adsb.fi has no /mil
  const providers = p==='/mil'
    ?[
       {name:'adsb.lol',base:'https://api.adsb.lol/v2',path:p},
       {name:'airplanes.live',base:'https://api.airplanes.live/v2',path:p}
     ]
    :[
       {name:'adsb.lol',base:'https://api.adsb.lol/v2',path:p},
       {name:'airplanes.live',base:'https://api.airplanes.live/v2',path:p},
       {name:'adsb.fi',base:'https://opendata.adsb.fi/api',path:toAdsbFi(p)}
     ].filter(x=>x.path);

  const flight=(async()=>{
    const results=await Promise.allSettled(providers.map(async prov=>{
      if(phBlocked(prov.name))throw new Error(prov.name+' cooling down');
      const release=await gate();
      try{
        const started=Date.now();
        const r=await fetch(prov.base+prov.path,{headers:{'user-agent':UA,'accept':'application/json'},signal:AbortSignal.timeout(8000)});
        if(!r.ok){phFail(prov.name);throw new Error(prov.name+' HTTP '+r.status)}
        phOk(prov.name);
        console.log('ADS-B',r.status,prov.name,prov.path,Date.now()-started+'ms');
        return {base:prov.name,data:await r.json()};
      }catch(e){phFail(prov.name);throw e}
      finally{release()}
    }));
    const ok=results.filter(x=>x.status==='fulfilled').map(x=>x.value);
    const all=ok.flatMap(x=>Array.isArray(x.data.ac)?x.data.ac:[]);
    if(all.length){
      const primary=ok.slice().sort((a,b)=>(b.data.ac||[]).length-(a.data.ac||[]).length)[0].data;
      const merged=mergeAircraftRows(all),b=JSON.stringify({...primary,ac:merged,total:merged.length,sources:ok.map(x=>x.base)});
      cache.set(p,{t:Date.now(),b});return b;
    }
    if(hit&&hit.b){console.log('ADS-B all failed, using stale cache for',p);throw new Error('retaining stale cache')}
    throw new Error('all ADS-B providers failed or rate-limited');
  })();
  cache.set(p,{...(hit||{}),flight});
  const cleanup=()=>{const latest=cache.get(p);if(latest&&latest.flight===flight){if(latest.b)cache.set(p,{t:latest.t,b:latest.b});else cache.delete(p)}};
  if(hit&&hit.b){flight.catch(e=>console.log('ADS-B background failed',p,e.message)).finally(cleanup);return hit.b}
  try{return await flight}finally{cleanup()}
}

/* ---- keys ---- */
const KF=path.join(ROOT,'keys.json');let KEYS={};try{KEYS=JSON.parse(fs.readFileSync(KF,'utf8'))}catch(e){}
const key=n=>process.env[n.toUpperCase()]||KEYS[n]||'';

/* ---- OpenSky ---- */
let tok=null,tokExp=0,osCache=null;
async function osToken(){const id=key('opensky_id'),sec=key('opensky_secret');if(!id||!sec)return null;if(tok&&Date.now()<tokExp)return tok;
 const r=await fetch('https://auth.opensky-network.org/auth/realms/opensky-network/protocol/openid-connect/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded','user-agent':UA},body:new URLSearchParams({grant_type:'client_credentials',client_id:id,client_secret:sec})});
 if(!r.ok)throw new Error('opensky auth '+r.status);const j=await r.json();tok=j.access_token;tokExp=Date.now()+(j.expires_in-60)*1000;return tok}
async function opensky(){const ttl=(key('opensky_id')?120:900)*1000;if(osCache&&Date.now()-osCache.t<ttl)return osCache.b;
 try{const t=await osToken(),r=await fetch('https://opensky-network.org/api/states/all',{headers:{...(t?{authorization:'Bearer '+t}:{}),'user-agent':UA},signal:AbortSignal.timeout(30000)});
  console.log(r.status,'opensky',t?'(auth)':'(anonymous)');if(!r.ok)throw new Error('opensky '+r.status);osCache={t:Date.now(),b:await r.text()};return osCache.b}
 catch(e){console.log('opensky error:',e.message);if(osCache){osCache.t=Date.now()-ttl+60000;return osCache.b}throw e}}

/* ---- AISStream ---- */
const ships=new Map(),stat=new Map();let ais=null,aisKey='';
function startAis(){const k=key('aisstream');if(!k||k===aisKey)return;if(typeof WebSocket==='undefined'){console.log('AISStream needs Node 22+ (global WebSocket)');return}aisKey=k;try{ais&&ais.close()}catch(e){}
 const open=()=>{const ws=ais=new WebSocket('wss://stream.aisstream.io/v0/stream');
  ws.onopen=()=>{ws.send(JSON.stringify({APIKey:k,BoundingBoxes:[[[-90,-180],[90,180]]],FilterMessageTypes:['PositionReport','ShipStaticData']}));console.log('aisstream connected')};
  ws.onmessage=async ev=>{try{let d=ev.data;if(typeof d!=='string')d=typeof d.text==='function'?await d.text():Buffer.from(d).toString();const m=JSON.parse(d);
   if(m.error){console.log('aisstream:',m.error);return}const md=m.MetaData,sd=m.Message&&m.Message.ShipStaticData;if(sd&&md){stat.set(md.MMSI,[sd.Type,(sd.Destination||'').trim()]);return}const p=m.Message&&m.Message.PositionReport;if(!p||!md)return;const s=stat.get(md.MMSI)||[];
   ships.set(md.MMSI,[md.MMSI,(md.ShipName||'').trim(),md.latitude,md.longitude,p.Cog,p.Sog,Date.now(),s[0],s[1]])}catch(e){}};
  ws.onclose=()=>{if(aisKey===k)setTimeout(open,5000)};ws.onerror=()=>{}};open()}
setInterval(()=>{const o=Date.now()-18e5;for(const[k,v]of ships)if(v[6]<o)ships.delete(k)},6e4);startAis();

/* ---- News ---- */
const newsC=new Map();
async function news(q){const h=newsC.get(q);if(h&&Date.now()-h.t<18e5)return h.b;let b;
 try{const r=await fetch('https://news.google.com/rss/search?q='+encodeURIComponent(q+' when:2d')+'&hl=en-US&gl=US&ceid=US:en',{headers:{'user-agent':UA},signal:AbortSignal.timeout(20000)});
  if(!r.ok)throw new Error('google news '+r.status);const a=rss(await r.text());if(!a.length)throw new Error('no items');b=JSON.stringify({articles:a})}
 catch(e){console.log('news:',e.message);const k=key('answerline');if(!k)throw e;
  const r=await fetch('https://api.answerline.dev/v1/monitor/google/news',{method:'POST',headers:{authorization:'Bearer '+k,'content-type':'application/json','user-agent':UA},body:JSON.stringify({query:q,pages:1}),signal:AbortSignal.timeout(60000)});
  b=await r.text();if(!r.ok)throw new Error('answerline '+r.status+' '+b.slice(0,160))}
 newsC.set(q,{t:Date.now(),b});return b}
function rss(x){const g=(s,t)=>{const m=s.match(new RegExp('<'+t+'[^>]*>([\\s\\S]*?)</'+t+'>'));return m?m[1].replace(/<!\[CDATA\[|\]\]>/g,'').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"').replace(/&#39;/g,"'").replace(/&amp;/g,'&').trim():''};
 return[...x.matchAll(/<item>([\s\S]*?)<\/item>/g)].slice(0,8).map(m=>({title:g(m[1],'title'),url:g(m[1],'link'),source:g(m[1],'source'),date:g(m[1],'pubDate')}))}

/* ---- TLEs ---- */
async function tle(){
 const f=path.join(ROOT,'.cache','tle.txt');let st=null;try{st=fs.statSync(f)}catch(e){}
 if(st&&Date.now()-st.mtimeMs<72e5)return fs.readFileSync(f);
 const groups=['active','stations'],parts=[];
 for(const g of groups){
  const urls=[`https://celestrak.org/NORAD/elements/gp.php?GROUP=${g}&FORMAT=tle`,`https://celestrak.com/NORAD/elements/gp.php?GROUP=${g}&FORMAT=tle`];
  for(const url of urls){
   try{const r=await fetch(url,{headers:{'user-agent':UA,'accept':'text/plain'},signal:AbortSignal.timeout(30000)});console.log(r.status,'tle',g);
    if(r.ok){parts.push(Buffer.from(await r.arrayBuffer()).toString());break}}catch(e){console.log('tle err',e.message)}
  }
 }
 if(parts.length){const b=Buffer.from(parts.join('\n'));fs.mkdirSync(path.dirname(f),{recursive:true});fs.writeFileSync(f,b);return b}
 if(st)return fs.readFileSync(f);
 throw new Error('CelesTrak blocked this IP (403). Result is cached after the first success.');
}

/* ---- FIRMS ---- */
let fireC=null;
const FIRMS_FEEDS=[
 'https://firms.modaps.eosdis.nasa.gov/data/active_fire/suomi-npp-viirs-c2/csv/SUOMI_VIIRS_C2_Global_24h.csv',
 'https://firms.modaps.eosdis.nasa.gov/data/active_fire/modis-c6.1/csv/MODIS_C6_1_Global_24h.csv'
];
async function firms(){if(fireC&&Date.now()-fireC.t<18e5)return fireC.b;
 const rows=new Map();let got=0;
 for(const url of FIRMS_FEEDS){
  try{
   const r=await fetch(url,{headers:{'user-agent':UA},signal:AbortSignal.timeout(60000)});console.log(r.status,'firms',url.split('/').pop());
   if(!r.ok)continue;
   const L=(await r.text()).split('\n'),h=L[0].trim().split(','),ix=n=>h.indexOf(n);
   const a=ix('latitude'),o=ix('longitude'),f=ix('frp'),c=ix('confidence');
   for(let i=1;i<L.length;i++){
    const p=L[i].split(',');if(p.length<h.length)continue;
    if(c>=0&&p[c]==='l')continue;
    const lat=+p[a],lon=+p[o],frp=+p[f];
    if(!Number.isFinite(lat)||!Number.isFinite(lon)||!Number.isFinite(frp))continue;
    const k=lat.toFixed(2)+','+lon.toFixed(2),old=rows.get(k);
    if(!old||frp>old[2])rows.set(k,[lat,lon,frp]);
   }
   got++;
  }catch(e){console.log('firms err',e.message)}
 }
 if(!rows.size){if(fireC)return fireC.b;throw new Error('FIRMS feeds unavailable')}
 const all=[...rows.values()].sort((x,y)=>y[2]-x[2]).slice(0,6000);
 console.log('firms merged',got,'feeds →',all.length);
 const b=JSON.stringify(all);fireC={t:Date.now(),b};return b}

/* ---- Earthquakes ---- */
let quakeC=null;
const rad=x=>x*Math.PI/180;
function kmBetween(a,b){const dLat=rad(a[1]-b[1]),dLon=rad(a[0]-b[0]),q=Math.sin(dLat/2)**2+Math.cos(rad(a[1]))*Math.cos(rad(b[1]))*Math.sin(dLon/2)**2;return 6371*2*Math.asin(Math.min(1,Math.sqrt(q)))}
async function quakes(){if(quakeC&&Date.now()-quakeC.t<90000)return quakeC.b;
 const since=new Date(Date.now()-86400000).toISOString();
 const srcs=[
  {n:'USGS',u:'https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/2.5_day.geojson'},
  {n:'EMSC',u:'https://www.seismicportal.eu/fdsnws/event/1/query?format=json&minmag=2.5&limit=500&starttime='+encodeURIComponent(since)},
  {n:'GEOFON',u:'https://geofon.gfz-potsdam.de/fdsnws/event/1/query?format=json&minmagnitude=2.5&limit=500&starttime='+encodeURIComponent(since)}
 ];
 const results=await Promise.allSettled(srcs.map(s=>fetch(s.u,{headers:{'user-agent':UA},signal:AbortSignal.timeout(14000)}).then(async r=>{if(!r.ok)throw Error(s.n+' '+r.status);return {source:s.n,features:(await r.json()).features||[]}})));
 const features=[];
 for(const r of results){
  if(r.status!=='fulfilled'){console.log('quake source failed:',r.reason&&r.reason.message);continue}
  for(const f of r.value.features){
   const p=f.properties||{},g=f.geometry;if(!g||!g.coordinates||g.coordinates.length<2)continue;
   const lon=+g.coordinates[0],lat=+g.coordinates[1];
   const mag=+(p.mag??p.Mag??p.magnitude??NaN);
   if(!Number.isFinite(lat)||!Number.isFinite(lon)||!Number.isFinite(mag)||mag<2.5)continue;
   const rawT=p.time??p.Time??p.originTime;
   const time=typeof rawT==='number'?rawT:typeof rawT==='string'?(Date.parse(rawT)||0):0;
   const place=p.place||p.flynn_region||p.Flynn_region||p.region||'Unknown location';
   const entry={type:'Feature',id:r.value.source+' '+(f.id||p.source_id||p.unid||`${time}:${lat.toFixed(2)}:${lon.toFixed(2)}`),
     geometry:{type:'Point',coordinates:[lon,lat,+((g.coordinates[2])||0)]},
     properties:{mag,time,place,url:p.url||'',sources:[r.value.source]}};
   const dupe=features.find(x=>Math.abs((x.properties.time||0)-time)<120000&&Math.abs((x.properties.mag||0)-mag)<1.1&&kmBetween(x.geometry.coordinates,[lon,lat])<65);
   if(dupe){dupe.properties.sources=[...new Set([...(dupe.properties.sources||[]),r.value.source])];
     if(r.value.source==='USGS'){dupe.id=entry.id;dupe.properties={...entry.properties,sources:dupe.properties.sources}}}
   else features.push(entry);
  }
 }
 if(!features.length&&quakeC)return quakeC.b;
 if(!features.length)throw Error('earthquake feeds unavailable');
 features.sort((a,b)=>(b.properties.time||0)-(a.properties.time||0));
 const b=JSON.stringify({type:'FeatureCollection',features});quakeC={t:Date.now(),b};return b;
}

/* ---- Buoys ---- */
let buoyC=null;
async function buoys(){
 if(buoyC&&Date.now()-buoyC.t<9e5)return buoyC.b;
 const out=new Map();
 try{
  const r=await fetch('https://www.ndbc.noaa.gov/data/latest_obs/latest_obs.txt',{headers:{'user-agent':UA},signal:AbortSignal.timeout(30000)});
  if(r.ok){
   const n=v=>v!=null&&v!=='MM';
   for(const l of (await r.text()).split('\n').slice(2)){
    const p=l.trim().split(/\s+/);
    if(p.length<19||p[1]==='MM')continue;
    const lat=+p[1],lon=+p[2];
    if(!Number.isFinite(lat)||!Number.isFinite(lon))continue;
    out.set(p[0],[p[0],lat,lon,'NOAA NDBC · '+[n(p[11])?'waves '+p[11]+' m':'',n(p[9])?'wind '+p[9]+' m/s':'',n(p[18])?'sea '+p[18]+'°C':'',n(p[17])?'air '+p[17]+'°C':''].filter(Boolean).join(' · ')]);
   }
  }
 }catch(e){console.log('ndbc obs err',e.message)}
 try{
  const r=await fetch('https://www.ndbc.noaa.gov/activestations.xml',{headers:{'user-agent':UA},signal:AbortSignal.timeout(30000)});
  if(r.ok){
   const x=await r.text();
   for(const m of x.matchAll(/<station\b[^>]*id="([^"]+)"[^>]*lat="([^"]+)"[^>]*lon="([^"]+)"[^>]*>/g)){
    const id=m[1],lat=+m[2],lon=+m[3];
    if(!Number.isFinite(lat)||!Number.isFinite(lon))continue;
    if(!out.has(id))out.set(id,[id,lat,lon,'NOAA NDBC station']);
   }
  }
 }catch(e){console.log('ndbc roster err',e.message)}
 if(!out.size){if(buoyC)return buoyC.b;throw new Error('NDBC unavailable')}
 const b=JSON.stringify([...out.values()]);buoyC={t:Date.now(),b};console.log('buoys:',out.size);return b;
}

const LOCALIP=['127.0.0.1','::1','::ffff:127.0.0.1'];
const FETCH_OK=['webcams.nyctmc.org','511on.ca','511.alberta.ca','www.ndbc.noaa.gov','api.adsbdb.com','www.gdacs.org','data.livetraffic.com','static.data.gov.hk','services.arcgis.com','gis.bouldercolorado.gov','api.gdeltproject.org','opendata.adsb.fi','api.airplanes.live'];
http.createServer(async(req,res)=>{const u=new URL(req.url,'http://x');
 try{
  if(u.pathname==='/favicon.ico'){res.writeHead(204);return res.end()}
  if(u.pathname==='/api/opensky'){const b=await opensky();res.writeHead(200,{'content-type':'application/json'});return res.end(b)}
  if(u.pathname==='/api/ships'){res.writeHead(200,{'content-type':'application/json'});return res.end(JSON.stringify([...ships.values()].filter(v=>v[7]!==35).map(v=>[...v.slice(0,6),v[7],v[8]])))}
  if(u.pathname==='/api/keys'){
   if(req.method==='POST'){if(!LOCALIP.includes(req.socket.remoteAddress)){res.writeHead(403);return res.end()}
    let b='';for await(const c of req)b+=c;const j=JSON.parse(b||'{}');for(const k of['aisstream','opensky_id','opensky_secret','answerline'])if(typeof j[k]==='string'&&j[k].trim())KEYS[k]=j[k].trim();
    fs.writeFileSync(KF,JSON.stringify(KEYS,null,1));tok=null;osCache=null;startAis()}
   res.writeHead(200,{'content-type':'application/json'});return res.end(JSON.stringify({opensky:!!(key('opensky_id')&&key('opensky_secret')),aisstream:!!key('aisstream'),answerline:!!key('answerline'),ws:typeof WebSocket!=='undefined',ships:ships.size}))}
  if(u.pathname==='/api/health'){
   const age=x=>x?Math.max(0,Math.round((Date.now()-x.t)/1000)):null;
   res.writeHead(200,{'content-type':'application/json','cache-control':'no-store'});
   return res.end(JSON.stringify({ok:true,node:process.version,websocket:typeof WebSocket!=='undefined',uptime:Math.round(process.uptime()),providers:{adsb:{cached:cache.size,health:PH},quakes:{cacheAgeSeconds:age(quakeC)},opensky:{configured:!!(key('opensky_id')&&key('opensky_secret')),cacheAgeSeconds:age(osCache)},aisstream:{configured:!!key('aisstream'),connected:!!(ais&&ais.readyState===1),ships:ships.size},news:{cachedQueries:newsC.size},fireHotspots:{cacheAgeSeconds:age(fireC)},buoys:{cacheAgeSeconds:age(buoyC)}}}))
  }
  if(u.pathname==='/api/news'){const q=(u.searchParams.get('q')||'').slice(0,120);if(!q){res.writeHead(400);return res.end('no query')}res.writeHead(200,{'content-type':'application/json'});return res.end(await news(q))}
  if(u.pathname==='/api/tle'){res.writeHead(200,{'content-type':'text/plain'});return res.end(await tle())}
  if(u.pathname==='/api/fire'){res.writeHead(200,{'content-type':'application/json'});return res.end(await firms())}
  if(u.pathname==='/api/buoys'){res.writeHead(200,{'content-type':'application/json'});return res.end(await buoys())}
  if(u.pathname==='/api/quakes'){const b=await quakes();res.writeHead(200,{'content-type':'application/geo+json','cache-control':'public, max-age=30'});return res.end(b)}
  if(u.pathname==='/api/fetch'){const t=new URL(u.searchParams.get('u')||'');if(t.protocol!=='https:'||t.username||t.password||t.port||!FETCH_OK.includes(t.hostname)){res.writeHead(403);return res.end('host not allowed')}
   const r=await fetch(t,{redirect:'follow',headers:{'user-agent':UA,'accept':'application/json,*/*'},signal:AbortSignal.timeout(30000)});res.writeHead(r.status,{'content-type':r.headers.get('content-type')||'application/json','cache-control':'public, max-age=30'});return res.end(Buffer.from(await r.arrayBuffer()))}
  if(u.pathname==='/api/adsb'){const p=u.searchParams.get('p')||'';
   if(!/^\/(mil|point\/-?[\d.]+\/-?[\d.]+\/\d+)$/.test(p)){res.writeHead(400);return res.end('bad path')}
   const b=await upstream(p);res.writeHead(200,{'content-type':'application/json'});return res.end(b)}
  if(u.pathname.startsWith('/cesium/')){const rel=path.normalize(decodeURIComponent(u.pathname.slice(8)));const f=path.join(CC,rel);
   if(!f.startsWith(CC)){res.writeHead(403);return res.end()}
   if(!fs.existsSync(f)){const r=await fetch(CDN+rel.split(path.sep).join('/'));if(!r.ok){res.writeHead(404);return res.end()}
    fs.mkdirSync(path.dirname(f),{recursive:true});fs.writeFileSync(f,Buffer.from(await r.arrayBuffer()))}
   res.writeHead(200,{'content-type':MIME[path.extname(f)]||'application/octet-stream'});return fs.createReadStream(f).pipe(res)}
  if(u.pathname==='/'||/^\/eye.*\.html$/.test(decodeURIComponent(u.pathname))){
   const fl=fs.readdirSync(ROOT).filter(n=>/^eye.*\.html$/i.test(n)).sort((x,y)=>fs.statSync(path.join(ROOT,y)).mtimeMs-fs.statSync(path.join(ROOT,x)).mtimeMs);
   if(!fl.length){res.writeHead(404,{'content-type':'text/plain'});return res.end('No eye*.html found in '+ROOT)}
   res.writeHead(200,{'content-type':'text/html'});return res.end(fs.readFileSync(path.join(ROOT,fl[0])))}
  res.writeHead(404);res.end()}
 catch(e){console.log('ERR',u.pathname,u.searchParams.get('u')||'',e.message);if(!res.headersSent)res.writeHead(502,{'content-type':'text/plain; charset=utf-8'});if(!res.writableEnded)res.end(String(e.message))}}).listen(PORT,()=>{const fl=fs.readdirSync(ROOT).filter(n=>/^eye.*\.html$/i.test(n));console.log(fl.length?'Eye running at http://localhost:'+PORT+'  (page: '+fl[0]+')':'WARNING: no eye*.html in '+ROOT)});