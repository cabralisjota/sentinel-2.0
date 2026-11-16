
from flask import Flask, jsonify, render_template_string
from datetime import datetime
from collections import Counter
import random
import threading
import time

app = Flask(__name__)
from access_soc import register_access_soc
register_access_soc(app)
events = []
lock = threading.Lock()
event_id = 0

# Simulated locations, not actual attackers.
SOURCES = [
    ("United States", "203.0.113.42", 39.8, -98.6),
    ("Canada", "198.51.100.27", 56.1, -106.3),
    ("Brazil", "192.0.2.83", -14.2, -51.9),
    ("United Kingdom", "203.0.113.18", 55.4, -3.4),
    ("Germany", "198.51.100.64", 51.2, 10.4),
    ("Russia", "192.0.2.95", 61.5, 90.0),
    ("India", "203.0.113.91", 20.6, 78.9),
    ("China", "198.51.100.72", 35.9, 104.2),
    ("Japan", "192.0.2.81", 36.2, 138.3),
    ("Australia", "203.0.113.22", -25.3, 133.8),
    ("South Africa", "192.0.2.44", -30.6, 22.9),
    ("France", "198.51.100.88", 46.6, 2.2)
]

THREATS = [
    ("Port Scan", "medium"),
    ("Brute Force", "high"),
    ("Failed Login", "low"),
    ("Malware Signature", "critical"),
    ("Suspicious Traffic", "medium"),
    ("Firewall Block", "low"),
    ("Unauthorized Access", "critical"),
    ("Credential Stuffing", "high")
]

def monitor():
    global event_id
    while True:
        country, ip, lat, lon = random.choice(SOURCES)
        kind, severity = random.choice(THREATS)
        with lock:
            event_id += 1
            events.insert(0, {
                "id": event_id,
                "time": datetime.now().strftime("%H:%M:%S"),
                "type": kind,
                "severity": severity,
                "country": country,
                "ip": ip,
                "lat": lat,
                "lon": lon
            })
            del events[300:]
        time.sleep(1.8)

threading.Thread(target=monitor, daemon=True).start()

HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport"
content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#080e19">
<title>Sentinel 2.0 | Threat Intelligence</title>

<link rel="stylesheet"
href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">

<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>

<style>
:root{
--bg:#080e19;
--sidebar:#0b1220;
--panel:#0e1829;
--border:#1d3048;
--cyan:#00e5ff;
--red:#ff416b;
--green:#00f0a0;
--yellow:#ffc36b;
--text:#dce8fa;
--muted:#8298b3;
}

*{box-sizing:border-box}

body{
margin:0;
background:var(--bg);
color:var(--text);
font:12px/1.5 Arial,sans-serif;
}

button,input{font:inherit}
button{cursor:pointer}

.shell{
display:flex;
min-height:100vh;
}

.sidebar{
width:205px;
flex-shrink:0;
background:var(--sidebar);
border-right:1px solid var(--border);
padding:18px 11px;
position:sticky;
top:0;
height:100vh;
z-index:1000;
}

.brand{
display:flex;
align-items:center;
gap:10px;
padding:5px 8px 25px;
font-size:17px;
font-weight:900;
letter-spacing:1px;
}

.shield{
background:#063c52;
color:var(--cyan);
padding:9px;
border-radius:7px;
}

.brand small{
display:block;
color:var(--cyan);
font-size:9px;
letter-spacing:2px;
}

.navlabel{
font-size:9px;
letter-spacing:2px;
color:#526b87;
margin:20px 12px 10px;
}

.nav{
width:100%;
text-align:left;
background:none;
border:0;
border-left:2px solid transparent;
color:#8b9fb8;
padding:11px;
border-radius:5px;
margin:2px 0;
}

.nav:hover,.nav.active{
background:#0b3044;
color:var(--cyan);
}

.nav.active{
border-left-color:var(--cyan);
}

.nav span{
display:inline-block;
width:25px;
font-size:15px;
}

.sidebottom{
position:absolute;
bottom:20px;
left:20px;
right:20px;
border-top:1px solid var(--border);
padding-top:15px;
}

.live{color:var(--green);font-size:10px}

.dot{
display:inline-block;
width:7px;
height:7px;
background:var(--green);
border-radius:50%;
box-shadow:0 0 12px var(--green);
margin-right:6px;
}

.muted{color:var(--muted);font-size:11px}

.main{
flex:1;
min-width:0;
padding:17px 21px;
max-width:1700px;
}

.topbar{
display:flex;
justify-content:space-between;
align-items:center;
gap:12px;
margin-bottom:16px;
}

h1{
font-size:19px;
margin:3px 0;
}

.eyebrow{
font-size:10px;
letter-spacing:2px;
color:var(--cyan);
}

.pill{
background:#0d2b2d;
border:1px solid #194b47;
color:var(--green);
padding:6px 10px;
border-radius:5px;
font-size:10px;
white-space:nowrap;
}

.menu{
display:none;
background:#102238;
color:var(--cyan);
border:1px solid var(--border);
border-radius:5px;
padding:8px 12px;
}

.banner{
background:#231322;
border:1px solid #56243c;
color:#f29ab3;
padding:9px 12px;
border-radius:5px;
font-size:10px;
margin-bottom:13px;
}

.stats{
display:grid;
grid-template-columns:repeat(4,minmax(0,1fr));
gap:11px;
margin-bottom:12px;
}

.stat,.panel{
background:linear-gradient(150deg,#111d30,#0c1625);
border:1px solid var(--border);
border-radius:7px;
}

.stat{
padding:13px;
min-height:92px;
}

.stat small{
font-size:9px;
letter-spacing:1px;
color:#849bb6;
}

.value{
font-size:27px;
font-weight:800;
margin:6px 0;
}

.cyan{color:var(--cyan)}
.red{color:var(--red)}
.green{color:var(--green)}
.yellow{color:var(--yellow)}

.panel{padding:13px}

.panelhead{
display:flex;
justify-content:space-between;
align-items:center;
gap:8px;
margin-bottom:12px;
}

.panelhead h2{
font-size:12px;
margin:0;
letter-spacing:.5px;
}

.panelhead h2 span{color:var(--cyan)}

.tag{
background:#0b302e;
border:1px solid #245c57;
color:var(--green);
padding:4px 8px;
border-radius:4px;
font-size:9px;
}

.maplayout{
display:grid;
grid-template-columns:minmax(0,3fr) minmax(180px,1fr);
gap:12px;
margin-bottom:12px;
}

.mapbox{
height:340px;
position:relative;
overflow:hidden;
border:1px solid #18334c;
border-radius:5px;
background:#071321;
}

#map{
width:100%;
height:100%;
background:#071321;
z-index:1;
}

.leaflet-container{
background:#071321!important;
font-family:Arial,sans-serif;
}

.leaflet-control-attribution{
background:#071321cc!important;
color:#7891a8!important;
font-size:9px!important;
}

.leaflet-control-attribution a{
color:#00e5ff!important;
}

.leaflet-popup-content-wrapper{
background:#0e1d30;
color:#dce8fa;
border:1px solid #2c5069;
border-radius:6px;
}

.leaflet-popup-tip{
background:#0e1d30;
}

.leaflet-popup-content{
font-size:12px;
}

.attack-dot{
width:10px;
height:10px;
background:#ff416b;
border-radius:50%;
border:1px solid #ff99b1;
box-shadow:0 0 9px #ff416b,0 0 20px #ff416b88;
animation:pulse 1.8s infinite;
}

@keyframes pulse{
0%{transform:scale(.8);opacity:1}
50%{transform:scale(1.5);opacity:.65}
100%{transform:scale(.8);opacity:1}
}

.target-dot{
width:12px;
height:12px;
background:#00e5ff;
border-radius:50%;
box-shadow:0 0 12px #00e5ff,0 0 24px #00e5ff;
}

.map-overlay{
position:absolute;
left:12px;
top:12px;
z-index:500;
pointer-events:none;
background:#071321c9;
border:1px solid #20435c;
padding:7px 10px;
border-radius:4px;
font-size:10px;
color:#00e5ff;
}

.country{
display:flex;
justify-content:space-between;
border-bottom:1px solid #1b2e43;
padding:9px 0;
font-size:11px;
}

.country strong{color:#ff6688}

.charts{
display:grid;
grid-template-columns:1.6fr 1fr;
gap:12px;
margin-bottom:12px;
}

.canvasbox{
height:175px;
position:relative;
}

canvas{
width:100%;
height:100%;
display:block;
}

.tablewrap{
overflow:auto;
max-height:340px;
}

table{
width:100%;
border-collapse:collapse;
white-space:nowrap;
text-align:left;
}

th{
color:#7b93ad;
font-size:9px;
letter-spacing:1px;
padding:10px 8px;
border-bottom:1px solid var(--border);
}

td{
padding:10px 8px;
border-bottom:1px solid #192b40;
font-size:10px;
color:#b9cce1;
}

.sev{
padding:4px 7px;
border-radius:4px;
font-size:9px;
font-weight:bold;
}

.critical{background:#542037;color:#ff7898}
.high{background:#52351d;color:#ffc17b}
.medium{background:#51451e;color:#ffdc83}
.low{background:#174536;color:#65eab4}

.search{
background:#081321;
border:1px solid #28415a;
color:white;
padding:8px;
border-radius:5px;
width:160px;
}

.footer{
text-align:center;
padding:25px;
color:#516a86;
font-size:9px;
letter-spacing:1px;
}

.hidden{display:none!important}

@media(max-width:1000px){
.sidebar{width:175px}
.main{padding:13px}
}

@media(max-width:760px){
.sidebar{
position:fixed;
width:220px;
transform:translateX(-100%);
transition:transform .2s;
box-shadow:15px 0 40px #0009;
}
.sidebar.open{transform:translateX(0)}
.menu{display:block}
.main{padding:12px}
.stats{grid-template-columns:repeat(2,1fr)}
.maplayout{grid-template-columns:1fr}
.charts{grid-template-columns:1fr}
.mapbox{height:290px}
.value{font-size:24px}
h1{font-size:16px}
}
</style>
</head>

<body>
<div class="shell">

<aside class="sidebar" id="sidebar">
<div class="brand">
<div class="shield">◈</div>
<div>SENTINEL
<small>CYBER DEFENSE 2.0</small>
</div>
</div>

<div class="navlabel">OPERATIONS</div>

<button class="nav active" data-page="overview">
<span>▦</span>SOC Overview
</button>
<button class="nav" data-page="map">
<span>◎</span>Attack Map
</button>
<button class="nav" data-page="threats">
<span>⌁</span>Threat Monitoring
</button>
<button class="nav" data-page="incidents">
<span>◉</span>Incidents
</button>

<div class="navlabel">INTELLIGENCE</div>

<button class="nav" data-page="analytics">
<span>▥</span>Analytics
</button>
<button class="nav" data-page="settings">
<span>⚙</span>Settings
</button>

<div class="sidebottom">
<div class="live"><span class="dot"></span>ENGINE ONLINE</div>
<p class="muted">Local Flask instance</p>
<p class="muted">Simulation mode · v2.0</p>
</div>
</aside>

<main class="main">

<div class="topbar">
<div style="display:flex;align-items:center;gap:12px">
<button class="menu" id="menu">☰</button>
<div>
<div class="eyebrow">SECURITY OPERATIONS CENTER</div>
<h1 id="pageTitle">Attack Intelligence Map</h1>
<div class="muted">Global threat intelligence and monitoring</div>
</div>
</div>
<div class="pill">● LIVE SIM</div>
</div>

<div class="banner">
● DEMONSTRATION MODE —
All security events and attack routes are simulated.
</div>

<section class="stats" id="stats">
<div class="stat">
<small>TOTAL EVENTS</small>
<div class="value cyan" id="total">0</div>
<div class="muted">Observed demo activity</div>
</div>
<div class="stat">
<small>CRITICAL ALERTS</small>
<div class="value red" id="critical">0</div>
<div class="muted">Critical severity</div>
</div>
<div class="stat">
<small>FIREWALL BLOCKS</small>
<div class="value green" id="blocked">0</div>
<div class="muted">Simulated blocks</div>
</div>
<div class="stat">
<small>THREAT SOURCES</small>
<div class="value yellow" id="sources">0</div>
<div class="muted">Unique demo IPs</div>
</div>
</section>

<section id="mapSection" class="maplayout">

<div class="panel">
<div class="panelhead">
<h2><span>◎</span> LIVE ATTACK MAP</h2>
<span class="tag">● LIVE SIMULATION</span>
</div>

<div class="mapbox">
<div id="map"></div>
<div class="map-overlay">◉ GLOBAL THREAT VISUALIZATION</div>
</div>

<div class="muted" style="margin-top:9px">
Accurate geographic coastlines · Simulated threat routes
</div>
</div>

<div class="panel">
<div class="panelhead">
<h2><span>◉</span> TOP ATTACK SOURCES</h2>
</div>
<div id="countries"></div>
<div style="margin-top:18px;border-top:1px solid #1d3048;padding-top:15px">
<div class="muted">SIMULATED EVENT RATE</div>
<div class="value cyan" id="rate">0</div>
<div class="muted">Events per minute</div>
</div>
</div>

</section>

<section class="charts" id="chartsSection">
<div class="panel">
<div class="panelhead">
<h2><span>⌁</span> LIVE ACTIVITY</h2>
<span class="muted">Events / refresh</span>
</div>
<div class="canvasbox">
<canvas id="activity"></canvas>
</div>
</div>

<div class="panel">
<div class="panelhead">
<h2><span>▥</span> ATTACK TYPES</h2>
<span class="muted">Session totals</span>
</div>
<div class="canvasbox">
<canvas id="bars"></canvas>
</div>
</div>
</section>

<section id="incidentsSection">
<div class="panel">
<div class="panelhead">
<h2><span>⚡</span> SECURITY EVENT STREAM</h2>
<input class="search" id="search"
placeholder="Search threats or IP">
</div>
<div class="tablewrap">
<table>
<thead>
<tr>
<th>TIME</th>
<th>EVENT</th>
<th>SOURCE IP</th>
<th>COUNTRY</th>
<th>SEVERITY</th>
</tr>
</thead>
<tbody id="rows"></tbody>
</table>
</div>
</div>
</section>

<section id="settingsSection" class="hidden">
<div class="panel">
<h2>⚙ SYSTEM SETTINGS</h2>
<p class="muted">Version: Sentinel 2.0</p>
<p class="muted">Backend: Python Flask</p>
<p class="muted">Feed: Simulated events</p>
<p class="muted">Retention: 300 events in memory</p>
<p class="muted">Network inspection: Disabled</p>
<p class="muted">Server: 127.0.0.1:5000</p>
</div>
</section>

<div class="footer">
SENTINEL 2.0 // CYBER DEFENSE LAB
<br>SECURITY OPERATIONS SIMULATION
</div>

</main>
</div>

<script>
const $=id=>document.getElementById(id);
let latest=[];
let history=[];
let lastId=0;

const pages={
overview:["Attack Intelligence Map",1,1,1,1],
map:["Global Attack Map",0,1,0,0],
threats:["Threat Monitoring",1,1,1,1],
incidents:["Incident Investigation",0,0,0,1],
analytics:["Threat Analytics",1,0,1,0],
settings:["System Settings",0,0,0,0]
};

function showPage(page){
const c=pages[page];
$("pageTitle").textContent=c[0];
["stats","mapSection","chartsSection","incidentsSection"]
.forEach((id,i)=>{
$(id).classList.toggle("hidden",!c[i+1]);
});
$("settingsSection").classList.toggle(
"hidden",page!=="settings");
document.querySelectorAll(".nav").forEach(n=>{
n.classList.toggle("active",n.dataset.page===page);
});
$("sidebar").classList.remove("open");
setTimeout(()=>{
if(window.sentinelMap)sentinelMap.invalidateSize();
drawCharts();
},100);
}

document.querySelectorAll(".nav").forEach(n=>{
n.onclick=()=>showPage(n.dataset.page);
});

$("menu").onclick=()=>{
$("sidebar").classList.toggle("open");
};

// Real geographic map using Leaflet and GeoJSON.
let sentinelMap=null;
let routeLayer=null;
let markerLayer=null;

const TARGET=[43.6532,-79.3832];

async function initMap(){
if(typeof L==="undefined"){
$("map").textContent="Map library unavailable. Check internet.";
return;
}

sentinelMap=L.map("map",{
zoomControl:true,
attributionControl:true,
worldCopyJump:false,
minZoom:1,
maxZoom:7
}).setView([20,0],2);

L.control.attribution({prefix:false}).addTo(sentinelMap);

// Public geographic boundary dataset.
try{
const response=await fetch(
"https://raw.githubusercontent.com/holtzy/D3-graph-gallery/master/DATA/world.geojson"
);
if(!response.ok)throw Error("GeoJSON download failed");
const geojson=await response.json();

L.geoJSON(geojson,{
style:{
color:"#28516a",
weight:.65,
fillColor:"#14364a",
fillOpacity:.72,
opacity:.8
}
}).addTo(sentinelMap);
}catch(err){
console.error(err);
const warning=L.control({position:"bottomleft"});
warning.onAdd=function(){
const div=L.DomUtil.create("div");
div.style.cssText="background:#251827;color:#ff9db5;padding:6px";
div.textContent="World outlines unavailable";
return div;
};
warning.addTo(sentinelMap);
}

routeLayer=L.layerGroup().addTo(sentinelMap);
markerLayer=L.layerGroup().addTo(sentinelMap);

L.circleMarker(TARGET,{
radius:6,
color:"#00e5ff",
fillColor:"#00e5ff",
fillOpacity:1,
weight:2
}).addTo(sentinelMap).bindPopup("Simulated SOC destination");

setTimeout(()=>sentinelMap.invalidateSize(),300);
}

function arcPoints(start,end){
const points=[];
const steps=40;
let lonDelta=end[1]-start[1];
if(lonDelta>180)lonDelta-=360;
if(lonDelta< -180)lonDelta+=360;

for(let i=0;i<=steps;i++){
const t=i/steps;
const lat=start[0]+(end[0]-start[0])*t+
Math.sin(Math.PI*t)*12;
let lon=start[1]+lonDelta*t;
if(lon>180)lon-=360;
if(lon< -180)lon+=360;
points.push([lat,lon]);
}
return points;
}

function updateMap(data){
if(!sentinelMap||!routeLayer||!markerLayer)return;
routeLayer.clearLayers();
markerLayer.clearLayers();

const unique=new Map();
data.forEach(e=>{
if(!unique.has(e.ip))unique.set(e.ip,e);
});

Array.from(unique.values()).slice(0,12).forEach((e,i)=>{
const start=[e.lat,e.lon];
const points=arcPoints(start,TARGET);

const line=L.polyline(points,{
color:e.severity==="critical"?"#ff416b":"#00e5ff",
weight:1.3,
opacity:.65,
dashArray:"4 7",
interactive:false
}).addTo(routeLayer);

const marker=L.circleMarker(start,{
radius:e.severity==="critical"?6:4,
color:"#ff7394",
weight:1,
fillColor:"#ff416b",
fillOpacity:.95
}).addTo(markerLayer);

marker.bindPopup(
"<b>"+e.country+"</b><br>"+
e.type+"<br>"+
e.ip+"<br>"+
e.severity.toUpperCase()
);
});
}

function canvasSetup(id){
const canvas=$(id);
const rect=canvas.getBoundingClientRect();
if(rect.width<1||rect.height<1)return null;
const dpr=Math.min(window.devicePixelRatio||1,2);
canvas.width=Math.round(rect.width*dpr);
canvas.height=Math.round(rect.height*dpr);
const ctx=canvas.getContext("2d");
ctx.scale(dpr,dpr);
return {ctx,w:rect.width,h:rect.height};
}

function drawActivity(){
const c=canvasSetup("activity");
if(!c)return;
const {ctx,w,h}=c;
const left=30,top=12,bottom=24;
const width=w-left-10;
const height=h-top-bottom;
const values=history.map(v=>v.count);
const max=Math.max(4,...values)*1.2;

ctx.font="10px Arial";

for(let i=0;i<=4;i++){
const y=top+height*i/4;
ctx.strokeStyle="#21364d";
ctx.beginPath();
ctx.moveTo(left,y);
ctx.lineTo(w-10,y);
ctx.stroke();
ctx.fillStyle="#6f89a5";
ctx.textAlign="right";
ctx.fillText(Math.round(max*(4-i)/4),left-6,y+3);
}

if(!history.length)return;

const px=i=>left+(history.length===1?
width/2:width*i/(history.length-1));
const py=v=>top+height-v/max*height;

ctx.beginPath();
history.forEach((v,i)=>{
if(i===0)ctx.moveTo(px(i),py(v.count));
else ctx.lineTo(px(i),py(v.count));
});
ctx.lineTo(px(history.length-1),top+height);
ctx.lineTo(px(0),top+height);
ctx.closePath();

const gradient=ctx.createLinearGradient(0,top,0,top+height);
gradient.addColorStop(0,"rgba(0,229,255,.25)");
gradient.addColorStop(1,"rgba(0,229,255,0)");
ctx.fillStyle=gradient;
ctx.fill();

ctx.beginPath();
history.forEach((v,i)=>{
if(i===0)ctx.moveTo(px(i),py(v.count));
else ctx.lineTo(px(i),py(v.count));
});
ctx.strokeStyle="#00e5ff";
ctx.lineWidth=2;
ctx.shadowColor="#00e5ff";
ctx.shadowBlur=7;
ctx.stroke();
ctx.shadowBlur=0;

ctx.fillStyle="#6f89a5";
ctx.textAlign="center";
if(history.length>1){
ctx.fillText(history[0].time,left+20,h-5);
ctx.fillText(history[history.length-1].time,w-35,h-5);
}
}

function drawBars(){
const c=canvasSetup("bars");
if(!c)return;
const {ctx,w,h}=c;
const counts={};

latest.forEach(e=>{
counts[e.type]=(counts[e.type]||0)+1;
});

const items=Object.entries(counts)
.sort((a,b)=>b[1]-a[1]).slice(0,6);
if(!items.length)return;

const left=18,top=13,bottom=42;
const width=w-left-8;
const height=h-top-bottom;
const max=Math.max(1,...items.map(x=>x[1]));

ctx.font="9px Arial";
ctx.textAlign="center";

for(let i=0;i<=3;i++){
const y=top+height*i/3;
ctx.strokeStyle="#21364d";
ctx.beginPath();
ctx.moveTo(left,y);
ctx.lineTo(w-8,y);
ctx.stroke();
}

const slot=width/items.length;

items.forEach(([name,n],i)=>{
const bw=Math.min(35,slot*.63);
const x=left+i*slot+(slot-bw)/2;
const bh=height*n/max;

ctx.fillStyle="#00e5ff";
ctx.shadowColor="#00e5ff";
ctx.shadowBlur=5;
ctx.fillRect(x,top+height-bh,bw,bh);
ctx.shadowBlur=0;

ctx.fillStyle="#b7d1e3";
ctx.fillText(n,x+bw/2,top+height-bh-5);

const short={
"Suspicious Traffic":"Traffic",
"Malware Signature":"Malware",
"Unauthorized Access":"Access",
"Credential Stuffing":"Credential",
"Firewall Block":"Firewall",
"Failed Login":"Login",
"Brute Force":"Brute",
"Port Scan":"Scan"
}[name]||name;

ctx.fillStyle="#7894ad";
ctx.fillText(short,x+bw/2,h-18);
});
}

function drawCharts(){
drawActivity();
drawBars();
}

function populateRows(){
const term=$("search").value.trim().toLowerCase();
const tbody=$("rows");
tbody.replaceChildren();

const filtered=latest.filter(e=>
[e.type,e.ip,e.country,e.severity]
.some(v=>v.toLowerCase().includes(term))
);

for(const e of filtered.slice(0,50)){
const tr=document.createElement("tr");

for(const value of [e.time,e.type,e.ip,e.country]){
const td=document.createElement("td");
td.textContent=value;
tr.appendChild(td);
}

const td=document.createElement("td");
const badge=document.createElement("span");
badge.className="sev "+e.severity;
badge.textContent=e.severity.toUpperCase();
td.appendChild(badge);
tr.appendChild(td);
tbody.appendChild(tr);
}
}

$("search").addEventListener("input",populateRows);

async function refresh(){
try{
const response=await fetch("/api/events",{
cache:"no-store"
});
if(!response.ok)throw Error("API unavailable");
const data=await response.json();
latest=data;

$("total").textContent=data.length;
$("critical").textContent=
data.filter(e=>e.severity==="critical").length;
$("blocked").textContent=
data.filter(e=>e.type==="Firewall Block").length;
$("sources").textContent=
new Set(data.map(e=>e.ip)).size;

const countries={};
data.forEach(e=>{
countries[e.country]=(countries[e.country]||0)+1;
});

$("countries").replaceChildren();

Object.entries(countries)
.sort((a,b)=>b[1]-a[1])
.slice(0,7)
.forEach(([name,count])=>{
const row=document.createElement("div");
row.className="country";
const label=document.createElement("span");
label.textContent="◈ "+name;
const number=document.createElement("strong");
number.textContent=count;
row.append(label,number);
$("countries").appendChild(row);
});

updateMap(data);
populateRows();

const newest=data.length?data[0].id:0;
const newCount=data.filter(e=>e.id>lastId).length;
lastId=Math.max(lastId,newest);

history.push({
time:new Date().toLocaleTimeString(),
count:newCount
});
if(history.length>28)history.shift();

const avg=history.reduce((s,v)=>s+v.count,0)/
history.length;
$("rate").textContent=Math.round(avg*30);

drawCharts();
}catch(error){
console.error("Sentinel update error:",error);
}
}

window.addEventListener("resize",()=>{
if(sentinelMap)sentinelMap.invalidateSize();
drawCharts();
});

initMap();
refresh();
setInterval(refresh,2000);
</script>
</body>
</html>
"""

@app.route("/")
def dashboard():
    return render_template_string(HTML)

@app.route("/api/events")
def api_events():
    with lock:
        return jsonify(list(events))

if __name__ == "__main__":
    print("SENTINEL 2.0 // GEO INTELLIGENCE ONLINE")
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
