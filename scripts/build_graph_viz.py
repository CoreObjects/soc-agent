#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从单一事实源 model/graph_model.json 生成自包含的 HTML 图（Cytoscape.js 渲染）。
用法：python scripts/build_graph_viz.py
改模型只改 graph_model.json，再重跑本脚本重新生成视图（视图永不手工维护，杜绝漂移）。
"""
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
MODEL_PATH = ROOT / "model" / "graph_model.json"
OUT_PATH = ROOT / "model" / "graph-model.html"

model = json.loads(MODEL_PATH.read_text(encoding="utf-8"))
model_js = json.dumps(model, ensure_ascii=False)

HTML = """<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>全场景安全告警研判知识图谱 · 图模型 __VERSION__</title>
<script src="https://unpkg.com/cytoscape@3.28.1/dist/cytoscape.min.js"></script>
<style>
  :root { --panel: 340px; }
  * { box-sizing: border-box; }
  body { margin:0; font-family: -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif; color:#1e293b; }
  #wrap { display:flex; height:100vh; }
  #cy { flex:1; height:100%; background:#f8fafc; }
  #side { width:var(--panel); height:100%; overflow:auto; border-left:1px solid #e2e8f0; padding:14px 16px; }
  h1 { font-size:16px; margin:0 0 2px; }
  .sub { color:#64748b; font-size:12px; margin-bottom:12px; }
  h2 { font-size:13px; margin:16px 0 6px; border-bottom:1px solid #e2e8f0; padding-bottom:4px; }
  .chip { display:inline-block; padding:2px 8px; border-radius:10px; font-size:11px; color:#fff; margin:2px 3px 2px 0; }
  .row { font-size:12px; margin:3px 0; }
  .k { color:#64748b; }
  label.f { display:block; font-size:12px; margin:3px 0; cursor:pointer; }
  label.f input { vertical-align:middle; margin-right:6px; }
  .swatch { display:inline-block; width:11px; height:11px; border-radius:2px; vertical-align:middle; margin-right:5px; }
  #nodeinfo { font-size:12px; background:#f1f5f9; border-radius:6px; padding:8px; min-height:34px; }
  #nodeinfo .t { font-weight:bold; }
  .cov { font-size:11px; margin:4px 0; padding-left:14px; text-indent:-14px; }
  .ok { color:#16a34a; }
  .note { font-size:11px; color:#94a3b8; margin-top:6px; }
  button { font-size:12px; padding:4px 8px; margin:2px 0; cursor:pointer; }
  #warn { position:absolute; top:10px; left:10px; background:#fef2f2; color:#b91c1c; border:1px solid #fecaca; padding:8px 12px; border-radius:6px; font-size:12px; display:none; }
</style>
</head>
<body>
<div id="wrap">
  <div id="cy"></div>
  <div id="warn">Cytoscape 未加载（可能离线/CDN 被墙）。请联网后刷新，或改用本地 vendored 版本。</div>
  <div id="side">
    <h1>安全告警研判知识图谱</h1>
    <div class="sub">图模型 <b>__VERSION__</b> · __STATUS__<br/>生成自 <code>model/graph_model.json</code>（单一事实源）</div>

    <div id="nodeinfo">点击节点查看 属性 / 键</div>

    <h2>层（点色块可高亮）</h2>
    <div id="layers"></div>

    <h2>边类型过滤</h2>
    <div id="cats"></div>
    <label class="f"><input type="checkbox" id="showDeferred"/> 显示研判扩展层(延后)</label>

    <h2>连接键 vs 关联规则</h2>
    <div id="keys"></div>

    <h2>典型告警覆盖（__COVN__ 类）</h2>
    <div id="cov"></div>

    <div class="note">节点 __NNODES__ · 边类型 __NEDGES__。虚线框/虚线边 = 研判扩展层(第一阶段可不落库)。</div>
  </div>
</div>
<script>
const MODEL = __MODEL__;
if (typeof cytoscape === 'undefined') { document.getElementById('warn').style.display='block'; }

const LAYER_ORDER = ["L1_object","L1_event","L2_resource","L3_enrichment","L4_verdict"];
const elements = [];

// 层（compound 父节点）
LAYER_ORDER.forEach(lk => {
  const L = MODEL.layers[lk];
  if (L) elements.push({ data:{ id:'layer:'+lk, label:L.title, isLayer:1, color:L.color } });
});

// 实体节点（preset 位置：按层分带）
const byLayer = {};
MODEL.nodes.forEach(n => { (byLayer[n.layer] = byLayer[n.layer]||[]).push(n); });
const COL_W = 200, ROW_H = 240, X0 = 130, Y0 = 130;
LAYER_ORDER.forEach((lk, li) => {
  (byLayer[lk]||[]).forEach((n, i) => {
    elements.push({
      data:{ id:n.name, label:n.name, parent:'layer:'+lk, layer:lk,
             color:(MODEL.layers[lk]||{}).color, deferred:n.deferred?1:0,
             keys:(n.keys||[]).join(', '), props:(n.props||[]).join(', '),
             tstate:(n.temporal_state_props||[]).join(', '),
             obs:n.carries_obs?1:0, note:n.note||'' },
      position:{ x:X0 + i*COL_W, y:Y0 + li*ROW_H }
    });
  });
});

// 边（展开 数组/@observable）
function tgts(to){ if(Array.isArray(to)) return to; if(to==='@observable') return ['layer:L1_object','layer:L1_event']; return [to]; }
function srcs(f){ return Array.isArray(f)? f : [f]; }
let eid=0;
MODEL.edges.forEach(e=>{
  const cat = (MODEL.edge_categories||{})[e.category] || {color:'#999'};
  srcs(e.from).forEach(s=> tgts(e.to).forEach(t=>{
    elements.push({ data:{ id:'e'+(eid++), source:s, target:t, label:e.name,
      category:e.category, color:cat.color, deferred:e.deferred?1:0 } });
  }));
});

let cy;
if (typeof cytoscape !== 'undefined') {
cy = cytoscape({
  container: document.getElementById('cy'),
  elements,
  boxSelectionEnabled:false,
  style:[
    { selector:'node[isLayer]', style:{ 'background-color':'data(color)','background-opacity':0.05,
      'border-color':'data(color)','border-width':2,'shape':'round-rectangle','label':'data(label)',
      'text-valign':'top','text-halign':'center','font-size':15,'font-weight':'bold','color':'data(color)','padding':22 } },
    { selector:'node[!isLayer]', style:{ 'background-color':'data(color)','label':'data(label)','color':'#fff',
      'font-size':12,'text-valign':'center','text-halign':'center','shape':'round-rectangle',
      'width':'label','height':30,'padding':10,'text-wrap':'wrap','border-width':0 } },
    { selector:'node[deferred=1]', style:{ 'background-opacity':0.4,'border-style':'dashed','border-width':2,'border-color':'#9ca3af' } },
    { selector:'edge', style:{ 'width':1.4,'line-color':'data(color)','target-arrow-color':'data(color)',
      'target-arrow-shape':'triangle','curve-style':'bezier','label':'data(label)','font-size':9,'color':'#334155',
      'text-background-color':'#fff','text-background-opacity':0.85,'text-background-padding':2,'arrow-scale':0.85 } },
    { selector:'edge[deferred=1]', style:{ 'line-style':'dashed','opacity':0.45 } },
    { selector:'.dim', style:{ 'opacity':0.08 } },
    { selector:'.hl', style:{ 'opacity':1 } }
  ],
  layout:{ name:'preset', fit:true, padding:30 }
});

cy.on('tap','node[!isLayer]', evt=>{
  const d = evt.target.data();
  document.getElementById('nodeinfo').innerHTML =
    '<div class="t">'+d.label+'</div>'+
    (d.keys?'<div class="row"><span class="k">键:</span> '+d.keys+'</div>':'')+
    (d.props?'<div class="row"><span class="k">属性:</span> '+d.props+'</div>':'')+
    (d.tstate?'<div class="row"><span class="k">时效状态属性:</span> '+d.tstate+'</div>':'')+
    (d.obs?'<div class="row"><span class="k">含 Observation 元字段</span></div>':'')+
    (d.note?'<div class="row"><span class="k">备注:</span> '+d.note+'</div>':'');
});
}

// 侧栏：层
const layersDiv = document.getElementById('layers');
LAYER_ORDER.forEach(lk=>{ const L=MODEL.layers[lk]; if(!L) return;
  const s=document.createElement('div'); s.className='row';
  s.innerHTML='<span class="chip" style="background:'+L.color+'">'+L.title+'</span> <span class="k">'+L.desc+'</span>';
  layersDiv.appendChild(s);
});

// 侧栏：边类型过滤
const cats = MODEL.edge_categories||{};
const catsDiv = document.getElementById('cats');
Object.keys(cats).forEach(ck=>{ const c=cats[ck];
  const l=document.createElement('label'); l.className='f';
  l.innerHTML='<input type="checkbox" data-cat="'+ck+'" checked/><span class="swatch" style="background:'+c.color+'"></span>'+c.label+' ('+ck+')';
  catsDiv.appendChild(l);
});
function applyFilters(){
  if(!cy) return;
  const on={}; document.querySelectorAll('#cats input').forEach(i=> on[i.dataset.cat]=i.checked);
  const showDef = document.getElementById('showDeferred').checked;
  cy.batch(()=>{
    cy.edges().forEach(e=>{ const d=e.data();
      const vis = (on[d.category]!==false) && (showDef || !d.deferred);
      e.style('display', vis?'element':'none');
    });
    cy.nodes('[deferred=1]').forEach(n=> n.style('display', showDef?'element':'none'));
  });
}
document.querySelectorAll('#cats input, #showDeferred').forEach(i=> i.addEventListener('change', applyFilters));
applyFilters();

// 侧栏：连接键
const ck = MODEL.connection_keys||{};
document.getElementById('keys').innerHTML =
  '<div class="row"><b>强键</b>: '+(ck.strong||[]).join(', ')+'</div>'+
  '<div class="row"><b>弱键</b>: '+(ck.weak||[]).join(', ')+'</div>'+
  '<div class="row"><b>事件类型键</b>: '+(ck.event_type||[]).join(', ')+' <span class="k">(非唯一,不可当强键)</span></div>'+
  '<div class="row"><b>时序规则</b>: '+(ck.temporal_rules||[]).join(', ')+'</div>'+
  '<div class="row"><b>派生指纹</b>: '+(ck.derived_fingerprints||[]).join(', ')+'</div>';

// 侧栏：告警覆盖
document.getElementById('cov').innerHTML = (MODEL.alert_coverage||[]).map(c=>
  '<div class="cov"><span class="ok">✓</span> <b>'+c.alert+'</b> <span class="k">— '+c.path+'</span></div>').join('');
</script>
</body>
</html>
"""

html = (HTML
        .replace("__MODEL__", model_js)
        .replace("__VERSION__", str(model.get("version", "")))
        .replace("__STATUS__", str(model.get("status", "")))
        .replace("__NNODES__", str(len(model.get("nodes", []))))
        .replace("__NEDGES__", str(len(model.get("edges", []))))
        .replace("__COVN__", str(len(model.get("alert_coverage", [])))))

OUT_PATH.write_text(html, encoding="utf-8")
print(f"[ok] generated {OUT_PATH.relative_to(ROOT)}  ({len(html)} bytes)")
print(f"     nodes={len(model['nodes'])} edges={len(model['edges'])} layers={len(model['layers'])}")
print(f"     直接双击打开，或 repo 根跑 `python -m http.server 8000` 后访问 http://localhost:8000/model/graph-model.html")
