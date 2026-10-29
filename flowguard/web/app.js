"use strict";
document.addEventListener("DOMContentLoaded", () => {
  const $ = id => document.getElementById(id);
  const esc = value => String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const editor = $("code-editor");
  let presets = {}, result = null, terminal = "", version = 0, request = 0, zoom = 1;
  const stages = ["lex", "parse", "semantic", "cfg", "data_flow", "report"];
  function stageView(states = {}) {
    $("stages").innerHTML = stages.map((s,i) => `<span class="stage ${esc(states[s] || 'pending')}"><b>0${i+1}</b> ${s.replace('_',' ').toUpperCase()} <small>${esc(states[s] || 'pending')}</small></span>`).join('<span class="stage-arrow">→</span>');
  }
  function status(text, kind = "") { $("status-pill").textContent = text; $("status-pill").className = kind; }
  function syncEditor(stale = false) {
    if (stale) { version++; request++; status(result ? "Edited · results stale" : "Ready", "stale"); $("btn-analyze").disabled=false; $("export-json").disabled=true; $("export-md").disabled=true; }
    $("line-numbers").textContent = editor.value.split('\n').map((_,i) => i+1).join('\n');
    const pattern = /#[^\n]*|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|\b(?:def|return|if|elif|else|while|and|or|not|True|False|None|pass)\b|\b\d+(?:\.\d+)?\b/g;
    let last=0, markup="";
    for (const match of editor.value.matchAll(pattern)) {
      markup += esc(editor.value.slice(last, match.index));
      const cls=match[0][0]==='#'?'comment':/^["']/.test(match[0])?'string':/^\d/.test(match[0])?'number':'keyword';
      markup += `<span class="${cls}">${esc(match[0])}</span>`; last=match.index+match[0].length;
    }
    $("highlight").innerHTML = markup+esc(editor.value.slice(last))+'\n';
    syncScroll(); cursor();
  }
  function syncScroll() { $("highlight").scrollTop=editor.scrollTop; $("highlight").scrollLeft=editor.scrollLeft; $("line-numbers").scrollTop=editor.scrollTop; }
  function cursor() { const lines=editor.value.slice(0,editor.selectionStart).split('\n'); $("cursor-location").textContent=`Ln ${lines.length}, Col ${lines.at(-1).length+1}`; }
  function lineSelect(line) { const lines=editor.value.split('\n'); const start=lines.slice(0,line-1).reduce((n,s)=>n+s.length+1,0); editor.focus(); editor.setSelectionRange(start,start+(lines[line-1]||'').length); editor.scrollTop=Math.max(0,(line-4)*23); syncScroll(); }
  editor.addEventListener('input',()=>syncEditor(true)); editor.addEventListener('scroll',syncScroll); editor.addEventListener('click',cursor); editor.addEventListener('keyup',cursor);
  editor.addEventListener('keydown',e=> { if(e.key==='Tab') {e.preventDefault(); editor.setRangeText('    ',editor.selectionStart,editor.selectionEnd,'end');syncEditor(true);} if(e.key==='Enter'&&(e.ctrlKey||e.metaKey)){e.preventDefault();analyze();} });
  function load() { editor.value=presets[$('preset-select').value] || ''; syncEditor(true); }
  $('preset-select').addEventListener('change',load); $('btn-reset').addEventListener('click',load);
  const tabs=[...document.querySelectorAll('.tab-btn')];
  function tab(name) { tabs.forEach(b=>{const on=b.dataset.tab===name;b.classList.toggle('active',on);b.setAttribute('aria-selected',on);b.tabIndex=on?0:-1;const pane=$('tab-'+b.dataset.tab);pane.hidden=!on;pane.classList.toggle('active',on);}); }
  tabs.forEach((b,i)=>{b.addEventListener('click',()=>tab(b.dataset.tab));b.addEventListener('keydown',e=>{if(['ArrowLeft','ArrowRight','Home','End'].includes(e.key)){e.preventDefault();const n=e.key==='Home'?0:e.key==='End'?tabs.length-1:(i+(e.key==='ArrowRight'?1:-1)+tabs.length)%tabs.length;tab(tabs[n].dataset.tab);tabs[n].focus();}});});
  async function analyze() {
    const stamp=++request, revision=version, code=editor.value; $('btn-analyze').disabled=true; status('Analyzing…');
    try {
      const response=await fetch('/api/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code})});
      const payload=await response.json(); if(stamp!==request || revision!==version)return;
      if(!response.ok || !payload.success)throw Error(payload.error || 'Analysis unavailable');
      result=payload.data;terminal=payload.terminal_report;render();
    } catch(error) { if(stamp===request){status('Request failed','error');$('diagnostics').textContent=error.message;result=null;stageView();$('overview').textContent='Analysis failed. No security conclusion is available.';$('export-json').disabled=true;$('export-md').disabled=true;} }
    finally { if(stamp===request)$('btn-analyze').disabled=false; }
  }
  $('btn-analyze').addEventListener('click',analyze);
  function render() {
    const failed=result.status==='failed', findings=result.findings, stats=result.statistics;
    status(failed?'Analysis failed':findings.length?`${findings.length} finding${findings.length===1?'':'s'}`:'Completed · no modeled flows',failed?'error':findings.length?'risk':'complete');stageView(result.stages);
    const headline=failed?'Analysis could not complete':findings.length?'Untrusted data reaches a sensitive operation':'No modeled unsafe flows detected';
    $('overview').innerHTML=`<div class="eyebrow">ANALYSIS / ${esc(result.status.toUpperCase())}</div><h2>${headline}</h2><p class="intro">${failed?'Resolve the diagnostics below and analyze again.':findings.length?'Inspect a representative source-to-sink witness in Taint Trace.':'No findings within the supported model. This is not a guarantee of security.'}</p><div class="metrics">${[['TOKENS',stats.tokens],['AST NODES',stats.ast_nodes],['CFG BLOCKS',stats.cfg_blocks],['FINDINGS',stats.findings],['WORKLIST VISITS',stats.worklist_steps],['FIXPOINT',stats.converged?'Reached':'Unavailable']].map(([label,value])=>`<div class="metric"><span>${label}</span><strong>${value}</strong></div>`).join('')}</div><div id="finding-cards">${findings.map((f,i)=>`<button class="finding-card" data-finding="${i}"><span class="risk">${esc(f.severity)} / ${esc(f.category)} RISK</span><strong>${esc(f.source_name)} → ${esc(f.sink_name)}()</strong><small>Source L${f.source_line} · Sink L${f.sink_line} · Inspect trace ↗</small></button>`).join('')}</div>`;
    document.querySelectorAll('[data-finding]').forEach(b=>b.addEventListener('click',()=>{$('finding-select').value=b.dataset.finding;trace();tab('trace');}));
    $('diagnostics').replaceChildren(); (result.diagnostics || result.semantic_diagnostics).forEach(d=>{const b=document.createElement('button');b.className='diagnostic '+d.severity.toLowerCase();b.textContent=`${d.severity} · L${d.line}:${d.col} · ${d.message}`;b.onclick=()=>lineSelect(d.line);$('diagnostics').append(b);});
    $('tokens-tbody').innerHTML=result.tokens.map(t=>`<tr><td>${esc(t.type)}</td><td><code>${esc(t.value)}</code></td><td>${t.line}</td><td>${t.col}</td></tr>`).join('');
    $('worklist-tbody').innerHTML=result.iteration_logs.map(l=>`<tr><td>${l.step}</td><td>${esc(l.block_id)}</td><td>${l.changed?'Yes':'No'}</td><td>${esc(JSON.stringify(l.in_vars))}</td><td>${esc(JSON.stringify(l.out_vars))}</td></tr>`).join('');
    $('ast-tree').replaceChildren();if(result.ast)$('ast-tree').append(tree(result.ast,'Program'));
    $('cfg-select').innerHTML=Object.keys(result.cfgs).map(n=>`<option>${esc(n)}</option>`).join('');$('cfg-select').value='main';zoom=1;graph();
    $('finding-select').innerHTML=findings.map((f,i)=>`<option value="${i}">${i+1}. ${esc(f.category)} · sink L${f.sink_line} · source L${f.source_line}</option>`).join('');trace();
    $('terminal-report-view').textContent=terminal;$('export-json').disabled=false;$('export-md').disabled=false;
  }
  function tree(value,label) {
    if(value===null || typeof value!=='object'){const leaf=document.createElement('div');leaf.className='ast-leaf';leaf.textContent=`${label}: ${value}`;return leaf;}
    const d=document.createElement('details'),s=document.createElement('summary');d.open=['Program','body'].includes(label);s.textContent=Array.isArray(value)?`${label} [${value.length}]`:`${label} · ${value.type||'Node'}${value.line?' · L'+value.line+':'+value.col:''}`;d.append(s);
    Object.entries(value).filter(([k])=>!['type','line','col'].includes(k)).forEach(([k,v])=>d.append(tree(v,k)));return d;
  }
  function trace() {
    const f=result?.findings[Number($('finding-select').value)||0];$('trace').replaceChildren();if(!f){$('trace').textContent=result?.status==='failed'?'Analysis incomplete. No trace available.':'No modeled source-to-sink findings to display.';return;}
    const p=document.createElement('p');p.className='intro';p.textContent=f.explanation;$('trace').append(p);
    f.path.forEach((hop,i)=>{const step=document.createElement('button');step.className='trace-step '+(i===0?'source':i===f.path.length-1?'sink':'');step.innerHTML=`<small>${i===0?'SOURCE':i===f.path.length-1?'SINK':'PROPAGATION'} / L${hop.line}</small><strong>${esc(hop.variable)}</strong><span>${esc(hop.action)}</span><code>${esc(result.source_code.split('\n')[hop.line-1]||'')}</code>`;step.onclick=()=>lineSelect(hop.line);$('trace').append(step);});
    const meta=document.createElement('p');meta.className='muted';meta.textContent=f.path_kind+' CFG walk (loop visits may be summarized): '+f.cfg_path.join(' → ');$('trace').append(meta);
  }
  $('finding-select').addEventListener('change',trace);
  function graph() {
    const cfg=result?.cfgs[$('cfg-select').value];if(!cfg){$('graph').textContent='No CFG available.';return;}
    // Longest-path ranks on the DAG with explicit loop back edges removed.
    const ranks={}, indegree=Object.fromEntries(cfg.nodes.map(n=>[n.id,0]));
    const forward=cfg.edges.filter(e=>e.label!=='LoopBack');
    forward.forEach(e=>indegree[e.target]++);
    const queue=cfg.nodes.filter(n=>indegree[n.id]===0).map(n=>n.id);
    queue.forEach(id=>ranks[id]=0);
    while(queue.length){const id=queue.shift();for(const e of forward.filter(e=>e.source===id)){ranks[e.target]=Math.max(ranks[e.target]||0,(ranks[id]||0)+1);if(--indegree[e.target]===0)queue.push(e.target);}}
    const rows={};cfg.nodes.forEach(n=>{const rank=ranks[n.id]??0;(rows[rank]??=[]).push(n);});
    const width=Math.max(1,...Object.values(rows).map(r=>r.length))*360+160,pos={}, heights={};
    Object.entries(rows).forEach(([rank,nodes])=>nodes.forEach((n,i)=>{pos[n.id]={x:80+(width-160-nodes.length*360)/2+i*360,y:40+Number(rank)*200};heights[n.id]=Math.min(6,n.instructions.length)*20+55;}));
    const height=(Math.max(...Object.keys(rows).map(Number))+1)*200+50;
    let svg=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" style="width:${width*zoom}px;height:${height*zoom}px" role="img" aria-label="Control flow graph for ${esc(cfg.name)}"><defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8" fill="#73989d"/></marker></defs>`;
    cfg.edges.forEach((e,i)=>{const a=pos[e.source],b=pos[e.target],back=b.y<=a.y,x=a.x+160,y=a.y+heights[e.source],tx=b.x+160,ty=b.y;const lane=25+(i%4)*13;let path=back?`M${a.x},${a.y+25} C${lane},${a.y+25} ${lane},${b.y+25} ${b.x},${b.y+25}`:`M${x},${y} C${x},${(y+ty)/2} ${tx},${(y+ty)/2} ${tx},${ty}`;svg+=`<path d="${path}" fill="none" stroke="${back?'#bd985b':'#73989d'}" stroke-width="1.5" marker-end="url(#arrow)"/><text x="${back?lane+5:(x+tx)/2+8}" y="${back?(a.y+b.y)/2+25:(y+ty)/2-6}" fill="#b8c8cf" font-size="12">${esc(e.label)}</text>`;});
    cfg.nodes.forEach(n=>{const {x,y}=pos[n.id];svg+=`<g><rect x="${x}" y="${y}" width="320" height="${heights[n.id]}" rx="5" fill="#16212b" stroke="${n.label==='Entry'||n.label==='Exit'?'#51b8ac':'#465563'}"/><text x="${x+12}" y="${y+23}" fill="#76cabc" font-size="13">${esc(n.id)} / ${esc(n.label)}</text>`;n.instructions.slice(0,6).forEach((v,i)=>{const label=`L${v.line}: ${v.repr}`;svg+=`<text x="${x+12}" y="${y+48+i*20}" fill="#dae2e9" font-size="12"><title>${esc(label)}</title>${esc(label.length>40?label.slice(0,37)+'…':label)}</text>`;});svg+='</g>';});$('graph').innerHTML=svg+'</svg>';
  }
  $('cfg-select').addEventListener('change',()=>{zoom=1;graph();});$('zoom-in').onclick=()=>{zoom=Math.min(2,zoom+.2);graph();};$('zoom-out').onclick=()=>{zoom=Math.max(.3,zoom-.2);graph();};$('fit').onclick=()=>{const cfg=result?.cfgs[$('cfg-select').value];if(!cfg)return;zoom=1;graph();const svg=$('graph').querySelector('svg');if(svg){zoom=Math.min(1,($('graph').clientWidth-30)/svg.viewBox.baseVal.width);graph();}};
  function download(kind) {if(!result)return;const blob=new Blob([kind==='json'?JSON.stringify(result,null,2):result.markdown_report],{type:kind==='json'?'application/json':'text/markdown'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='flowguard-report.'+(kind==='json'?'json':'md');a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);}
  $('export-json').onclick=()=>download('json');$('export-md').onclick=()=>download('md');
  stageView();tab('overview');
  fetch('/api/examples').then(r=>{if(!r.ok)throw Error('Examples unavailable');return r.json();}).then(data=>{presets=data;$('preset-select').innerHTML=Object.keys(data).map(n=>`<option value="${esc(n)}">${esc(n)}</option>`).join('');$('preset-select').value='slide_example.fg';load();status('Ready');}).catch(e=>status(e.message,'error'));
});
