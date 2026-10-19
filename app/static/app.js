let selected=null;
const API_BASE=String(window.OMNIFORENSICS_API_BASE||"").replace(/\/$/,"");
const apiPath=path=>API_BASE+path;
let authToken=sessionStorage.getItem("omni_api_auth")||"";
function authHeader(){return authToken?{Authorization:"Basic "+authToken}:{}}
const $=id=>document.getElementById(id);
const esc=value=>String(value??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
function toast(message){const t=$("toast");t.textContent=message;t.style.display="block";setTimeout(()=>t.style.display="none",3500)}
async function req(url,options={}){
 const target=apiPath(url);
 const headers={...(options.headers||{}),...authHeader()};
 let response=await fetch(target,{...options,headers});
 if(response.status===401 && API_BASE && !authToken){
  const username=prompt("OmniForensics API username (shared Render credential)");
  if(username===null)throw Error("Login cancelled");
  const password=prompt("OmniForensics API password");
  if(password===null)throw Error("Login cancelled");
  authToken=btoa(unescape(encodeURIComponent(username+":"+password)));
  sessionStorage.setItem("omni_api_auth",authToken);
  response=await fetch(target,{...options,headers:{...(options.headers||{}),...authHeader()}});
 }
 if(!response.ok){if(response.status===401){authToken="";sessionStorage.removeItem("omni_api_auth")}let data={};try{data=await response.json()}catch{}throw Error(data.detail||`Request failed ${response.status}`)}return response
}
async function refresh(){
 const query=$("caseSearch")?.value.trim()||"";
 const cases=await(await req("/api/cases"+(query?"?q="+encodeURIComponent(query):""))).json();
 $("caseCount").textContent=cases.length;
 $("evidenceCount").textContent=cases.reduce((sum,item)=>sum+item.evidence_count,0);
 $("cases").innerHTML=cases.length?cases.map(item=>`<button class="case ${selected===item.id?"active":""}" data-id="${esc(item.id)}"><b>${esc(item.title)}</b><small>${esc(item.id)} · ${item.evidence_count} evidence file(s)</small></button>`).join(""):'<p class="muted">No matching cases. Create an investigation.</p>';
 document.querySelectorAll("[data-id]").forEach(button=>button.onclick=()=>openCase(button.dataset.id));
}
$("refresh").onclick=()=>refresh().catch(error=>toast(error.message));
$("caseSearch")?.addEventListener("input",()=>refresh().catch(error=>toast(error.message)));
$("caseForm").onsubmit=async event=>{
 event.preventDefault();
 try{const result=await(await req("/api/cases",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({title:$("title").value,description:$("description").value})})).json();selected=result.id;$("title").value="";$("description").value="";await refresh();await openCase(result.id);toast("Case created")}
 catch(error){toast(error.message)}
};
function evCard(e){
 let analysis={};try{analysis=JSON.parse(e.analysis_json)}catch{}
 const media=analysis.image?`${analysis.image.width} × ${analysis.image.height} · ${analysis.image.format}`:analysis.video?`${analysis.video.width||"?"} × ${analysis.video.height||"?"} · ${analysis.video.duration_seconds??"?"} sec · ${analysis.video.sampled_frames||0} sampled frames`:"No recognized image/video metadata";
 return `<div class="evidence"><h3>${esc(e.original_name)}</h3><span class="tag">${esc(e.id)}</span><span class="tag">${esc(e.detected_mime)}</span><p class="meta">${esc(media)} · ${Number(e.size_bytes).toLocaleString()} bytes</p><div class="hash">SHA-256: ${esc(e.sha256)}</div><p class="meta">Tags: ${esc(e.tags||"none")} · Source: ${esc(e.source_description||"not recorded")} · Collected by: ${esc(e.collected_by||"not recorded")}</p><div class="actions"><button class="secondary" data-verify="${esc(e.id)}">Verify integrity</button><button class="secondary" data-analysis="${esc(e.id)}">View analysis</button><button class="secondary" data-provenance="${esc(e.id)}">Edit provenance</button><button class="secondary" data-custody="${esc(e.id)}">Add custody event</button><button class="secondary" data-custody-view="${esc(e.id)}">View custody</button></div></div>`;
}
async function openCase(id){
 selected=id;await refresh();
 const data=await(await req(`/api/cases/${encodeURIComponent(id)}`)).json(),c=data.case;
 $("detail").innerHTML=`<h2>${esc(c.title)}</h2><p class="meta">${esc(c.id)} · ${esc(c.created_at)}<br>${esc(c.description||"No description")}</p>
 <div class="upload"><b>Upload evidence</b><p class="muted">Images, videos, documents, logs, PCAP and other files can be stored. Specialized analysis is optional and depends on installed tools/models.</p><form id="upload"><input type="file" id="file" required><button style="margin-top:10px">Upload & inspect</button></form></div>
 <div class="actions"><a class="tag" href="#" data-download="/api/cases/${esc(encodeURIComponent(id))}/report" data-filename="${esc(id)}-report.pdf">Generate PDF report</a><a class="tag" href="#" data-download="/api/cases/${esc(encodeURIComponent(id))}/manifest.json" data-filename="${esc(id)}-manifest.json">Export JSON manifest</a><button id="correlations" class="secondary">Find correlations</button></div>
 <h2>Evidence inventory (${data.evidence.length})</h2>${data.evidence.map(evCard).join("")||'<p class="muted">No evidence uploaded.</p>'}<hr><h2>Investigator notes</h2><form id="note"><input id="noteBody" required maxlength="5000" placeholder="Record a factual observation or follow-up task"><button style="margin-top:8px">Add note</button></form>${data.notes.map(note=>`<div class="evidence"><p>${esc(note.body)}</p><small class="meta">${esc(note.created_at)}</small></div>`).join("")||'<p class="muted">No notes recorded.</p>'}
 <hr><h2>Audit & timeline</h2><div class="actions"><button id="audit" class="secondary">View audit log</button><button id="auditVerify" class="secondary">Verify audit chain</button><button id="timelineBtn" class="secondary">View timeline</button></div><pre id="auditText" style="white-space:pre-wrap;overflow-wrap:anywhere;font-size:11px"></pre>`;
 document.querySelectorAll("[data-download]").forEach(link=>link.onclick=async event=>{
  event.preventDefault();
  try{const response=await req(link.dataset.download);const blob=await response.blob();const objectUrl=URL.createObjectURL(blob);const anchor=document.createElement("a");anchor.href=objectUrl;anchor.download=link.dataset.filename||"download";document.body.appendChild(anchor);anchor.click();anchor.remove();URL.revokeObjectURL(objectUrl)}catch(error){toast(error.message)}
 });
 $("upload").onsubmit=async event=>{event.preventDefault();const file=$("file").files[0];const form=new FormData();form.append("file",file);try{const result=await(await req(`/api/cases/${encodeURIComponent(id)}/evidence`,{method:"POST",body:form})).json();toast("Uploaded. SHA-256 "+result.sha256.slice(0,12)+"…");await openCase(id)}catch(error){toast(error.message)}};
 $("note").onsubmit=async event=>{event.preventDefault();try{await req(`/api/cases/${encodeURIComponent(id)}/notes`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({body:$("noteBody").value})});await openCase(id);toast("Note saved")}catch(error){toast(error.message)}};
 $("audit").onclick=async()=>{try{$("auditText").textContent=JSON.stringify(await(await req(`/api/cases/${encodeURIComponent(id)}/audit`)).json(),null,2)}catch(error){toast(error.message)}};
 $("auditVerify").onclick=async()=>{try{const result=await(await req(`/api/cases/${encodeURIComponent(id)}/audit/integrity`)).json();$("auditText").textContent=JSON.stringify(result,null,2);toast("Audit chain: "+result.status)}catch(error){toast(error.message)}};
 $("timelineBtn").onclick=async()=>{try{$("auditText").textContent=JSON.stringify(await(await req(`/api/cases/${encodeURIComponent(id)}/timeline`)).json(),null,2)}catch(error){toast(error.message)}};
 $("correlations").onclick=async()=>{try{$("auditText").textContent=JSON.stringify(await(await req(`/api/cases/${encodeURIComponent(id)}/correlations`)).json(),null,2)}catch(error){toast(error.message)}};
 document.querySelectorAll("[data-verify]").forEach(button=>button.onclick=async()=>{try{const result=await(await req(`/api/evidence/${button.dataset.verify}/integrity`)).json();button.textContent="Integrity: "+result.status.toUpperCase();toast("Integrity status: "+result.status)}catch(error){toast(error.message)}});
 document.querySelectorAll("[data-analysis]").forEach(button=>button.onclick=async()=>{try{const result=await(await req(`/api/evidence/${button.dataset.analysis}`)).json();alert(JSON.stringify({id:result.id,sha256:result.sha256,size_bytes:result.size_bytes,mime_type:result.detected_mime,analysis:result.analysis},null,2))}catch(error){toast(error.message)}});
 document.querySelectorAll("[data-provenance]").forEach(button=>button.onclick=async()=>{
  const evidenceId=button.dataset.provenance;
  try{const current=await(await req(`/api/evidence/${evidenceId}`)).json();
   const tags=prompt("Comma-separated tags",current.tags||"") ;if(tags===null)return;
   const source=prompt("Evidence source / acquisition method",current.source_description||"");if(source===null)return;
   const handler=prompt("Collected by",current.collected_by||"");if(handler===null)return;
   const acquired=prompt("Acquisition time (ISO 8601 recommended)",current.acquired_at||"");if(acquired===null)return;
   await req(`/api/evidence/${evidenceId}`,{method:"PATCH",headers:{"Content-Type":"application/json"},body:JSON.stringify({tags,source_description:source,collected_by:handler,acquired_at:acquired})});
   await openCase(id);toast("Provenance saved")
  }catch(error){toast(error.message)}
 });
 document.querySelectorAll("[data-custody]").forEach(button=>button.onclick=async()=>{
  const evidenceId=button.dataset.custody;
  try{const action=prompt("Custody action (e.g. received, transferred, sealed, examined)");if(!action)return;
   const handler=prompt("Handler / recipient","");if(handler===null)return;
   const location=prompt("Storage location","");if(location===null)return;
   const details=prompt("Details (condition, reason, reference)","");if(details===null)return;
   await req(`/api/evidence/${evidenceId}/custody`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({action,handler,location,details})});
   toast("Custody event recorded");await openCase(id)
  }catch(error){toast(error.message)}
 });
 document.querySelectorAll("[data-custody-view]").forEach(button=>button.onclick=async()=>{try{alert(JSON.stringify(await(await req(`/api/evidence/${button.dataset.custodyView}/custody`)).json(),null,2))}catch(error){toast(error.message)}});
}
$("evidenceSearch")?.addEventListener("submit",async event=>{
 event.preventDefault();
 const query=$("evidenceQuery").value.trim(),tag=$("evidenceTag").value.trim();
 try{const results=await(await req("/api/evidence/search?"+new URLSearchParams({q:query,tag}))).json();$("evidenceSearchResults").innerHTML=results.length?results.map(item=>`<button class="case" data-search-case="${esc(item.case_id)}"><b>${esc(item.original_name)}</b><small>${esc(item.case_id)} · ${esc(item.tags||"no tags")} · ${esc(item.sha256.slice(0,16))}…</small></button>`).join(""):'<p class="muted">No matching evidence.</p>';document.querySelectorAll("[data-search-case]").forEach(button=>button.onclick=()=>openCase(button.dataset.searchCase))}catch(error){toast(error.message)}
});
refresh().catch(error=>toast(error.message));
