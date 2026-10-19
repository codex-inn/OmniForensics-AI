"use strict";
const $ = id => document.getElementById(id);
let reportData = null;
const MAX_FILES = 5, MAX_BYTES = 4 * 1024 * 1024;
function esc(value) {
  return String(value ?? "").replace(/[&<>"]/g, ch => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[ch]));
}
function toast(message) { $("toast").textContent = message; }
function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob), a = document.createElement("a");
  a.href = url; a.download = filename; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function ascii(bytes, start, length) {
  return Array.from(bytes.subarray(start, Math.min(start + length, bytes.length)), b => String.fromCharCode(b)).join("");
}
function signature(bytes, name) {
  const starts = (arr) => arr.every((b, i) => bytes[i] === b);
  if (starts([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a])) return "PNG image";
  if (starts([0xff,0xd8,0xff])) return "JPEG image";
  if (starts([0x47,0x49,0x46,0x38,0x37,0x61]) || starts([0x47,0x49,0x46,0x38,0x39,0x61])) return "GIF image";
  if (starts([0x25,0x50,0x44,0x46,0x2d])) return "PDF document";
  if (starts([0x50,0x4b,0x03,0x04])) return "ZIP-based file";
  if (starts([0x7f,0x45,0x4c,0x46])) return "ELF executable";
  if (starts([0x4d,0x5a])) return "Windows executable";
  if (starts([0x4f,0x67,0x67,0x53])) return "Ogg media";
  if (starts([0x52,0x49,0x46,0x46])) return "RIFF container";
  if (name.toLowerCase().endsWith(".txt")) return "Text file (extension only; signature not verified)";
  return "Unknown / unrecognized signature";
}
async function inspectFile(file) {
  if (file.size > MAX_BYTES) throw new Error(file.name + " exceeds the 4 MiB limit.");
  const buffer = await file.arrayBuffer(), bytes = new Uint8Array(buffer);
  if (!bytes.length) throw new Error(file.name + " is empty.");
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  const sha256 = Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("");
  const result = { filename:file.name, size_bytes:file.size, sha256, signature_hint:signature(bytes,file.name), limitation:"A signature hint and hash do not establish authenticity, origin, identity, timeline, or criminal activity." };
  if (["PNG image","JPEG image","GIF image"].includes(result.signature_hint)) {
    try {
      const bitmap = await createImageBitmap(file);
      result.image = { width:bitmap.width, height:bitmap.height, format:result.signature_hint.replace(" image","") };
      bitmap.close();
    } catch (_) { result.image_parse_note = "Image dimensions could not be read by this browser."; }
  }
  if (result.signature_hint === "PDF document" || file.name.toLowerCase().endsWith(".pdf")) {
    const sample = ascii(bytes, 0, Math.min(bytes.length, 2 * 1024 * 1024));
    const pages = (sample.match(/\/Type\s*\/Page\b/g) || []).length;
    result.pdf = { page_count_hint:pages || null, title_hint:extractPdfText(sample, /\/Title\s*\(([^)]{1,300})\)/), author_hint:extractPdfText(sample, /\/Author\s*\(([^)]{1,200})\)/), note:"Basic byte-pattern hints only; compressed or complex PDFs may not be parsed." };
  }
  return result;
}
function extractPdfText(text, pattern) { const match = text.match(pattern); return match ? match[1].replace(/\\([()\\])/g,"$1") : ""; }
function buildReport(files = []) {
  const observations = $("observations").value.split(/\r?\n/).map(x=>x.trim().replace(/^[•\-\t ]+/,"")).filter(Boolean);
  const checks = [];
  if (!$("sceneDescription").value.trim()) checks.push("Incident description was not supplied.");
  if (!observations.length) checks.push("No investigator observations were supplied.");
  if (!$("incidentDate").value.trim()) checks.push("Incident date/time is unspecified; verify against a trusted source.");
  if (!$("sceneLocation").value.trim()) checks.push("Scene location is unspecified.");
  if (!files.length) checks.push("No files were submitted for metadata and hash review.");
  const byHash = new Map();
  for (const f of files) { if (!byHash.has(f.sha256)) byHash.set(f.sha256, []); byHash.get(f.sha256).push(f.filename); }
  for (const names of byHash.values()) if (names.length > 1) checks.push("Identical file bytes detected among submitted files: " + names.join(", "));
  for (const f of files) if (f.signature_hint.startsWith("Unknown")) checks.push("No recognized leading-byte signature detected for: " + f.filename);
  return {
    product:"OmniForensics AI — Browser-only Scene Triage",
    generated_at_utc:new Date().toISOString(),
    case_reference:$("caseRef").value.trim(),
    incident_date:$("incidentDate").value.trim(),
    location:$("sceneLocation").value.trim(),
    incident_type:$("incidentType").value,
    description:$("sceneDescription").value.trim(),
    investigator_observations:observations,
    automated_checks_and_followups:checks,
    files,
    file_count:files.length,
    privacy:{analysis_location:"This browser", files_uploaded_to_analysis_server:false, persistent_case_storage:false, database_used:false, note:"The app does not send analysis inputs or files to a backend. Device/browser/extensions/network may independently retain data."},
    scope_note:"Educational triage only. This report does not determine that a crime occurred, identify suspects, establish cause of death, reconstruct events, or prove guilt. Human investigators must independently verify findings."
  };
}
function renderReport(r) {
  const fileHtml = r.files.map(f => "<article class='evidence'><h3>"+esc(f.filename)+"</h3><p>"+esc(f.signature_hint)+" · "+f.size_bytes+" bytes</p><p class='hash'>SHA-256: "+esc(f.sha256)+"</p>"+(f.image?"<p>Image dimensions: "+f.image.width+" × "+f.image.height+" ("+esc(f.image.format)+")</p>":"")+(f.pdf?"<p>PDF page count hint: "+esc(f.pdf.page_count_hint ?? "Not detected")+"</p><p>"+esc(f.pdf.note)+"</p>":"")+"</article>").join("");
  $("summary").innerHTML = "<p><b>Generated (UTC):</b> "+esc(r.generated_at_utc)+"</p><p><b>Case reference:</b> "+esc(r.case_reference||"Not supplied")+"</p><p><b>Type:</b> "+esc(r.incident_type)+"</p><p><b>Location:</b> "+esc(r.location||"Not supplied")+"</p><p><b>Description:</b><br>"+esc(r.description||"No description supplied").replace(/\n/g,"<br>")+"</p><h3>Investigator observations</h3><ul>"+(r.investigator_observations.map(x=>"<li>"+esc(x)+"</li>").join("")||"<li>None supplied.</li>")+"</ul><h3>File checks</h3>"+(fileHtml||"<p>No files submitted.</p>")+"<h3>Follow-up checks</h3><ul>"+(r.automated_checks_and_followups.map(x=>"<li>"+esc(x)+"</li>").join("")||"<li>No automated flags generated. This does not prove no issues exist.</li>")+"</ul><p class='notice'>"+esc(r.scope_note)+"</p>";
  $("report").hidden = false;
}
function pdfEscape(s) { return String(s).replace(/\\/g,"\\\\").replace(/\(/g,"\\(").replace(/\)/g,"\\)").replace(/[^\x20-\x7e]/g,"?"); }
function makePdf(text) {
  const lines = [];
  for (const para of text.split("\n")) {
    if (!para) { lines.push(""); continue; }
    let remaining = para;
    while (remaining.length > 88) { let cut = remaining.lastIndexOf(" ",88); if (cut < 30) cut = 88; lines.push(remaining.slice(0,cut)); remaining=remaining.slice(cut).trimStart(); }
    lines.push(remaining);
  }
  const pageLines = lines.slice(0,48);
  if (lines.length > 48) pageLines.push("... Report shortened in PDF; download JSON for complete data.");
  let stream = "BT\n/F1 10 Tf\n50 755 Td\n13 TL\n";
  for (const line of pageLines) stream += "(" + pdfEscape(line) + ") Tj\nT*\n";
  stream += "ET";
  const objects = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    "<< /Length " + stream.length + " >>\nstream\n" + stream + "\nendstream"
  ];
  let pdf = "%PDF-1.4\n", offsets = [0];
  for (let i=0;i<objects.length;i++) { offsets.push(pdf.length); pdf += (i+1)+" 0 obj\n"+objects[i]+"\nendobj\n"; }
  const xref = pdf.length; pdf += "xref\n0 "+(objects.length+1)+"\n0000000000 65535 f \n";
  for (let i=1;i<offsets.length;i++) pdf += String(offsets[i]).padStart(10,"0")+" 00000 n \n";
  pdf += "trailer\n<< /Size "+(objects.length+1)+" /Root 1 0 R >>\nstartxref\n"+xref+"\n%%EOF";
  return new Blob([pdf], {type:"application/pdf"});
}
function pdfText(r) {
  const lines = ["OMNIFORENSICS AI","BROWSER-ONLY SCENE TRIAGE REPORT","Generated UTC: "+r.generated_at_utc,"","Case reference: "+(r.case_reference||"Not supplied"),"Incident date/time: "+(r.incident_date||"Not supplied"),"Location: "+(r.location||"Not supplied"),"Incident type: "+r.incident_type,"","Description:",r.description||"Not supplied","","Investigator observations:",...(r.investigator_observations.length?r.investigator_observations:["None supplied."]),"","FILE CHECKS"];
  for (const f of r.files) lines.push(f.filename+" | "+f.signature_hint+" | "+f.size_bytes+" bytes","SHA-256: "+f.sha256, f.image?"Image: "+f.image.width+" x "+f.image.height:"", f.pdf?"PDF page count hint: "+(f.pdf.page_count_hint||"Not detected"):"");
  lines.push("","FOLLOW-UP CHECKS",...(r.automated_checks_and_followups.length?r.automated_checks_and_followups:["No automated flags generated."]), "", "SCOPE & PRIVACY",r.scope_note,"Inputs are processed in this browser; no analysis server is called. Browser/device/network may retain data independently.");
  return lines.join("\n");
}
$("analysisForm").addEventListener("submit", async event => {
  event.preventDefault();
  const button=$("analyzeBtn"); button.disabled=true; toast("Analyzing files locally in this browser…");
  try {
    if (!window.crypto?.subtle) throw new Error("Secure browser cryptography is unavailable. Open the HTTPS GitHub Pages site in a modern browser.");
    const selected=Array.from($("sceneFiles").files);
    if (selected.length>MAX_FILES) throw new Error("Select no more than 5 files.");
    const files=[]; for (const file of selected) files.push(await inspectFile(file));
    reportData=buildReport(files);
    renderReport(reportData); toast("Analysis complete. Nothing was uploaded to an analysis server."); $("report").scrollIntoView({behavior:"smooth",block:"start"});
  } catch(error) { toast(error.message || "Analysis failed."); }
  finally { button.disabled=false; }
});
$("downloadJson").addEventListener("click",()=>{if(reportData)saveBlob(new Blob([JSON.stringify(reportData,null,2)],{type:"application/json;charset=utf-8"}),"omniforensics-analysis.json");});
$("downloadPdf").addEventListener("click",()=>{if(reportData)saveBlob(makePdf(pdfText(reportData)),"omniforensics-analysis-report.pdf");});
$("clearForm").addEventListener("click",()=>{$("analysisForm").reset();$("report").hidden=true;reportData=null;toast("Form and in-memory analysis cleared. This app does not keep case history.");});
