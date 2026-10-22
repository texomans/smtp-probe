const $ = id => document.getElementById(id);
// Fresh visits, reloads and back/forward navigation start with no SMTP host.
window.addEventListener('pageshow', () => { $('host').value = ''; });
const verifyButton = $('verify-btn');
const sendButton = $('send-btn');
const terminal = $('console');
let transcript = [];
let lastResult = null;
let busy = false;
let sendsEnabled = false;
let appVersion = 'unknown';
let csrfToken = null;

async function loadSession() {
  const result = await fetch('/api/session', {cache:'no-store',credentials:'same-origin'});
  if (!result.ok) throw new Error('Cannot load session.');
  const session = await result.json();
  if (!session.authenticated) { window.location.replace('/'); return; }
  csrfToken = session.csrfToken;
  const response = await fetch('/api/info', {cache:'no-store',credentials:'same-origin'});
  if (response.status === 401) {window.location.replace('/');return;}
  if (!response.ok) throw new Error('Cannot read server configuration.');
  const info = await response.json();
  appVersion = info.version || 'unknown';
  sendsEnabled = info.sendEnabled === true;
  sendButton.disabled = !sendsEnabled;
  $('send-flag').textContent = sendsEnabled ? 'Available' : 'Disabled in private preview';
  if (sendsEnabled) $('notice').textContent = 'Sending requires approved recipient addresses or domains; any public SMTP host is permitted unless the administrator restricts it. Authentication, TLS and rate limits still apply.';
}
loadSession().catch(() => {$('notice').textContent = 'Unable to load session. Refresh the page.';});

$('logout-btn').addEventListener('click', async () => {
  const button = $('logout-btn');
  button.disabled = true;
  try {
    const response = await fetch('/api/logout', {method:'POST', credentials:'same-origin',
      headers: {'x-csrf-token':csrfToken ?? ''}});
    if (response.status === 401) {window.location.replace('/');return;}
    if (!response.ok) throw new Error('Logout request failed.');
    csrfToken = null;
    window.location.replace('/');
  } catch {
    $('notice').textContent = 'Logout failed; your session may still be active. Please retry.';
    button.disabled = false;
  }
});

function line(kind, text) {
  if (terminal.querySelector('.empty-console')) terminal.replaceChildren();
  const el = document.createElement('div');
  el.className = `line ${kind}`;
  el.textContent = text;
  terminal.append(el);
  terminal.scrollTop = terminal.scrollHeight;
  transcript.push(text);
  if (transcript.length > 400) {transcript.shift(); terminal.firstElementChild?.remove();}
}
function status(style,text,duration='') {
  $('status').className = 'status ' + style;
  $('status-text').textContent = text;
  $('duration').textContent = duration;
}
function showDetails(result) {
  const tlsEl = $('tls-details');
  const deliveryEl = $('delivery-details');
  const capabilitiesEl = $('capabilities');
  tlsEl.classList.add('hidden'); deliveryEl.classList.add('hidden'); capabilitiesEl.classList.add('hidden');
  tlsEl.replaceChildren(); deliveryEl.replaceChildren(); capabilitiesEl.replaceChildren();
  if (result.tls) {
    tlsEl.classList.remove('hidden');
    const title = document.createElement('h3'); title.textContent = 'TLS / CERTIFICATE'; tlsEl.append(title);
    const pairs = [['Protocol',result.tls.protocol],['Cipher',result.tls.cipher],['Validated',result.tls.authorized ? 'Yes':'No']];
    if (result.tls.certificateChain?.length) {
      const leaf = result.tls.certificateChain[0];
      pairs.push(['Subject',leaf.subject],['Issuer',leaf.issuer],['Expires',leaf.expires],['SHA-256',leaf.fingerprint256]);
      pairs.push(['Chain',`${result.tls.certificateChain.length} certificate(s)`]);
    }
    const grid = document.createElement('div'); grid.className = 'kv';
    pairs.forEach(([key,val]) => {const k = document.createElement('span'); k.textContent = key; const v = document.createElement('span'); v.textContent = val ?? 'N/A'; grid.append(k,v);});
    tlsEl.append(grid);
  }
  if (result.delivery) {
    deliveryEl.classList.remove('hidden');
    const title = document.createElement('h3'); title.textContent = 'SMTP SUBMISSION RECEIPT';
    const grid = document.createElement('div'); grid.className = 'kv';
    const pairs = [
      ['Recipient',result.delivery.recipient],
      ['SMTP status',result.delivery.smtpCode],
      ['Server response',result.delivery.smtpResponse],
      ['Message-ID',result.messageId],
    ];
    pairs.forEach(([key,val]) => {const k=document.createElement('span'); k.textContent=key; const v=document.createElement('span'); v.textContent=String(val??'N/A'); grid.append(k,v);});
    deliveryEl.append(title,grid);
  }
  if (result.capabilities?.length) {
    capabilitiesEl.classList.remove('hidden');
    const title = document.createElement('h3'); title.textContent='POST-HANDSHAKE SMTP CAPABILITIES';
    const list = document.createElement('div'); list.className='cap-list';
    result.capabilities.slice(0,36).forEach(cap => {const el = document.createElement('span'); el.textContent=cap;list.append(el);});
    capabilitiesEl.append(title,list);
  }
}
function configFor(mode) {
  const form = $('test-form');
  if (!form.reportValidity()) return null;
  const formData = new FormData(form);
  const cfg = Object.fromEntries(formData.entries());
  cfg.port = Number(cfg.port);
  cfg.mode = mode;
  if (mode === 'send') {
    for (const id of ['from','to','subject','message']) {
      const field = $(id);
      if (!field.value.trim() || !field.checkValidity()) {field.reportValidity(); field.focus(); return null;}
    }
    cfg.from=$('from').value.trim(); cfg.to=$('to').value.trim(); cfg.subject=$('subject').value;
    cfg.message=$('message').value;
  }
  return cfg;
}
async function run(mode) {
  if (busy) return;
  if (!csrfToken) {window.location.replace('/');return;}
  const cfg = configFor(mode);
  if (!cfg) return;
  if (mode === 'send' && !window.confirm(`Send one real test email to ${cfg.to} using ${cfg.host}:${cfg.port}?`)) return;
  busy = true;
  verifyButton.disabled = true;
  sendButton.disabled = true;
  transcript = [];
  lastResult = null;
  terminal.replaceChildren();
  $('tls-details').classList.add('hidden');
  $('delivery-details').classList.add('hidden');
  $('capabilities').classList.add('hidden');
  status('busy', mode==='send'?'Sending test email…':'Connecting…');
  line('info', `> ${mode.toUpperCase()} ${cfg.host}:${cfg.port} (${cfg.tlsMode.toUpperCase()})`);
  let completed = false;
  try {
    const response = await fetch('/api/test',{method:'POST',headers:{'content-type':'application/json','x-csrf-token':csrfToken},credentials:'same-origin',body:JSON.stringify(cfg),cache:'no-store'});
    if (response.status === 401) { window.location.replace('/'); return; }
    if (!response.ok) {
      const data=await response.json().catch(()=>({}));
      throw new Error(data.error || `HTTP ${response.status}`);
    }
    if (!response.body) throw new Error('Streaming is unavailable in this browser.');
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let pending='';
    while (true) {
      const {value,done}=await reader.read();
      if (done) break;
      pending+=decoder.decode(value,{stream:true}).replace(/\r\n/g,'\n');
      let at;
      while ((at=pending.indexOf('\n\n'))!==-1) {
        const event=pending.slice(0,at); pending=pending.slice(at+2);
        const dataLines=event.split('\n').filter(x=>x.startsWith('data: '));
        if (!dataLines.length) continue;
        let data;
        try {data=JSON.parse(dataLines.map(x=>x.slice(6)).join('\n'));} catch {continue;}
        if (data.type==='transcript') line(data.kind,data.text);
        if (data.type==='stage') {status('busy',data.text); line('stage',`● ${data.text}`);}
        if (data.type==='result') {
          completed=true;
          lastResult=data;
          status(data.ok?'success':'error',data.ok?'Test passed':`Test failed · ${data.stage||'unknown'}`,`${((data.durationMs||0)/1000).toFixed(1)}s`);
          line(data.ok?'tls':'error',data.ok ? `✓ ${data.message}` : `✕ ${data.message}`);
          showDetails(data);
        }
      }
    }
    if (!completed) throw new Error('Connection closed without a result.');
  } catch(err) {status('error','Request failed');line('error',`✕ ${err.message||String(err)}`);}
  finally {busy=false;verifyButton.disabled=false;sendButton.disabled=!sendsEnabled;}
}
verifyButton.addEventListener('click',()=>run('verify'));
sendButton.addEventListener('click',()=>run('send'));
function reportText() {
  const lines=[`SMTP Probe v${appVersion} - redacted diagnostic report`,`Exported: ${new Date().toISOString()}`];
  if (lastResult) {
    lines.push(`Result: ${lastResult.ok?'PASS':'FAIL'}`);
    lines.push(`Outcome: ${lastResult.message||'N/A'}`);
    if (lastResult.durationMs!=null) lines.push(`Duration: ${lastResult.durationMs} ms`);
    if (lastResult.delivery) {
      lines.push(`Recipient: ${lastResult.delivery.recipient}`);
      lines.push(`SMTP acceptance: ${lastResult.delivery.smtpCode} ${lastResult.delivery.smtpResponse}`);
      lines.push(`Message-ID: ${lastResult.messageId||'N/A'}`);
    }
    if (lastResult.tls) lines.push(`TLS: ${lastResult.tls.protocol||'N/A'} · ${lastResult.tls.cipher||'N/A'} · validated ${lastResult.tls.authorized?'yes':'no'}`);
  }
  lines.push('', 'Transcript:', ...transcript);
  return lines.join('\n');
}
$('copy-btn').addEventListener('click',async()=>{
  try {await navigator.clipboard.writeText(reportText());$('copy-btn').textContent='Copied!';}
  catch {$('copy-btn').textContent='Clipboard blocked';}
  setTimeout(()=>$('copy-btn').textContent='Copy report',1800);
});
$('download-btn').addEventListener('click',()=>{
  const file = new Blob([reportText()],{type:'text/plain;charset=utf-8'});
  const url=URL.createObjectURL(file);
  const link=document.createElement('a');
  link.href=url; link.download=`smtp-probe-${new Date().toISOString().slice(0,10)}.txt`;
  document.body.append(link); link.click(); link.remove();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
});
$('tlsMode').addEventListener('change',()=>{
  const mode = $('tlsMode').value;
  if (mode==='implicit' && $('port').value==='587') $('port').value='465';
  if (mode==='starttls' && $('port').value==='465') $('port').value='587';
});
