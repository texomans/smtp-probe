import { InputError } from './safety.mjs';
import { validateDnsInput, runDnsDiagnostics } from './email-auth.mjs';

export function createDnsHandler({auth, checkOrigin, json, readJsonBody, requesterIp, limiter, run = runDnsDiagnostics, maxActive = 3}) {
  let active = 0;
  return async function dnsDiagnostics(req, res, session) {
    if (!session) return json(res,401,{error:'Authentication required.'});
    if (!auth.verifyCsrf(session,req.headers['x-csrf-token'])) return json(res,403,{error:'Session verification failed. Refresh and retry.'});
    if (!checkOrigin(req)) return json(res,403,{error:'Cross-origin request blocked.'});
    if (!String(req.headers['content-type'] || '').toLowerCase().startsWith('application/json')) return json(res,415,{error:'Expected application/json.'});
    if (active >= maxActive) return json(res,429,{error:'DNS diagnostics busy. Retry shortly.'});
    let config;
    try {config=validateDnsInput(await readJsonBody(req));}
    catch (error) {return json(res,400,{error:error instanceof InputError ? error.message : 'Invalid DNS diagnostic request.'});}
    // Parsing a request is asynchronous; recheck capacity before reserving it.
    if (active >= maxActive) return json(res,429,{error:'DNS diagnostics busy. Retry shortly.'});
    if (!limiter.allow({ip:requesterIp(req),host:config.fromDomain,mode:'dns'})) return json(res,429,{error:'DNS diagnostic rate limit reached. Retry later.'});
    active++;
    const controller=new AbortController();
    const cancel=()=>controller.abort();
    res.on('close',cancel);
    try {
      const result=await run({...config,selectors:config.selectors.join(',')},{signal:controller.signal});
      if (!res.destroyed && !res.writableEnded) return json(res,200,result);
    } catch {
      if (!res.destroyed && !res.writableEnded) return json(res,500,{error:'DNS diagnostics could not be completed.'});
    } finally {active--;res.off('close',cancel);}
  };
}
