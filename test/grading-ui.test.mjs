import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFileSync} from 'node:fs';
import {gradeConnection} from '../src/grading.mjs';
class Element {
  constructor(){this.children=[];this.textContent='';this.className='';this.classes=new Set();this.classList={add:x=>this.classes.add(x),remove:x=>this.classes.delete(x),toggle:(x,on)=>on?this.classes.add(x):this.classes.delete(x)};}
  append(...children){this.children.push(...children);}
  replaceChildren(...children){this.children=children;}
  addEventListener(){}
}
function setup() {
  const elements=new Map();
  const context=vm.createContext({document:{getElementById:id=>{if(!elements.has(id)) elements.set(id,new Element());return elements.get(id);},createElement:()=>new Element()},window:{addEventListener(){}},fetch:()=>new Promise(()=>{}),setTimeout,console});
  vm.runInContext(readFileSync(new URL('../public/app.js',import.meta.url),'utf8'),context);
  return {context,elements};
}
const text=el=>[el.textContent,...el.children.map(text)].join(' ');
test('scorecard renders findings as text and report exports the same assessment',()=>{
  const {context,elements}=setup();
  const malicious='<script>alert(1)</script>';
  const grading=gradeConnection({tlsMode:'none'},{ok:true,capabilities:['AUTH '+malicious]},{tcp:'pass',greeting:'pass',ehlo:'pass',plaintextAuth:true});
  context.fixture={ok:true,message:'Verified',grading};
  vm.runInContext('showDetails(fixture); lastResult=fixture;',context);
  const panel=elements.get('grading');
  assert.ok(!panel.classes.has('hidden'));
  assert.match(text(panel),/SECURITY & CONNECTIVITY/);
  assert.match(text(panel),/NOT TESTED/);
  assert.ok(text(panel).includes(malicious.toUpperCase()));
  assert.match(text(panel),/Connectivity: Passed/);
  const report=vm.runInContext('reportText()',context);
  assert.match(report,/Security grade: F/);
  assert.match(report,/SMTP Probe policy v1/);
  assert.match(report,/AUTH before TLS: WARN/);
  assert.match(report,/Scope: This connection only/);
});
test('new run clears previous grading and absent grading remains hidden',()=>{
  const {context,elements}=setup();
  vm.runInContext('showGrading(null)',context);
  assert.ok(elements.get('grading').classes.has('hidden'));
  assert.equal(elements.get('grading').children.length,0);
});


test('DNS cards and report safely display DNS text with explicit scope and identities',()=>{
 const {context,elements}=setup();
 const malicious='<script>alert(1)</script>';
 context.dnsFixture={schemaVersion:1,checkedAt:'2026-10-24T12:00:00Z',input:{fromDomain:'example.com',envelopeDomain:null,dkimDomain:null},scope:'DNS only; no message verification.',
  spf:{domain:'example.com',status:'warning',lookupTerms:1,incomplete:false,findings:[],nodes:[{domain:'example.com',records:[malicious],findings:[]}]},
  dmarc:{policyDomain:null,organizationalDomain:'example.com',policy:null,status:'error',discovery:[],findings:[{level:'error',message:malicious}]},
  dkim:{domain:'example.com',status:'not-tested',selectors:[],findings:[]},alignment:[{kind:'SPF',status:'not-tested',detail:'No identity supplied.'}],queries:[{name:'example.com',status:'ok'}]};
 vm.runInContext('showDnsResults(dnsFixture); lastDnsResult=dnsFixture;',context);
 assert.ok(!elements.get('dns-results').classes.has('hidden'));
 assert.ok(text(elements.get('dns-results')).includes(malicious));
 const report=vm.runInContext('dnsReportText()',context);
 assert.match(report,/SPF · example.com: WARNING/);
 assert.match(report,/DKIM · example.com: NOT-TESTED/);
 assert.match(report,/SPF: NOT-TESTED/);
 assert.match(report,/MAIL FROM: Not supplied/);
 assert.ok(report.includes(malicious));
 vm.runInContext('showDnsResults(null);lastDnsResult=null;',context);
 assert.ok(elements.get('dns-results').classes.has('hidden'));assert.equal(vm.runInContext('dnsReportText()',context),'');
});
