// Test-only TLS certificate. Generated locally so no private key is distributed or committed.
import {execFileSync} from 'node:child_process';
import {mkdirSync,chmodSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const folder=path.join(path.dirname(fileURLToPath(import.meta.url)),'fixtures');
mkdirSync(folder,{recursive:true});
const key=path.join(folder,'smtp-test.key');
const cert=path.join(folder,'smtp-test.crt');
try {
  execFileSync('openssl',[
    'req','-x509','-newkey','rsa:2048','-nodes','-days','365',
    '-keyout',key,'-out',cert,'-subj','/CN=smtp.mock.example',
    '-addext','subjectAltName=DNS:smtp.mock.example',
    '-addext','basicConstraints=critical,CA:TRUE',
    '-addext','keyUsage=digitalSignature,keyEncipherment,keyCertSign'
  ],{stdio:'ignore'});
  chmodSync(key,0o600);
  console.log('Generated a disposable, local-only TLS certificate for the tests.');
} catch (e) {
  console.error('Could not generate test certificate. OpenSSL CLI is required for npm test.');
  process.exit(1);
}
