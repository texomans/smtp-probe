// Launched by tls.test.mjs in a fresh Node process that trusts the test-only certificate.
import { runSmtpTest } from '../../src/smtp.mjs';
const secret = 'a-unique-secret-password';
const username = 'smtp-tester';
const config = {
  host:process.env.MOCK_HOST || 'smtp.mock.example',port:Number(process.env.MOCK_PORT),tlsMode:process.env.MOCK_TLS,
  mode:process.env.MOCK_MODE || 'verify', username,password:secret,
  authMethod: process.env.MOCK_AUTH || 'auto',
  from:'sender@example.net',to:'recipient@example.net',subject:'SMTP Probe test',message:'Hello from test.\n.Line beginning with dot.'
};
const events=[];
const result=await runSmtpTest(config,{address:'127.0.0.1',family:4,host:process.env.MOCK_HOST || 'smtp.mock.example'},e=>events.push(e));
console.log(JSON.stringify({result,events}));
