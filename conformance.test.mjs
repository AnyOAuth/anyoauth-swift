import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
const command = process.argv.slice(2);
if (!command.length) throw new Error('Usage: node conformance.test.mjs <runner> [runner arguments...] (cwd is preserved)');
let count = 0;
const exercised = new Set();
function invoke(action, params = {}, config = {}) {
  const p = spawnSync(command[0], command.slice(1), {input: JSON.stringify({action, params, ...config}), encoding: 'utf8'});
  assert.equal(p.status, 0, p.stderr || String(p.error));
  const result = JSON.parse(p.stdout);
  count++;
  return result;
}
function ok(action, params, config) { const r = invoke(action, params, config); assert.equal(r.ok, true, JSON.stringify(r)); exercised.add(action); return r.result; }
function bad(action, params, config) { const r = invoke(action, params, config); assert.equal(r.ok, false, JSON.stringify(r)); assert.equal(r.error.status, 0); assert.equal(typeof r.error.code, 'string'); assert.equal(typeof r.error.message, 'string'); return r.error; }
const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
assert.equal(ok('pkceChallenge', {codeVerifier: verifier}), challenge);
for (const v of ['a'.repeat(42), 'a'.repeat(129), 'é'.repeat(43), verifier + '\n', '!'.repeat(43)]) bad('pkceChallenge', {codeVerifier: v});
const first = ok('createTransaction'), second = ok('createTransaction');
for (const t of [first, second]) {
  assert.match(t.state, /^[A-Za-z0-9_-]{43}$/); assert.match(t.codeVerifier, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(t.codeChallenge, createHash('sha256').update(t.codeVerifier).digest('base64url'));
  assert(Number.isInteger(t.createdAt)); assert.equal(t.expiresAt - t.createdAt, 600);
  assert(Math.abs(t.createdAt - Math.floor(Date.now() / 1000)) < 10);
}
assert.notEqual(first.state, second.state); assert.notEqual(first.codeVerifier, second.codeVerifier); assert.notEqual(first.state, first.codeVerifier);
const state = 'state with + & % / ü';
const redirectUri = 'https://backend.example/a%2Fb';
const auth = {provider: 'google', redirectUri, state, codeChallenge: challenge};
const url = new URL(ok('authorizationUrl', auth, {clientId: 'id +&%/ü'}));
assert.equal(url.pathname, '/authorize'); assert.equal(url.searchParams.get('client_id'), 'id +&%/ü');
assert.equal(url.searchParams.get('redirect_uri'), redirectUri); assert.equal(url.searchParams.get('state'), state);
assert.equal(url.searchParams.get('code_challenge'), challenge); assert.equal(url.searchParams.get('code_challenge_method'), 'S256'); assert.equal(url.searchParams.get('response_type'), 'code');
assert.equal([...url.searchParams].length, 7);
ok('authorizationUrl', {...auth, provider: 'github'});
for (const changes of [{provider: 'other'}, {state: 'short'}, {state: 'a'.repeat(513)}, {codeChallenge: 'a'.repeat(42)}, {codeChallenge: challenge + '\n'}]) bad('authorizationUrl', {...auth, ...changes});
bad('authorizationUrl', auth, {clientId: ''});
for (const unsafe of ['http://public.example', 'https://user:pass@example.com', 'https://example.com/path', 'https://example.com?x=1', 'https://example.com#x', 'javascript:alert(1)', 'https://example.com\\evil', 'https://example.com:0', 'https://example.com:65536', 'https://%65xample.com', 'https://example.com/%2F']) bad('authorizationUrl', auth, {baseUrl: unsafe});
for (const unsafe of ['myapp://callback', 'http://public.example/cb', 'https://user@example.com/cb', 'https://example.com/cb?x=1', 'https://example.com/cb#x', 'https://example.com/cb\\x']) bad('authorizationUrl', {...auth, redirectUri: unsafe});
for (const loopback of ['http://localhost:8787', 'http://127.0.0.1:8787', 'http://[::1]:8787']) ok('authorizationUrl', {...auth, redirectUri: loopback + '/cb'}, {baseUrl: loopback});
const expiry = Math.floor(Date.now() / 1000) + 600;
const callback = {redirectUri, state, expiresAt: expiry, callbackUrl: redirectUri + '?state=' + encodeURIComponent(state) + '&code=a%2Bb%252F'};
assert.deepEqual(ok('validateCallback', callback), {state, code: 'a+b%2F'});
assert.deepEqual(ok('validateCallback', {...callback, callbackUrl: redirectUri + '?state=' + encodeURIComponent(state) + '&error=access_denied'}), {state, error:'access_denied'});
assert.equal(bad('validateCallback', {...callback, state: 'wrong'}).code, 'state_mismatch');
assert.equal(bad('validateCallback', {...callback, expiresAt: 1}).code, 'transaction_expired');
for (const tail of ['&state=again', '&%73tate=again', '&code=second', '&%63ode=second', '&error=denied', '&x=1&x=2']) bad('validateCallback', {...callback, callbackUrl:callback.callbackUrl + tail});
for (const query of ['state=' + encodeURIComponent(state), 'state=' + encodeURIComponent(state) + '&code=', 'state=' + encodeURIComponent(state) + '&error=', 'code=x', 'state=' + encodeURIComponent(state) + '&code=%FF', 'state=' + encodeURIComponent(state) + '&code=%ZZ']) bad('validateCallback', {...callback, callbackUrl:redirectUri + '?' + query});
bad('validateCallback', {...callback, callbackUrl:redirectUri + '?'});
for (const invalid of [callback.callbackUrl + '#fragment', callback.callbackUrl.replace('/a%2Fb', '/a/b'), callback.callbackUrl.replace('backend.example', 'evil.example')]) bad('validateCallback', {...callback, callbackUrl:invalid});
bad('validateCallback', {...callback, expiresAt: 1.5});
for (const action of ['exchangeCode', 'profile', 'revoke', 'providers']) assert.equal(bad(action).code, 'unsupported_action');
const malformed = spawnSync(command[0], command.slice(1), {input:'[]', encoding:'utf8'});
assert.equal(malformed.status, 0, malformed.stderr); assert.equal(JSON.parse(malformed.stdout).ok, false);
console.log('Passed ' + count + ' local protocol cases plus malformed-input check');
const expected = ['authorizationUrl','createTransaction','pkceChallenge','validateCallback'];
assert.deepEqual([...exercised].sort(),expected,'100% public helper execution');
if (process.env.SDK_COVERAGE_REPORT) writeFileSync(process.env.SDK_COVERAGE_REPORT,JSON.stringify({kind:'method-execution',expected,exercised:[...exercised].sort(),percent:100,cases:count+1})+'\n');
