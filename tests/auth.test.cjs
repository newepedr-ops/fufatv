const {test}=require('node:test');
const assert=require('node:assert/strict');
const S=require('../lib/security.cjs');
const {createHandler,requireUser}=require('../lib/auth.cjs');
const origin='https://fufatv.vercel.app';
function response(){return {headers:{},setHeader(k,v){this.headers[k]=v;},status(n){this.code=n;return this;},json(v){this.body=v;return this;}};}
function request(action,body={},extra={}){return {method:'POST',query:{action},headers:{origin,'content-type':'application/json','x-forwarded-for':'192.0.2.1'},body,...extra};}
function handler(pool){return createHandler({pool,sendMail:async()=>{},origin,rateSecret:'a'.repeat(64)});}
const rates={query:async sql=>{assert.match(sql,/INSERT INTO fufa_rate_limits/);return {rows:[{hits:1}]};}};
test('passwords are salted; correct password only; malformed stored hash fails closed',async()=>{
 const a=await S.hashPassword('my long password!'),b=await S.hashPassword('my long password!');assert.notEqual(a,b);
 assert.equal(await S.checkPassword('my long password!',a),true);assert.equal(await S.checkPassword('wrong password',a),false);assert.equal(await S.checkPassword('my long password!','corrupt'),false);
 await assert.rejects(S.hashPassword('short'));await assert.rejects(S.hashPassword('а'.repeat(200)));
});
test('session cookies are host-only, HttpOnly and Secure; raw tokens not used as DB keys',()=>{const r=response(),t=S.token();S.setCookie(r,t);assert.match(r.headers['Set-Cookie'],/HttpOnly; Secure; SameSite=Lax/);assert.ok(!r.headers['Set-Cookie'].includes('Domain='));assert.notEqual(S.digest(t),t);assert.equal(S.cookie({headers:{cookie:`${S.COOKIE}=${t}`}}),t);assert.equal(S.cookie({headers:{cookie:`${S.COOKIE}=forged`}}),null);});
test('cross-origin POST and non-JSON fail before database access',async()=>{const h=handler({query(){throw Error('Should not access database');}});for(const headers of [{origin:'https://evil.test','content-type':'application/json'},{origin}]){const r=response();await h(request('login',{}, {headers}),r);assert.ok([403,415].includes(r.code));}});
test('forged body account does not authorize guest uploads',async()=>{const r=response();await handler(rates)(request('upload-access',{user:{id:'fake',email_verified:true}}),r);assert.equal(r.code,401);});
test('GET me is unauthenticated without a valid session cookie',async()=>{const r=response();await handler(rates)(request('me',{}, {method:'GET'}),r);assert.deepEqual(r.body,{user:null});assert.equal(r.headers['Cache-Control'],'no-store, private');});
test('expired or unknown cookie is rejected using server session lookup',async()=>{let checked=false;const db={query:async(sql,values)=>{checked=true;assert.match(sql,/expires_at>now\(\).*email_verified_at IS NOT NULL/);assert.equal(values[0],S.digest(token));return {rows:[]};}};const token=S.token();await assert.rejects(requireUser(db,{headers:{cookie:`${S.COOKIE}=${token}`}}),e=>e.status===401);assert.ok(checked);});
test('verified server session permits upload access; body identity is ignored',async()=>{const u={id:'server-id',email:'real@example.com',username:'Real'};const db={query:async sql=>sql.includes('fufa_rate_limits')?{rows:[{hits:1}]}:{rows:[u]}};const req=request('upload-access',{email:'fake@example.com'});req.headers.cookie=`${S.COOKIE}=${S.token()}`;const r=response();await handler(db)(req,r);assert.equal(r.code,200);assert.equal(r.body.user.email,u.email);});
test('persistent limiter blocks excessive attempts',async()=>{const r=response();await handler({query:async()=>({rows:[{hits:61}]})})(request('login'),r);assert.equal(r.code,429);assert.equal(r.headers['Retry-After'],'900');});
test('invalid verification token cannot reach token SQL',async()=>{const r=response();await handler(rates)(request('verify',{token:'bad'}),r);assert.equal(r.code,400);});
test('missing configuration fails closed',async()=>{const r=response();await createHandler({pool:rates})(request('login'),r);assert.equal(r.code,503);});
test('logout revokes the server session and clears browser cookie',async()=>{let removed=false;const raw=S.token(),r=response(),req=request('logout');req.headers.cookie=`${S.COOKIE}=${raw}`;const db={query:async(sql,p)=>{if(sql.startsWith('DELETE')){removed=true;assert.equal(p[0],S.digest(raw));return {};}return {rows:[{hits:1}]};}};await handler(db)(req,r);assert.equal(r.code,200);assert.ok(removed);assert.match(r.headers['Set-Cookie'],/Max-Age=0/);});
