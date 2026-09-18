const {test}=require('node:test');
const assert=require('node:assert/strict');
const {createHandler}=require('../lib/auth.cjs');
const S=require('../lib/security.cjs');
// Behavioral DB double. Real PostgreSQL migration/concurrency tests need a configured database.
function database(){
 const users=new Map(),tokens=new Map(),sessions=new Map();
 const result=rows=>({rows,rowCount:rows.length});
 const db={users,tokens,sessions,async connect(){return {...db,release(){}};},async query(sql,p=[]){
  if(['BEGIN','COMMIT','ROLLBACK'].includes(sql))return result([]);
  if(sql.includes('INSERT INTO fufa_rate_limits'))return result([{hits:1}]);
  if(sql.startsWith('INSERT INTO fufa_users')){if(![...users.values()].some(u=>u.email===p[1]))users.set(p[0],{id:p[0],email:p[1],username:p[2],password_hash:p[3],email_verified_at:null});return result([]);}
  if(sql==='SELECT * FROM fufa_users WHERE email=$1')return result([...users.values()].filter(u=>u.email===p[0]).map(u=>({...u})));
  if(sql.includes('FROM fufa_users WHERE id=$1 FOR UPDATE'))return result(users.has(p[0])?[{...users.get(p[0])}]:[]);
  if(sql.startsWith('INSERT INTO fufa_tokens')){tokens.set(p[0],{user_id:p[1],purpose:p[2],expires_at:Date.now()+1800000});return result([]);}
  if(sql.startsWith('SELECT user_id FROM fufa_tokens')){const t=tokens.get(p[0]);return result(t&&t.purpose===p[1]&&t.expires_at>Date.now()?[{user_id:t.user_id}]:[]);}
  if(sql.startsWith('DELETE FROM fufa_tokens WHERE token_hash=')){const t=tokens.get(p[0]);if(!t||(p[1]&&(t.purpose!==p[1]||t.expires_at<=Date.now())))return result([]);tokens.delete(p[0]);return result([{user_id:t.user_id}]);}
  if(sql.startsWith('DELETE FROM fufa_tokens WHERE user_id=')){for(const [key,t]of tokens)if(t.user_id===p[0]&&t.purpose===p[1])tokens.delete(key);return result([]);}
  if(sql.startsWith('UPDATE fufa_users SET email_verified_at=')){Object.assign(users.get(p[0]),{email_verified_at:new Date(),password_hash:p[1]});return result([]);}
  if(sql.startsWith('UPDATE fufa_users SET password_hash=')){users.get(p[1]).password_hash=p[0];return result([]);}
  if(sql.startsWith('INSERT INTO fufa_sessions')){sessions.set(p[0],{user_id:p[1],expires_at:Date.now()+604800000});return result([]);}
  if(sql.startsWith('DELETE FROM fufa_sessions WHERE token_hash=')){sessions.delete(p[0]);return result([]);}
  if(sql.startsWith('DELETE FROM fufa_sessions WHERE user_id=')){for(const [key,s]of sessions)if(s.user_id===p[0])sessions.delete(key);return result([]);}
  if(sql.startsWith('SELECT u.id,u.email,u.username FROM fufa_sessions')){const s=sessions.get(p[0]),u=s&&users.get(s.user_id);return result(s&&s.expires_at>Date.now()&&u.email_verified_at?[{...u}]:[]);}
  throw Error('Unhandled test SQL: '+sql);
 }};return db;
}
test('registration → confirmation → login → reset; tokens one-use, session revocation, pre-hijack protection',async()=>{
 const db=database(),mail=[],origin='https://fufatv.vercel.app';
 const h=createHandler({pool:db,origin,rateSecret:'x'.repeat(64),sendMail:async(email,purpose,url)=>mail.push({email,purpose,token:new URLSearchParams(url.split('#')[1]).get('token')})});
 async function call(action,body={},cookie){const r={headers:{},setHeader(k,v){this.headers[k]=v},status(n){this.code=n;return this},json(b){this.body=b}};await h({method:action==='me'?'GET':'POST',query:{action},headers:{origin,'content-type':'application/json',cookie},body},r);return r;}
 const email='owner@example.com',attackerPassword='attacker knows this',password='real owner password',newPassword='new owner password';
 assert.equal((await call('register',{email:'OWNER@example.com',username:'Owner',password:attackerPassword})).code,200);
 const pending=[...db.users.values()][0];assert.equal(pending.email,email);assert.equal(pending.email_verified_at,null);assert.notEqual(pending.password_hash,attackerPassword);
 assert.equal((await call('login',{email,password:attackerPassword})).code,403,'unconfirmed email cannot sign in');
 assert.equal((await call('register',{email,username:'Replacement',password})).code,200);
 assert.equal([...db.users.values()][0].username,'Owner','duplicate registration does not replace account');
 const t=mail.at(-1).token;
 assert.equal(db.tokens.has(t),false,'only hashed tokens stored');
 assert.equal((await call('verify',{token:t,password})).code,200);
 assert.equal((await call('verify',{token:t,password})).code,400,'one-use token');
 assert.equal((await call('login',{email,password:attackerPassword})).code,401,'pre-registration password no longer works');
 const login=await call('login',{email,password});assert.equal(login.code,200);assert.equal(login.body.user.email_verified,true);assert.equal(login.body.user.password_hash,undefined);
 const cookie=login.headers['Set-Cookie'].split(';')[0];
 assert.equal((await call('me',{},cookie)).body.user.email,email);
 assert.equal((await call('upload-access',{},cookie)).code,200);
 assert.equal((await call('forgot',{email})).code,200);
 const reset=mail.at(-1).token;
 assert.equal((await call('reset',{token:reset,password:newPassword})).code,200);
 assert.equal((await call('me',{},cookie)).body.user,null,'old sessions revoked');
 assert.equal((await call('upload-access',{},cookie)).code,401);
 assert.equal((await call('reset',{token:reset,password:newPassword})).code,400);
 assert.equal((await call('login',{email,password})).code,401);
 assert.equal((await call('login',{email,password:newPassword})).code,200);
 await call('forgot',{email});const expired=mail.at(-1).token;db.tokens.get(S.digest(expired)).expires_at=0;
 assert.equal((await call('reset',{token:expired,password})).code,400,'expired reset link rejected');
 const before=mail.length;const unknown=await call('forgot',{email:'unknown@example.com'});assert.equal(unknown.code,200);assert.equal(mail.length,before,'unknown email does not send mail');
});
