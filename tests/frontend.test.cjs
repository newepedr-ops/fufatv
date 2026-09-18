const {test}=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm'),fs=require('node:fs'),path=require('node:path');
const html=fs.readFileSync(path.join(__dirname,'../site/index.html'),'utf8');
const script=html.match(/<script id="fufa-server-auth">([\s\S]*?)<\/script>/)[1];
function setup(){
 const elements=new Map(),data=new Map(),calls=[];
 function element(){return {set id(v){this._id=v;elements.set(v,this);},get id(){return this._id;},value:'',style:{},classList:{add(){},remove(){}},append(){},setAttribute(){},querySelector(){return element();},click(){return this.onclick?.();}};}
 const $=id=>{if(!elements.has(id))elements.set(id,element());return elements.get(id);};
 const c={URLSearchParams,console,state:{user:{email:'forged@example.com'}},location:{protocol:'https:',hash:'',pathname:'/',search:''},history:{replaceState(){}},persistLibrary(){},loadLibrary(){},updateAuthUI(){},defaultAvatar:'avatar',knownSessions:new Set(['forged@example.com']),readJSON(k,f){return data.has(k)?JSON.parse(data.get(k)):f;},localStorage:{setItem(k,v){data.set(k,v)},removeItem(k){data.delete(k)}},$,
  document:{createElement:element,addEventListener(){}},uiButton:'button',fieldClass:'field',isLoginMode:true,Router:{handleRoute(){},navigate(){}},showToast(){},stopLocalLive(){},stopShorts(){},adultUnlocked:false,requireUploadAccount(){return c.state.user;},persistPublication:async()=>{calls.push('published');return 'ok';},addBSide:async()=>{calls.push('bonus');},activateAccount(){},openAccounts(){},modal(){},formDialog(){},
  fetch:async(url,options)=>{calls.push({url,options});const action=new URL('https://test'+url).searchParams.get('action');return {ok:true,status:200,json:async()=>action==='me'?{user:null}:c.reply||{}};}
 };
 $('toggleAuthMode').onclick=()=>{c.isLoginMode=!c.isLoginMode;};$('uploadForm').onsubmit=async()=>calls.push('legacy');
 c.window=c;vm.createContext(c);vm.runInContext(script,c);
 return {c,$,data,calls,flush:()=>new Promise(resolve=>setImmediate(resolve)),submit:()=>$('authForm').onsubmit({preventDefault(){},target:{querySelector:element}})};
}
test('cached account cannot authenticate or publish',async()=>{const {c,flush,calls}=setup();assert.equal(c.state.user,null);await flush();assert.throws(()=>c.requireUploadAccount(),/Войдите/);await assert.rejects(c.persistPublication(),/Войдите/);assert.ok(!calls.includes('published'));});
test('registration waits for email confirmation and never creates a local session',async()=>{const t=setup();await t.flush();t.c.isLoginMode=false;t.c.reply={message:'Проверьте почту'};await t.submit();assert.equal(t.c.state.user,null);assert.equal(t.$('serverAuthStatus').textContent,'Проверьте почту');assert.ok(!t.data.has('vidora_user_session'));});
test('verified login enables upload only after fresh server authorization',async()=>{const t=setup();await t.flush();t.c.reply={user:{id:'real',email:'real@example.com',username:'Real',email_verified:true}};await t.submit();assert.equal(t.c.requireUploadAccount().email,'real@example.com');await t.c.persistPublication();assert.ok(t.calls.some(x=>x.url?.endsWith('action=upload-access')));assert.ok(t.calls.includes('published'));assert.ok(!t.data.has('vidora_user_session'));});
test('switching accounts requires login; it cannot activate cached credentials',async()=>{const t=setup();await t.flush();t.c.activateAccount('cached@example.com');assert.equal(t.c.state.user,null);assert.equal(t.$('authEmail').value,'cached@example.com');});
test('revoked session blocks upload and clears identity',async()=>{const t=setup();await t.flush();t.c.reply={user:{id:'real',email:'real@example.com',username:'Real',email_verified:true}};await t.submit();t.c.fetch=async()=>({ok:false,status:401,json:async()=>({error:'Войдите снова'})});await assert.rejects(t.c.persistPublication(),/Войдите снова/);assert.equal(t.c.state.user,null);assert.ok(!t.calls.includes('published'));});
