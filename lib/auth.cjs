const {randomUUID}=require('node:crypto');
const S=require('./security.cjs');
const MESSAGE='Если для этой почты доступно действие, письмо отправлено. Проверьте также папку «Спам».';
const profile=u=>({id:u.id,email:u.email,username:u.username,email_verified:true});
async function transaction(pool,fn){const c=await pool.connect();try{await c.query('BEGIN');const result=await fn(c);await c.query('COMMIT');return result;}catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}}
async function sessionUser(db,req){const raw=S.cookie(req);if(!raw)return null;const {rows}=await db.query('SELECT u.id,u.email,u.username FROM fufa_sessions s JOIN fufa_users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now() AND u.email_verified_at IS NOT NULL',[S.digest(raw)]);return rows[0]||null;}
async function requireUser(db,req){const u=await sessionUser(db,req);if(!u)S.fail(401,'Войдите в аккаунт с подтверждённой почтой.');return u;}
async function limit(db,secret,key,max){const {rows}=await db.query(`INSERT INTO fufa_rate_limits(key,hits,expires_at) VALUES($1,1,now()+interval '15 minutes') ON CONFLICT(key) DO UPDATE SET hits=CASE WHEN fufa_rate_limits.expires_at<=now() THEN 1 ELSE fufa_rate_limits.hits+1 END, expires_at=CASE WHEN fufa_rate_limits.expires_at<=now() THEN now()+interval '15 minutes' ELSE fufa_rate_limits.expires_at END RETURNING hits`,[S.rateKey(secret,key)]);if(rows[0].hits>max)S.fail(429,'Слишком много попыток. Попробуйте через 15 минут.');}
function createHandler({pool,sendMail,origin,rateSecret}){
 return async function handler(req,res){
  res.setHeader('Cache-Control','no-store, private');res.setHeader('Vary','Cookie');
  res.setHeader('X-Content-Type-Options','nosniff');
  const reply=(status,data)=>res.status(status).json(data);
  try{
   if(!origin||new URL(origin).origin!==origin||!origin.startsWith('https://')||!rateSecret||rateSecret.length<32)S.fail(503,'Сервис входа ещё не настроен.');
   const action=req.query?.action;
   if(req.method==='GET'&&action==='me'){const u=await sessionUser(pool,req);return reply(200,{user:u?profile(u):null});}
   if(req.method!=='POST'){res.setHeader('Allow','GET, POST');return reply(405,{error:'Метод не поддерживается.'});}
   S.originCheck(req,origin);
   if(Number(req.headers['content-length']||0)>8192)S.fail(413,'Слишком большой запрос.');
   const b=typeof req.body==='string'?JSON.parse(req.body):req.body;
   if(!b||typeof b!=='object'||Array.isArray(b)||Buffer.byteLength(JSON.stringify(b))>8192)S.fail(400,'Неверный запрос.');
   const allowed=['register','login','logout','verify','resend','forgot','reset','upload-access'];
   if(!allowed.includes(action))S.fail(404,'Действие не найдено.');
   // Vercel overwrites x-forwarded-for at its edge. Do not deploy behind an untrusted proxy.
   const ip=String(req.headers['x-forwarded-for']||req.socket?.remoteAddress||'unknown').split(',')[0].trim();
   await limit(pool,rateSecret,'ip:'+ip,60);
   if(action==='logout'){const t=S.cookie(req);if(t)await pool.query('DELETE FROM fufa_sessions WHERE token_hash=$1',[S.digest(t)]);S.setCookie(res,null);return reply(200,{ok:true});}
   if(action==='upload-access'){const u=await requireUser(pool,req);return reply(200,{user:profile(u)});}
   if(['register','login','resend','forgot'].includes(action)){
    const address=S.email(b.email);
    await limit(pool,rateSecret,(action==='login'?'login:':'mail:')+address,action==='login'?10:4);
    if(action==='login'){
     const {rows}=await pool.query('SELECT * FROM fufa_users WHERE email=$1',[address]);const u=rows[0];
     if(!await S.checkPassword(b.password,u?.password_hash))S.fail(401,'Неверная почта или пароль.');
     if(!u.email_verified_at)S.fail(403,'Подтвердите почту по ссылке из письма. Можно отправить письмо повторно.');
     const raw=S.token();
     await transaction(pool,async db=>{
      // Lock and recheck the password version: a concurrent reset must invalidate this login.
      const locked=(await db.query('SELECT password_hash FROM fufa_users WHERE id=$1 FOR UPDATE',[u.id])).rows[0];
      if(locked?.password_hash!==u.password_hash)S.fail(401,'Пароль изменён. Войдите снова.');
      const previous=S.cookie(req);if(previous)await db.query('DELETE FROM fufa_sessions WHERE token_hash=$1',[S.digest(previous)]);
      await db.query("INSERT INTO fufa_sessions(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval '7 days')",[S.digest(raw),u.id]);
     });
     S.setCookie(res,raw);return reply(200,{user:profile(u)});
    }
    if(action==='register'){
     const username=typeof b.username==='string'?b.username.trim():'';
     if(username.length<2||username.length>60)S.fail(400,'Имя канала: от 2 до 60 символов.');
     const hash=await S.hashPassword(b.password);
     // An existing account is never overwritten by a registration attempt.
     await pool.query('INSERT INTO fufa_users(id,email,username,password_hash) VALUES($1,$2,$3,$4) ON CONFLICT(email) DO NOTHING',[randomUUID(),address,username,hash]);
    }
    const u=(await pool.query('SELECT * FROM fufa_users WHERE email=$1',[address])).rows[0];
    const purpose=action==='forgot'?'reset':'verify';
    if(u&&((purpose==='verify'&&!u.email_verified_at)||(purpose==='reset'&&u.email_verified_at))){
     const raw=S.token(),hashed=S.digest(raw);
     await pool.query("INSERT INTO fufa_tokens(token_hash,user_id,purpose,expires_at) VALUES($1,$2,$3,now()+interval '30 minutes')",[hashed,u.id,purpose]);
     try{await sendMail(address,purpose,`${origin}/#auth=${purpose}&token=${raw}`);}catch{await pool.query('DELETE FROM fufa_tokens WHERE token_hash=$1',[hashed]);S.fail(503,'Не удалось отправить письмо. Попробуйте позже.');}
    }
    return reply(200,{message:MESSAGE});
   }
   if(action==='verify'||action==='reset'){
    if(typeof b.token!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(b.token))S.fail(400,'Ссылка недействительна или устарела.');
    const purpose=action,hashed=S.digest(b.token);
    // The mailbox owner sets the final password, preventing account pre-hijacking.
    const passwordHash=await S.hashPassword(b.password);
    await transaction(pool,async db=>{
     const t=(await db.query('SELECT user_id FROM fufa_tokens WHERE token_hash=$1 AND purpose=$2 AND expires_at>now()',[hashed,purpose])).rows[0];
     if(!t)S.fail(400,'Ссылка недействительна или устарела.');
     const owner=(await db.query('SELECT id,email_verified_at FROM fufa_users WHERE id=$1 FOR UPDATE',[t.user_id])).rows[0];
     if(!owner||(action==='verify'&&owner.email_verified_at))S.fail(400,'Почта уже подтверждена. Войдите или восстановите пароль.');
     const consumed=await db.query('DELETE FROM fufa_tokens WHERE token_hash=$1 AND purpose=$2 AND expires_at>now() RETURNING user_id',[hashed,purpose]);
     if(!consumed.rowCount)S.fail(400,'Ссылка уже использована или устарела.');
     if(action==='verify')await db.query('UPDATE fufa_users SET email_verified_at=now(),password_hash=$2 WHERE id=$1',[t.user_id,passwordHash]);
     else{await db.query('UPDATE fufa_users SET password_hash=$1 WHERE id=$2',[passwordHash,t.user_id]);await db.query('DELETE FROM fufa_sessions WHERE user_id=$1',[t.user_id]);}
     await db.query('DELETE FROM fufa_tokens WHERE user_id=$1 AND purpose=$2',[t.user_id,purpose]);
    });
    return reply(200,{message:action==='verify'?'Почта подтверждена. Теперь войдите.':'Пароль изменён. Войдите с новым паролем.'});
   }
  }catch(e){if(e.status===429)res.setHeader('Retry-After','900');return reply(e.status||503,{error:e.status?e.message:'Сервис временно недоступен. Попробуйте позже.'});}
 };
}
module.exports={createHandler,requireUser,sessionUser,transaction};

