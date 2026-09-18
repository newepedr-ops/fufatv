const {randomBytes,createHash,createHmac,scrypt:rawScrypt,timingSafeEqual}=require('node:crypto');
const {promisify}=require('node:util');
const scrypt=promisify(rawScrypt);
const COOKIE='__Host-fufa_session';
const digest=value=>createHash('sha256').update(value).digest('hex');
const token=()=>randomBytes(32).toString('base64url');
function fail(status,message){const e=Error(message);e.status=status;throw e;}
function password(value){if(typeof value!=='string'||value.length<12||Buffer.byteLength(value)>256)fail(400,'Пароль: от 12 символов, максимум 256 байт.');return value;}
async function hashPassword(value){password(value);const salt=randomBytes(16).toString('hex');const hash=await scrypt(value,salt,64,{N:32768,r:8,p:3,maxmem:64*1024*1024});return `scrypt$${salt}$${hash.toString('hex')}`;}
async function checkPassword(value,stored){if(typeof value!=='string'||Buffer.byteLength(value)>256)return false;const parts=(stored||'').split('$');const valid=parts.length===3&&parts[0]==='scrypt'&&/^[a-f0-9]{32}$/.test(parts[1])&&/^[a-f0-9]{128}$/.test(parts[2]);const salt=valid?parts[1]:'00000000000000000000000000000000';const hash=await scrypt(value,salt,64,{N:32768,r:8,p:3,maxmem:64*1024*1024});return valid&&timingSafeEqual(hash,Buffer.from(parts[2],'hex'));}
function email(value){const s=typeof value==='string'?value.trim().toLowerCase():'';if(s.length>254||! /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s))fail(400,'Введите корректную почту.');return s;}
function cookie(req){const found=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(COOKIE+'='));const value=found?.slice(COOKIE.length+1);return /^[A-Za-z0-9_-]{43}$/.test(value||'')?value:null;}
function setCookie(res,value){res.setHeader('Set-Cookie',`${COOKIE}=${value||''}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${value?604800:0}`);}
function originCheck(req,origin){if(req.headers.origin!==origin)fail(403,'Недопустимый источник запроса.');if(!(req.headers['content-type']||'').toLowerCase().startsWith('application/json'))fail(415,'Требуется JSON.');}
function rateKey(secret,value){return createHmac('sha256',secret).update(value).digest('hex');}
module.exports={COOKIE,digest,token,fail,password,hashPassword,checkPassword,email,cookie,setCookie,originCheck,rateKey};
