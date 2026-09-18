const {Pool}=require('pg');
const {createHandler}=require('../lib/auth.cjs');
let pool;
module.exports=async(req,res)=>{
 if(!process.env.DATABASE_URL||!process.env.RESEND_API_KEY||!process.env.MAIL_FROM){res.setHeader('Cache-Control','no-store');return res.status(503).json({error:'Сервис входа ещё не настроен владельцем сайта.'});}
 pool ||= new Pool({connectionString:process.env.DATABASE_URL,max:3,idleTimeoutMillis:10000,connectionTimeoutMillis:5000,statement_timeout:10000,allowExitOnIdle:true});
 const sendMail=async(to,purpose,url)=>{
  const reset=purpose==='reset';
  const response=await fetch('https://api.resend.com/emails',{method:'POST',signal:AbortSignal.timeout(10000),headers:{Authorization:`Bearer ${process.env.RESEND_API_KEY}`,'Content-Type':'application/json'},body:JSON.stringify({from:process.env.MAIL_FROM,to:[to],subject:reset?'ФУФА ТВ — восстановление пароля':'ФУФА ТВ — подтвердите почту',text:`${reset?'Изменить пароль':'Подтвердить почту'}: ${url}\n\nСсылка действует 30 минут. Если вы не отправляли запрос, проигнорируйте это письмо.`})});
  if(!response.ok)throw Error('Mail delivery failed');
 };
 return createHandler({pool,sendMail,origin:process.env.APP_ORIGIN,rateSecret:process.env.RATE_LIMIT_SECRET})(req,res);
};

