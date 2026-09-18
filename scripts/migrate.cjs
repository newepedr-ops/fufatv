const {Pool}=require('pg');
const fs=require('node:fs');
if(!process.env.DATABASE_URL) throw Error('Set DATABASE_URL in your environment');
const pool=new Pool({connectionString:process.env.DATABASE_URL, connectionTimeoutMillis:10000});
(async()=>{try{await pool.query(fs.readFileSync('schema.sql','utf8'));console.log('Schema ready');}finally{await pool.end();}})().catch(()=>{console.error('Migration failed. Check database connection and permissions.');process.exitCode=1;});
