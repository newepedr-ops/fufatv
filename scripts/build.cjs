const fs = require('node:fs');
fs.mkdirSync('public', {recursive: true});
for (const name of ['index.html','favicon.svg','favicon.ico','icon-192.png','apple-touch-icon.png']) fs.copyFileSync('site/'+name, 'public/'+name);
