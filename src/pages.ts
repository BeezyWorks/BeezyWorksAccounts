const esc = (s: string) =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;')

const CSS = `body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#f5f6f8;color:#222;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}
main{background:#fff;border-radius:12px;padding:28px;max-width:380px;width:calc(100% - 32px);box-shadow:0 2px 12px rgba(0,0,0,.08)}
h1{font-size:20px;margin:0 0 12px}p{line-height:1.5}label{display:block;font-size:14px;margin:12px 0 4px}
input{width:100%;box-sizing:border-box;padding:10px;font-size:16px;border:1px solid #bbb;border-radius:6px}
button{margin-top:16px;width:100%;padding:11px;font-size:16px;border:0;border-radius:6px;background:#1f4e8c;color:#fff}
button.alt{background:#fff;color:#1f4e8c;border:1px solid #1f4e8c}.small{font-size:13px;color:#555}
button:disabled{opacity:.6}.err{color:#b00020}.ok{color:#1a7f37}`

function shell(title: string, body: string, script = ''): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>${esc(title)}</title><style>${CSS}</style></head><body><main>${body}</main>${script ? `<script>${script}</script>` : ''}</body></html>`
}

export function verifiedPage(): string {
  return shell(
    'Email verified',
    '<h1>Email verified</h1><p>Your email address is confirmed. You can return to the app and sign in.</p>',
  )
}

export function resetPasswordPage(token: string | null): string {
  if (!token) {
    return shell(
      'Reset password',
      '<h1>Reset password</h1><p class="err">This reset link is missing its token. Please request a new one from the app.</p>',
    )
  }
  // The token is echoed only into an HTML-escaped data attribute and read by the script.
  const body = `<h1>Choose a new password</h1>
<form id="f" data-token="${esc(token)}">
<label for="p">New password</label><input id="p" type="password" minlength="8" autocomplete="new-password" required>
<label for="c">Confirm password</label><input id="c" type="password" minlength="8" autocomplete="new-password" required>
<button id="b" type="submit">Reset password</button></form><p id="m" role="status"></p>`
  const script = `var f=document.getElementById('f'),m=document.getElementById('m'),b=document.getElementById('b');
f.addEventListener('submit',function(e){e.preventDefault();
var p=document.getElementById('p').value,c=document.getElementById('c').value;m.className='';
if(p!==c){m.className='err';m.textContent='Passwords do not match.';return}
b.disabled=true;
fetch('/api/auth/reset-password',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({newPassword:p,token:f.dataset.token})})
.then(function(r){return r.json().catch(function(){return{}}).then(function(d){return{ok:r.ok,d:d}})})
.then(function(x){if(x.ok){f.style.display='none';m.className='ok';m.textContent='Your password was reset. You can return to the app and sign in.'}
else{b.disabled=false;m.className='err';m.textContent=(x.d&&x.d.message)||'This link is invalid or has expired. Please request a new one.'}})
.catch(function(){b.disabled=false;m.className='err';m.textContent='Network error. Please try again.'})});`
  return shell('Reset password', body, script)
}

/**
 * Both OAuth pages are reached from /api/auth/oauth2/authorize with a signed query (client_id, redirect_uri,
 * scope, sig, ...). The pages never trust it: they only forward the signed parameters as `oauth_query`, which the
 * server verifies, and write everything they show with textContent.
 */
const OAUTH_QUERY_JS = `function oq(){var p=new URLSearchParams(location.search),n=p.getAll('ba_param'),o=new URLSearchParams();
if(!p.has('sig')||!n.length)return;p.forEach(function(v,k){if(k==='sig'||k==='ba_param'||n.indexOf(k)>-1)o.append(k,v)});return o.toString()}
function post(path,body){return fetch(path,{method:'POST',headers:{'content-type':'application/json'},credentials:'same-origin',body:JSON.stringify(body)})
.then(function(r){return r.json().catch(function(){return{}}).then(function(d){return{ok:r.ok,d:d}})})}
function go(d){var u=d&&(d.url||d.redirect_uri);if(u){location.href=u;return true}return false}
var q=new URLSearchParams(location.search),m=document.getElementById('m'),who=document.getElementById('who');
function fail(t){m.className='err';m.textContent=t}`

export function oauthSignInPage(): string {
  const body = `<h1>Sign in to Baderech</h1>
<p id="who"></p>
<form id="f">
<label for="e">Email</label><input id="e" type="email" autocomplete="username" required>
<label for="p">Password</label><input id="p" type="password" autocomplete="current-password" required>
<button id="b" type="submit">Sign in</button></form><p id="m" role="status"></p>
<p class="small">Use the same account you use in the Siddur or Beitecha. Forgot your password? Reset it from the app, then come back.</p>`
  const script = `${OAUTH_QUERY_JS}
var b=document.getElementById('b'),f=document.getElementById('f');
if(!oq())fail('This sign-in link is not valid. Please start again from the app that sent you here.');
else if(q.get('client_id'))post('/api/auth/oauth2/public-client-prelogin',{client_id:q.get('client_id'),oauth_query:oq()}).then(function(x){
if(x.ok&&x.d&&x.d.client_name)who.textContent='Signing in for '+x.d.client_name+'.'});
f.addEventListener('submit',function(e){e.preventDefault();m.className='';m.textContent='';
if(!oq())return fail('This sign-in link is not valid. Please start again from the app that sent you here.');
b.disabled=true;
post('/api/auth/sign-in/email',{email:document.getElementById('e').value,password:document.getElementById('p').value,oauth_query:oq()})
.then(function(x){if(x.ok&&go(x.d))return;b.disabled=false;
fail((x.d&&x.d.message)||'We could not sign you in. Check your email and password.')})
.catch(function(){b.disabled=false;fail('Network error. Please try again.')})});`
  return shell('Sign in', body, script)
}

export function oauthConsentPage(): string {
  const body = `<h1>Allow access?</h1>
<p><strong id="name">An app</strong> wants to manage your shul's notices in Beitecha.</p>
<p class="small">It can read your shul's schedule and add or change notices, such as sponsorships, on your behalf. You can revoke it any time in Beitecha. It will return you to <strong id="host">its own site</strong>.</p>
<p class="small">Only allow this if you just asked this app to connect to Beitecha.</p>
<button id="a" type="button">Allow</button><button id="d" type="button" class="alt">Deny</button><p id="m" role="status"></p>`
  const script = `${OAUTH_QUERY_JS}
var a=document.getElementById('a'),d=document.getElementById('d');
try{document.getElementById('host').textContent=new URL(q.get('redirect_uri')).host}catch(e){}
if(!oq()){a.disabled=d.disabled=true;fail('This link is not valid. Please start again from the app.')}
else fetch('/api/auth/oauth2/public-client?client_id='+encodeURIComponent(q.get('client_id')||''),{credentials:'same-origin'})
.then(function(r){return r.ok?r.json():null}).then(function(c){if(c&&c.client_name)document.getElementById('name').textContent=c.client_name}).catch(function(){});
function answer(ok){a.disabled=d.disabled=true;m.className='';m.textContent='';
post('/api/auth/oauth2/consent',{accept:ok,oauth_query:oq()}).then(function(x){if(x.ok&&go(x.d))return;
a.disabled=d.disabled=false;fail((x.d&&x.d.message)||'Something went wrong. Please start again from the app.')})
.catch(function(){a.disabled=d.disabled=false;fail('Network error. Please try again.')})}
a.addEventListener('click',function(){answer(true)});d.addEventListener('click',function(){answer(false)});`
  return shell('Allow access', body, script)
}
