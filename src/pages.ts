const esc = (s: string) =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;')

const CSS = `body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#f5f6f8;color:#222;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}
main{background:#fff;border-radius:12px;padding:28px;max-width:380px;width:calc(100% - 32px);box-shadow:0 2px 12px rgba(0,0,0,.08)}
h1{font-size:20px;margin:0 0 12px}p{line-height:1.5}label{display:block;font-size:14px;margin:12px 0 4px}
input{width:100%;box-sizing:border-box;padding:10px;font-size:16px;border:1px solid #bbb;border-radius:6px}
button{margin-top:16px;width:100%;padding:11px;font-size:16px;border:0;border-radius:6px;background:#1f4e8c;color:#fff}
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
