export default {
  async fetch(request, env) {
    return handleRequest(request, env);
  }
};

const INDEX_KEY = "__index__";
const SESSION_KEY_PREFIX = "note_session_";

const SECURITY_HEADERS = {
  "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; object-src 'none';",
  "X-Frame-Options": "DENY",
  "X-Content-Type-Options": "nosniff",
};

function getSafeCookieName(name) {
  let hash = 0;
  const str = String(name || "");
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  const hashHex = Math.abs(hash).toString(36).padStart(12, '0').slice(0, 12);
  return `note_auth_${hashHex}`;
}

function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;
  cookieHeader.split(';').forEach(part => {
    const [name, ...valueParts] = part.trim().split('=');
    if (name) {
      cookies[name.trim()] = decodeURIComponent(valueParts.join('=').trim());
    }
  });
  return cookies;
}

function htmlEscape(str) {
  if (typeof str !== "string") return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...SECURITY_HEADERS, ...extraHeaders }
  });
}

async function handleRequest(request, env) {
  try {
    let url = new URL(request.url);

    if (url.pathname === "/favicon.ico") return new Response(null, { status: 404 });

    let noteName;
    try { 
      noteName = decodeURIComponent(url.pathname.slice(1)) || generateRandomNote(); 
    } catch(e){ 
      noteName = generateRandomNote(); 
    }

    function isValidNoteName(name){
      if(!name || name.length > 50 || name.length === 0) return false;
      if(/[-\u001F\u007F\/\\]/.test(name)) return false;
      return true;
    }

    if(!isValidNoteName(noteName) && url.pathname !== "/"){
      return new Response(`<script>alert("笔记名非法");history.back();</script>`, 
        { headers:{ "Content-Type":"text/html;charset=UTF-8", ...SECURITY_HEADERS } });
    }

    const method = request.method;
    const isRaw = url.searchParams.has("raw");

    // ==========================================
    // 1. 删除接口 (主页调用)
    // ==========================================
    if (method === "DELETE") {
      const existingNote = await env.NOTES_KV.get(noteName);
      if (!existingNote) return jsonResponse({ error: "笔记不存在" }, 404);
      
      const noteObj = JSON.parse(existingNote);
      
      // 加密笔记权限校验
      if (noteObj.encrypted) {
        const kvSessionKey = `${SESSION_KEY_PREFIX}${noteName}`;
        const cookieName = getSafeCookieName(noteName);
        const cookies = parseCookies(request.headers.get("Cookie") || "");
        const sessionToken = cookies[cookieName];
        const storedToken = await env.NOTES_KV.get(kvSessionKey);

        if(!sessionToken || sessionToken !== storedToken) {
          return jsonResponse({ error: "需要密码验证", requiresPassword: true }, 401);
        }
      }

      await env.NOTES_KV.delete(noteName);
      await updateIndex(noteName, null, env);
      await env.NOTES_KV.delete(`${SESSION_KEY_PREFIX}${noteName}`).catch(()=>{});

      return jsonResponse({ success: true });
    }

    // ==========================================
    // 2. 重命名接口 (主页调用)
    // ==========================================
    if (method === "POST" && url.searchParams.get("action") === "rename") {
      const formData = await request.formData();
      const oldName = formData.get("oldName");
      const newName = formData.get("newName");

      if (!oldName || !newName || !isValidNoteName(newName)) {
        return jsonResponse({ error: "新名称非法（不允许包含 - / \\ 等特殊字符，长度1-50）" }, 400);
      }

      const oldNote = await env.NOTES_KV.get(oldName);
      if (!oldNote) return jsonResponse({ error: "原笔记不存在" }, 404);

      const oldObj = JSON.parse(oldNote);

      if (oldName !== newName && await env.NOTES_KV.get(newName)) {
        return jsonResponse({ error: "该名称已被使用，请换一个" }, 409);
      }

      let headers = {};
      if (oldObj.encrypted) {
        const kvSessionKey = `${SESSION_KEY_PREFIX}${oldName}`;
        const cookieName = getSafeCookieName(oldName);
        const cookies = parseCookies(request.headers.get("Cookie") || "");
        const sessionToken = cookies[cookieName];
        const storedToken = await env.NOTES_KV.get(kvSessionKey);

        if(!sessionToken || sessionToken !== storedToken) {
          return jsonResponse({ error: "需要密码验证", requiresPassword: true }, 401);
        }

        const newCookieName = getSafeCookieName(newName);
        await env.NOTES_KV.put(`${SESSION_KEY_PREFIX}${newName}`, storedToken, { expirationTtl: 3600 });
        headers["Set-Cookie"] = `${newCookieName}=${storedToken}; Path=/; Max-Age=3600; Secure; SameSite=Strict`;
      }

      await env.NOTES_KV.put(newName, oldNote);
      await env.NOTES_KV.delete(oldName);
      await updateIndex(oldName, null, env);
      await updateIndex(newName, { created_at: oldObj.created_at, updated_at: oldObj.updated_at, encrypted: oldObj.encrypted }, env);

      return jsonResponse({ success: true, newName }, 200, headers);
    }

    // ==========================================
    // 3. 密码验证接口
    // ==========================================
    if(method === "POST" && url.searchParams.has("password")) {
      const formData = await request.formData();
      const password = formData.get("password");

      if(password === (env.FIXED_PASSWORD || "")) {
        const sessionToken = crypto.randomUUID();
        const kvSessionKey = `${SESSION_KEY_PREFIX}${noteName}`;
        const cookieName = getSafeCookieName(noteName);

        await env.NOTES_KV.put(kvSessionKey, sessionToken, { expirationTtl: 3600 });

        return jsonResponse({ success: true }, 200, {
          "Set-Cookie": `${cookieName}=${sessionToken}; Path=/; Max-Age=3600; Secure; SameSite=Strict`
        });
      } else {
        return jsonResponse({ success: false, error: "密码错误" }, 401);
      }
    }

    // ==========================================
    // 4. 保存/清空笔记接口
    // ==========================================
    if(method === "POST") {
      const text = await request.text();
      const encryptedFlag = url.searchParams.get("encrypt") === "1";

      const existingNote = await env.NOTES_KV.get(noteName);
      let existingObj = existingNote ? JSON.parse(existingNote) : null;
      
      if (existingObj && existingObj.encrypted) {
        const kvSessionKey = `${SESSION_KEY_PREFIX}${noteName}`;
        const cookieName = getSafeCookieName(noteName);
        const cookies = parseCookies(request.headers.get("Cookie") || "");
        const sessionToken = cookies[cookieName];
        const storedToken = await env.NOTES_KV.get(kvSessionKey);

        if(!sessionToken || sessionToken !== storedToken) {
          return jsonResponse({ success: false, error: "无权操作" }, 403);
        }
      }

      if(!text.trim()){
        await env.NOTES_KV.delete(noteName);
        await updateIndex(noteName, null, env);
        return jsonResponse({ deleted: true });
      }

      const createdAt = existingObj?.created_at || new Date().toISOString();
      const updatedAt = new Date().toISOString();

      await env.NOTES_KV.put(noteName, JSON.stringify({ 
        content: text, created_at: createdAt, updated_at: updatedAt, encrypted: encryptedFlag 
      }));
      await updateIndex(noteName, { created_at: createdAt, updated_at: updatedAt, encrypted: encryptedFlag }, env);

      return jsonResponse({ created_at: createdAt, updated_at: updatedAt, encrypted: encryptedFlag });
    }

    // ==========================================
    // 5. 获取原始文本接口
    // ==========================================
    let note = await env.NOTES_KV.get(noteName);
    let noteObj = note ? JSON.parse(note) : { content:"", created_at:null, updated_at:null, encrypted:false };
    const encryptedFlag = noteObj.encrypted || false;

    if(isRaw){
      if(encryptedFlag) {
        const kvSessionKey = `${SESSION_KEY_PREFIX}${noteName}`;
        const cookieName = getSafeCookieName(noteName);
        const cookies = parseCookies(request.headers.get("Cookie") || "");
        const sessionToken = cookies[cookieName];
        const storedToken = await env.NOTES_KV.get(kvSessionKey);

        if(!sessionToken || sessionToken !== storedToken) {
          return new Response("需要密码验证", { status: 401, headers: { "Content-Type": "text/plain;charset=UTF-8", ...SECURITY_HEADERS } });
        }
      }
      const content = note ? JSON.parse(note).content : "Not found";
      return new Response(content, { headers:{ "Content-Type": "text/plain;charset=UTF-8", ...SECURITY_HEADERS } });
    }

    // ==========================================
    // 6. 目录数据接口
    // ==========================================
    if(url.pathname === "/" && url.searchParams.get("list") === "1"){
      let indexData = await env.NOTES_KV.get(INDEX_KEY);
      let arr = indexData ? JSON.parse(indexData) : [];
      arr.sort((a, b) => new Date(b.updated_at || b.created_at) - new Date(a.updated_at || a.created_at));
      return jsonResponse(arr);
    }

    // ==========================================
    // 7. 目录页 HTML
    // ==========================================
    if(url.pathname === "/"){
      let html = `<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>📒 笔记本</title>
<style>
  :root { --bg: #f5f7fa; --card-bg: #ffffff; --text: #333; --sub-text: #666; --border: #eaeaea; --primary: #4f8ef7; --danger: #e74c3c; --hover-bg: #f9f9f9; }
  @media (prefers-color-scheme: dark) {
    :root { --bg: #1a1d23; --card-bg: #24262b; --text: #eaeaea; --sub-text: #a0a0a0; --border: #333640; --primary: #6fa3f7; --danger: #c0392b; --hover-bg: #2c2f38; }
  }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); margin:0; padding:20px; }
  .header { display:flex; justify-content:space-between; align-items:center; margin-bottom:24px; }
  .header h1 { margin:0; font-size:24px; }
  .new-btn { background: var(--primary); color: #fff; border:none; padding:8px 16px; border-radius:6px; cursor:pointer; font-size:14px; text-decoration:none; display:inline-block; font-weight:500;}
  .new-btn:hover { opacity:0.9; }
  ul { list-style:none; padding:0; margin:0; display:grid; gap:12px; }
  li { background: var(--card-bg); border:1px solid var(--border); padding:16px 20px; border-radius:8px; transition: box-shadow 0.2s; display:flex; justify-content:space-between; align-items:center; }
  li:hover { box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
  .item-left { flex:1; min-width:0; }
  a { text-decoration:none; color: var(--primary); font-size:16px; font-weight:500; display:inline-block; }
  .time-info { margin-top:4px; font-size:12px; color: var(--sub-text); display:flex; gap:15px; }
  .item-actions { display:flex; gap:8px; margin-left:15px; flex-shrink:0; }
  .btn-sm { border:1px solid var(--border); background:transparent; color:var(--sub-text); padding:4px 10px; border-radius:4px; cursor:pointer; font-size:12px; transition: all 0.2s; }
  .btn-sm:hover { background:var(--hover-bg); color:var(--text); }
  .btn-sm.danger { color:var(--danger); border-color:transparent; }
  .btn-sm.danger:hover { background:var(--danger); color:#fff; }
  .btn-sm.confirm { background:var(--danger); color:#fff; animation: shake 0.3s; }
  @keyframes shake { 0%, 100% {transform:translateX(0);} 25% {transform:translateX(-4px);} 75% {transform:translateX(4px);} }
  
  .rename-input { font-size:16px; font-weight:500; color:var(--primary); border:1px solid var(--primary); border-radius:4px; padding:2px 6px; outline:none; width:100%; max-width:300px; background:transparent; }
  
  .modal-overlay { position:fixed; top:0;left:0;right:0;bottom:0; background:rgba(0,0,0,0.5); display:none; justify-content:center; align-items:center; z-index:1000; }
  .modal-box { background:var(--card-bg); padding:24px; border-radius:8px; width:90%; max-width:360px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); }
  .modal-box h3 { margin-top:0; font-size:16px; }
  .modal-box input { width:100%; padding:10px; margin:10px 0; border:1px solid var(--border); border-radius:4px; background:var(--bg); color:var(--text); box-sizing:border-box; }
  .modal-box button { width:100%; padding:10px; background:var(--primary); color:#fff; border:none; border-radius:4px; cursor:pointer; }
  .modal-err { color:var(--danger); font-size:12px; height:16px; margin-bottom:5px; }
</style>
</head>
<body>
<div class="header">
  <h1>📒 笔记本</h1>
  <a href="/${generateRandomNote()}" class="new-btn">✚ 新建笔记</a>
</div>
<ul id="notesList"></ul>

<div class="modal-overlay" id="modalOverlay">
  <div class="modal-box">
    <h3>🔐 此笔记受密码保护</h3>
    <div class="modal-err" id="modalErr"></div>
    <input type="password" id="modalPwd" placeholder="请输入密码" onkeydown="if(event.key==='Enter')modalConfirm();">
    <button onclick="modalConfirm()">确认删除</button>
    <button style="background:transparent;color:var(--sub-text);margin-top:8px;" onclick="closeModal()">取消</button>
  </div>
</div>

<script>
let pendingDeleteName = null;
let cookies = {}; 
(function parse(){ (document.cookie || "").split(';').forEach(part => { const [n,...v] = part.trim().split('='); if(n) cookies[n.trim()] = decodeURIComponent(v.join('=').trim()); }); })();

function getSafeCookieName(name) {
  let hash = 0; const str = String(name || "");
  for (let i = 0; i < str.length; i++) { hash = ((hash << 5) - hash) + str.charCodeAt(i); hash = hash & hash; }
  return \`note_auth_\${Math.abs(hash).toString(36).padStart(12, '0').slice(0, 12)}\`;
}

function displayTime(t){return t?new Date(t).toLocaleString(undefined,{hour12:false}):"-";}

function createNoteEl(item) {
  const li = document.createElement("li");
  const isEnc = item.encrypted;
  const hasAuth = isEnc && cookies[getSafeCookieName(item.name)];
  const icon = isEnc ? (hasAuth ? '🔓 ' : '🔐 ') : '📄 ';
  
  // [修复] 绑定 isEnc 状态到 DOM 上，防止重命名时丢失加密状态
  li.dataset.isEnc = isEnc;
  
  li.innerHTML = \`
    <div class="item-left">
      <span class="title-wrap">\${icon}<a href="/\${encodeURIComponent(item.name)}">\${item.name}</a></span>
      <div class="time-info">创建: \${displayTime(item.created_at)} | 更新: \${displayTime(item.updated_at)}</div>
    </div>
    <div class="item-actions">
      <button class="btn-sm rename-btn">重命名</button>
      <button class="btn-sm danger del-btn">删除</button>
    </div>
  \`;
  bindItemEvents(li, item.name, isEnc);
  return li;
}

function bindItemEvents(li, name, isEnc) {
  const delBtn = li.querySelector('.del-btn');
  const renameBtn = li.querySelector('.rename-btn');
  let delTimer;

  delBtn.onclick = () => {
    if (delBtn.dataset.confirm === 'true') {
      clearTimeout(delTimer);
      if (isEnc) {
        showPasswordModal(name, li);
      } else {
        doDelete(name, li);
      }
    } else {
      delBtn.dataset.confirm = 'true';
      delBtn.innerHTML = '⚠️ 确认?';
      delBtn.classList.add('confirm');
      delTimer = setTimeout(() => {
        delBtn.dataset.confirm = 'false';
        delBtn.innerHTML = '删除';
        delBtn.classList.remove('confirm');
      }, 3000);
    }
  };

  renameBtn.onclick = () => startRename(li, name);
}

function startRename(li, oldName) {
  const wrap = li.querySelector('.title-wrap');
  const oldHtml = wrap.innerHTML;
  wrap.innerHTML = \`<input class="rename-input" type="text" value="\${oldName.replace(/"/g, '&quot;')}">\`;
  const input = wrap.querySelector('input');
  input.focus();
  input.select();

  let saved = false;
  const save = async (newName) => {
    if (saved) return; saved = true;
    newName = newName.trim();
    if (!newName || newName === oldName) { wrap.innerHTML = oldHtml; return; }
    
    try {
      const fd = new FormData(); fd.append('oldName', oldName); fd.append('newName', newName);
      const res = await fetch('/?action=rename', { method: 'POST', body: fd });
      const data = await res.json();
      if (data.success) {
        // [修复] 从 li.dataset 中正确读取之前的加密状态
        const isEnc = li.dataset.isEnc === 'true';
        const icon = isEnc ? (cookies[getSafeCookieName(data.newName)] ? '🔓 ' : '🔐 ') : '📄 ';
        wrap.innerHTML = \`\${icon}<a href="/\${encodeURIComponent(data.newName)}">\${data.newName}</a>\`;
        bindItemEvents(li, data.newName, isEnc);
      } else {
        alert(data.error || "重命名失败");
        wrap.innerHTML = oldHtml;
      }
    } catch(e) { alert("网络错误"); wrap.innerHTML = oldHtml; }
  };

  input.onkeydown = (e) => { if(e.key === 'Enter') save(input.value); if(e.key === 'Escape') { saved=true; wrap.innerHTML = oldHtml; } };
  input.onblur = () => save(input.value);
}

function doDelete(name, li) {
  fetch('/' + encodeURIComponent(name), { method: 'DELETE' })
    .then(r => {
      if (r.status === 401) throw new Error("授权失效，请刷新页面后重试");
      return r.json();
    })
    .then(data => {
      if(data.success) li.remove();
      else alert(data.error || "删除失败");
    }).catch(e => alert(e.message || "网络错误"));
}

function showPasswordModal(name, li) {
  pendingDeleteName = name;
  document.getElementById('modalPwd').value = '';
  document.getElementById('modalErr').textContent = '';
  document.getElementById('modalOverlay').style.display = 'flex';
  setTimeout(() => document.getElementById('modalPwd').focus(), 100);
}

function closeModal() {
  document.getElementById('modalOverlay').style.display = 'none';
  pendingDeleteName = null;
  document.querySelectorAll('.del-btn.confirm').forEach(btn => { btn.dataset.confirm='false'; btn.innerHTML='删除'; btn.classList.remove('confirm'); });
}

async function modalConfirm() {
  const pwd = document.getElementById('modalPwd').value;
  const errEl = document.getElementById('modalErr');
  if (!pwd) { errEl.textContent = "请输入密码"; return; }
  
  try {
    const fd = new FormData(); fd.append('password', pwd);
    const res = await fetch('/' + encodeURIComponent(pendingDeleteName) + '?password=1', { method: 'POST', body: fd });
    const data = await res.json();
    if (data.success) {
      // [修复] 必须先提取变量和元素，然后再调用 closeModal() 清空状态
      const nameToDelete = pendingDeleteName;
      const liToDelete = document.querySelector(\`a[href="/\${encodeURIComponent(pendingDeleteName)}"]\`).closest('li');
      closeModal(); 
      doDelete(nameToDelete, liToDelete);
    } else {
      errEl.textContent = data.error || "密码错误";
    }
  } catch(e) { errEl.textContent = "网络请求失败"; }
}

async function loadList(){
  try{
    const resp = await fetch("/?list=1");
    let arr = await resp.json();
    arr.sort((a, b) => new Date(b.updated_at || b.created_at) - new Date(a.updated_at || a.created_at));
    const ul = document.getElementById("notesList"); ul.innerHTML = "";
    arr.forEach(item => ul.appendChild(createNoteEl(item)));
  } catch(e){ console.error("加载目录失败", e); }
}
loadList();
setInterval(loadList, 10000);
</script>
</body></html>`;
      return new Response(html,{ headers:{ "Content-Type":"text/html;charset=UTF-8", ...SECURITY_HEADERS } });
    }

    // ==========================================
    // 8. 密码输入页 HTML
    // ==========================================
    if(encryptedFlag) {
      const kvSessionKey = `${SESSION_KEY_PREFIX}${noteName}`;
      const cookieName = getSafeCookieName(noteName);
      const cookies = parseCookies(request.headers.get("Cookie") || "");
      const sessionToken = cookies[cookieName];
      const storedToken = await env.NOTES_KV.get(kvSessionKey);

      if(!sessionToken || sessionToken !== storedToken) {
        return new Response(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>🔐 访问验证</title>
<style>
  :root { --bg: #f0f0f0; --card-bg: #fff; --text: #333; --input-bg: #f9f9f9; --btn-bg: #4f8ef7; --err-color: #e74c3c; }
  @media (prefers-color-scheme: dark) { :root { --bg: #121212; --card-bg: #24262b; --text: #fff; --input-bg: #333b4d; --btn-bg: #6fa3f7; } }
  body { font-family: sans-serif; background:var(--bg); padding:20px; display:flex; justify-content:center; align-items:center; height:100vh; margin:0; }
  .container { background:var(--card-bg); padding:30px; border-radius:10px; box-shadow:0 4px 20px rgba(0,0,0,0.1); text-align:center; max-width:360px; width:100%; color:var(--text); }
  .home-link { display:inline-block; margin-bottom:20px; color:var(--text); text-decoration:none; font-size:14px; opacity:0.7; }
  .home-link:hover { opacity:1; }
  h2 { margin:0 0 20px 0; font-size:18px; }
  input { width:100%; padding:12px; margin:10px 0; border:1px solid #ddd; border-radius:6px; background:var(--input-bg); color:var(--text); box-sizing:border-box; }
  button { width:100%; padding:12px; background:var(--btn-bg); color:#fff; border:none; border-radius:6px; cursor:pointer; font-size:16px; margin-top:10px; }
  button:hover { opacity:0.9; }
  .error { color:var(--err-color); font-size:14px; margin-top:10px; height:20px; }
</style></head><body>
<div class="container">
  <a href="/" class="home-link">← 返回主页</a>
  <h2>🔐 输入密码访问</h2>
  <input type="password" id="password" placeholder="请输入访问密码" onkeydown="if(event.key === 'Enter') submitPassword();">
  <div class="error" id="errorMsg"></div>
  <button onclick="submitPassword()">验证并进入</button>
</div>
<script>
function getSafeCookieName(name) {
  let hash = 0; const str = String(name || "");
  for (let i = 0; i < str.length; i++) { hash = ((hash << 5) - hash) + str.charCodeAt(i); hash = hash & hash; }
  return \`note_auth_\${Math.abs(hash).toString(36).padStart(12, '0').slice(0, 12)}\`;
}
async function submitPassword() {
  const password = document.getElementById('password').value;
  const errorMsg = document.getElementById('errorMsg');
  const formData = new FormData(); formData.append('password', password);
  try {
    const resp = await fetch(window.location.href + '?password=1', { method: 'POST', body: formData });
    const data = await resp.json();
    if(data.success) { sessionStorage.setItem(getSafeCookieName(window.location.pathname.slice(1)), "1"); window.location.reload(); }
    else { errorMsg.textContent = data.error || '密码错误'; }
  } catch(e) { errorMsg.textContent = '网络请求失败'; }
}
document.getElementById('password').focus();
</script></body></html>`, { headers: { "Content-Type": "text/html;charset=UTF-8", ...SECURITY_HEADERS } });
      }
    }

    // ==========================================
    // 9. 编辑页 HTML
    // ==========================================
    const content = noteObj.content || "";
    const createdAtISO = noteObj.created_at || "";
    const updatedAtISO = noteObj.updated_at || "";

    return new Response(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>📒 ${htmlEscape(noteName)}</title>
<style>
  :root { --bg: #f5f7fa; --editor-bg: #fff; --toolbar-bg: #fafafa; --text: #222; --sub-text: #888; --border: #e1e4e8; --btn-hover: #f0f0f0; --primary: #4f8ef7; --danger: #e74c3c; }
  @media (prefers-color-scheme: dark) {
    :root { --bg: #1a1d23; --editor-bg: #24262b; --toolbar-bg: #1e2028; --text: #eaeaea; --sub-text: #8b8fa3; --border: #333640; --btn-hover: #2c2f38; --primary: #6fa3f7; --danger: #c0392b; }
  }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display:flex; flex-direction:column; height:100vh; }
  .toolbar { display:flex; justify-content:space-between; align-items:center; padding:10px 20px; background:var(--toolbar-bg); border-bottom:1px solid var(--border); flex-shrink:0; }
  .toolbar-left { display:flex; align-items:center; gap:15px; }
  .home-btn { text-decoration:none; color:var(--sub-text); font-size:14px; display:flex; align-items:center; gap:4px; }
  .home-btn:hover { color:var(--text); }
  .note-title { font-weight:600; font-size:16px; }
  .save-indicator { font-size:12px; color:var(--sub-text); }
  #content { flex:1; margin:0; padding:20px; background:var(--editor-bg); color:var(--text); border:none; outline:none; resize:none; font-size:15px; line-height:1.6; width:100%; }
  .statusbar { display:flex; justify-content:space-between; align-items:center; padding:8px 20px; background:var(--toolbar-bg); border-top:1px solid var(--border); font-size:12px; color:var(--sub-text); flex-shrink:0; flex-wrap: wrap; gap: 10px; }
  .statusbar-right { display:flex; align-items:center; gap:12px; }
  .btn { border:1px solid var(--border); background:transparent; color:var(--sub-text); padding:4px 10px; border-radius:4px; cursor:pointer; font-size:12px; transition: all 0.2s; }
  .btn:hover { background:var(--btn-hover); color:var(--text); }
  .btn.danger { color:var(--danger); border-color:var(--danger); }
  .btn.danger:hover { background:var(--danger); color:#fff; }
  .encrypt-label { display:flex; align-items:center; gap:4px; cursor:pointer; user-select:none; }
  @media (max-width: 600px) {
    .toolbar { padding: 10px 12px; } #content { padding: 12px; font-size: 14px; } .statusbar { padding: 8px 12px; }
  }
</style></head><body>
<div class="toolbar">
  <div class="toolbar-left">
    <a href="/" class="home-btn">← 主页</a>
    <span class="note-title">${htmlEscape(noteName)}</span>
  </div>
  <div class="save-indicator" id="saveIndicator">✅ 已保存</div>
</div>
<textarea id="content" spellcheck="false">${htmlEscape(content)}</textarea>
<div class="statusbar">
  <div>创建: <span id="createdTime"></span> &nbsp;|&nbsp; 更新: <span id="updatedTime"></span></div>
  <div class="statusbar-right">
    <label class="encrypt-label"><input type="checkbox" id="encryptToggle"${encryptedFlag?' checked':''}/> 🔒 密码保护</label>
    <button class="btn danger" id="deleteBtn">🗑️ 删除</button>
  </div>
</div>
<script>
const textarea = document.getElementById('content');
const deleteBtn = document.getElementById('deleteBtn');
const encryptToggle = document.getElementById('encryptToggle');
const saveIndicator = document.getElementById('saveIndicator');
let previousContent = textarea.value;

function displayTime(t){ return t ? new Date(t).toLocaleString(undefined, {hour12: false}) : "-"; }
document.getElementById('createdTime').textContent = displayTime("${createdAtISO}");
document.getElementById('updatedTime').textContent = displayTime("${updatedAtISO}");

let saveTimeout;
function setSaveStatus(status) {
  if (status === 'saving') saveIndicator.innerHTML = '⏳ 保存中...';
  if (status === 'saved') saveIndicator.innerHTML = '✅ 已保存';
  if (status === 'error') saveIndicator.innerHTML = '❌ 保存失败';
}

async function save(auto = false) {
  const temp = textarea.value;
  if (previousContent === temp && auto) return;
  if (!auto) setSaveStatus('saving');
  try {
    const resp = await fetch(window.location.href + '?encrypt=' + (encryptToggle.checked ? "1" : "0"), { method: 'POST', body: temp });
    if (resp.status === 403) { alert("无权修改加密笔记，请刷新页面重新验证。"); setSaveStatus('error'); return; }
    const data = await resp.json();
    previousContent = temp; setSaveStatus('saved');
    if (data.deleted) { window.location.href = "/"; return; }
    if (data.updated_at) document.getElementById('updatedTime').textContent = displayTime(data.updated_at);
    if (data.created_at) document.getElementById('createdTime').textContent = displayTime(data.created_at);
  } catch(e) { console.error(e); setSaveStatus('error'); }
}

let deleteConfirmTimer;
deleteBtn.addEventListener('click', () => {
  if (deleteBtn.dataset.confirm === 'true') {
    clearTimeout(deleteConfirmTimer);
    fetch(window.location.href, { method: 'POST', body: "" }).then(() => window.location.href = "/");
  } else {
    deleteBtn.dataset.confirm = 'true'; deleteBtn.innerHTML = '⚠️ 再次点击确认';
    deleteBtn.style.background = 'var(--danger)'; deleteBtn.style.color = '#fff';
    deleteConfirmTimer = setTimeout(() => { deleteBtn.dataset.confirm = 'false'; deleteBtn.innerHTML = '🗑️ 删除'; deleteBtn.style.background = ''; deleteBtn.style.color = ''; }, 3000);
  }
});

encryptToggle.addEventListener('change', () => {
  if (encryptToggle.checked && !confirm('开启后需输入密码才能查看和修改，确认？')) { encryptToggle.checked = false; return; }
  save(false);
});

let autoSaveTimer;
textarea.addEventListener('input', () => { setSaveStatus('saving'); clearTimeout(autoSaveTimer); autoSaveTimer = setTimeout(() => save(true), 1000); });
textarea.addEventListener('blur', () => save(false));
if(!textarea.value) textarea.focus();
</script></body></html>`, { headers: { "Content-Type": "text/html;charset=UTF-8", ...SECURITY_HEADERS } });

  } catch (err) {
    console.error("Worker Error:", err);
    return new Response(`<h1>Worker Error</h1><p>${htmlEscape(err.message || err)}</p>`, {
      status: 500, headers: { "Content-Type": "text/html;charset=UTF-8", ...SECURITY_HEADERS }
    });
  }
}

async function updateIndex(name, timesObj, env){
  let indexData = await env.NOTES_KV.get(INDEX_KEY);
  let arr = indexData ? JSON.parse(indexData) : [];
  arr = arr.filter(item => item.name !== name);
  if (timesObj) {
    arr.push({ name, created_at: timesObj.created_at, updated_at: timesObj.updated_at, encrypted: timesObj.encrypted });
  }
  await env.NOTES_KV.put(INDEX_KEY, JSON.stringify(arr));
}

function generateRandomNote(){
  const chars = '234579abcdefghjkmnpqrstwxyz';
  return Array.from({length:5}, () => chars[Math.floor(Math.random()*chars.length)]).join('');
}
