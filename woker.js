// Cloudflare Worker 脚本 - 文件托管服务（完整版：双页面批量下载）
// 绑定KV命名空间: FILE_STORAGE
// 环境变量: TOTP_SECRET (Base32编码), SHA1。ADMIN_SESSION_TTL (可选, 默认3600秒)


// ==================== 配置 ====================
const MAX_FILE_SIZE = 25 * 1024 * 1024; // 25MB
const DEFAULT_EXPIRY_SECONDS = 24 * 60 * 60; // 24小时
const PERMANENT_EXPIRY = 9999999999; // 永久文件的过期时间戳

// TOTP 参数
const TOTP_WINDOW = 1;
const TOTP_STEP = 30;

// ==================== 工具函数 ====================

function generateUUID() {
  return crypto.randomUUID();
}

function base32Decode(base32) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let output = [];
  for (let i = 0; i < base32.length; i++) {
    const char = base32[i].toUpperCase();
    const idx = alphabet.indexOf(char);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      output.push((value >> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}

async function hmacSha1(key, message) {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, message);
  return new Uint8Array(signature);
}

async function generateTOTP(secretBase32, counter) {
  const key = base32Decode(secretBase32);
  const counterBytes = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = counter & 0xff;
    counter >>= 8;
  }
  const hmac = await hmacSha1(key, counterBytes);
  const offset = hmac[19] & 0xf;
  const code = ((hmac[offset] & 0x7f) << 24) |
               ((hmac[offset + 1] & 0xff) << 16) |
               ((hmac[offset + 2] & 0xff) << 8) |
               (hmac[offset + 3] & 0xff);
  return (code % 1000000).toString().padStart(6, '0');
}

async function verifyTOTP(token, secretBase32) {
  const epoch = Math.floor(Date.now() / 1000);
  for (let i = -TOTP_WINDOW; i <= TOTP_WINDOW; i++) {
    const counter = Math.floor(epoch / TOTP_STEP) + i;
    const expected = await generateTOTP(secretBase32, counter);
    if (expected === token) return true;
  }
  return false;
}

async function verifyAdminSession(request, env) {
  const cookie = request.headers.get('Cookie');
  if (!cookie) return false;
  const sessionId = cookie.match(/admin_session=([^;]+)/)?.[1];
  if (!sessionId) return false;
  const session = await env.FILE_STORAGE.get(`session:${sessionId}`, 'json');
  if (!session || session.expiresAt < Date.now()) return false;
  return true;
}

async function createAdminSession(env) {
  const sessionId = generateUUID();
  const ttl = parseInt(env.ADMIN_SESSION_TTL) || 3600;
  const expiresAt = Date.now() + ttl * 1000;
  await env.FILE_STORAGE.put(`session:${sessionId}`, JSON.stringify({ expiresAt }), { expirationTtl: ttl });
  return sessionId;
}

async function deleteFile(env, fileId) {
  await env.FILE_STORAGE.delete(`meta:${fileId}`);
  await env.FILE_STORAGE.delete(`data:${fileId}`);
}

async function getFileMeta(env, fileId, autoCleanup = true) {
  const meta = await env.FILE_STORAGE.get(`meta:${fileId}`, 'json');
  if (!meta) return null;
  const now = Math.floor(Date.now() / 1000);
  if (!meta.permanent && meta.expiresAt < now) {
    if (autoCleanup) {
      await deleteFile(env, fileId);
    }
    return null;
  }
  return meta;
}

async function listPublicFiles(env) {
  const list = await env.FILE_STORAGE.list({ prefix: 'meta:' });
  const files = [];
  const now = Math.floor(Date.now() / 1000);
  for (const key of list.keys) {
    const meta = await env.FILE_STORAGE.get(key.name, 'json');
    if (!meta) continue;
    if (!meta.permanent && meta.expiresAt < now) {
      deleteFile(env, key.name.slice(5)).catch(e => console.error(e));
      continue;
    }
    files.push({
      id: meta.id,
      filename: meta.filename,
      size: meta.size,
      uploadTime: meta.uploadTime,
      expiresAt: meta.expiresAt,
      permanent: meta.permanent || false,
      contentType: meta.contentType
    });
  }
  files.sort((a, b) => b.uploadTime - a.uploadTime);
  return files;
}

async function listAdminFiles(env) {
  const list = await env.FILE_STORAGE.list({ prefix: 'meta:' });
  const files = [];
  for (const key of list.keys) {
    const meta = await env.FILE_STORAGE.get(key.name, 'json');
    if (!meta) continue;
    files.push({
      id: meta.id,
      filename: meta.filename,
      size: meta.size,
      uploadTime: meta.uploadTime,
      expiresAt: meta.expiresAt,
      permanent: meta.permanent || false,
      contentType: meta.contentType
    });
  }
  files.sort((a, b) => b.uploadTime - a.uploadTime);
  return files;
}

async function saveFile(env, fileId, fileData, filename, contentType, size, permanent = false) {
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = permanent ? PERMANENT_EXPIRY : now + DEFAULT_EXPIRY_SECONDS;
  const meta = {
    id: fileId,
    filename,
    size,
    uploadTime: now,
    expiresAt,
    permanent,
    contentType
  };
  await env.FILE_STORAGE.put(`meta:${fileId}`, JSON.stringify(meta));
  await env.FILE_STORAGE.put(`data:${fileId}`, fileData);
  return meta;
}

// ==================== HTML 页面模板 ====================

function getIndexPage() {
  return `<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>文件共享 - 公共上传</title>
    <style>
        * { box-sizing: border-box; font-family: system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif; }
        body { max-width: 1200px; margin: 0 auto; padding: 2rem; background: #f5f7fb; }
        .card { background: white; border-radius: 1rem; box-shadow: 0 4px 12px rgba(0,0,0,0.05); padding: 1.5rem; margin-bottom: 2rem; }
        h1 { margin-top: 0; color: #1e293b; }
        .upload-area { border: 2px dashed #cbd5e1; border-radius: 1rem; padding: 2rem; text-align: center; cursor: pointer; transition: 0.2s; }
        .upload-area:hover { border-color: #3b82f6; background: #f8fafc; }
        .file-input { display: none; }
        .btn { background: #3b82f6; color: white; border: none; padding: 0.5rem 1rem; border-radius: 0.5rem; cursor: pointer; font-size: 0.9rem; transition: 0.2s; }
        .btn:hover { background: #2563eb; }
        .btn-small { padding: 0.25rem 0.75rem; font-size: 0.8rem; }
        .btn-success { background: #10b981; }
        .btn-success:hover { background: #059669; }
        table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
        th, td { text-align: left; padding: 0.75rem; border-bottom: 1px solid #e2e8f0; }
        th { background: #f1f5f9; font-weight: 600; }
        .file-actions button { margin: 0 0.25rem; }
        .time-badge { font-size: 0.8rem; color: #475569; background: #e2e8f0; padding: 0.2rem 0.5rem; border-radius: 1rem; white-space: nowrap; }
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); justify-content: center; align-items: center; z-index: 1000; }
        .modal-content { background: white; border-radius: 1rem; padding: 1.5rem; max-width: 400px; width: 90%; }
        .modal input { width: 100%; padding: 0.5rem; margin: 1rem 0; border: 1px solid #cbd5e1; border-radius: 0.5rem; }
        .toast { position: fixed; bottom: 20px; right: 20px; background: #1e293b; color: white; padding: 0.75rem 1.5rem; border-radius: 2rem; z-index: 1100; animation: fadeOut 3s forwards; }
        @keyframes fadeOut { 0% { opacity: 1; } 70% { opacity: 1; } 100% { opacity: 0; visibility: hidden; } }
        .queue-item { background: #f8fafc; border-radius: 0.5rem; padding: 0.75rem; margin-bottom: 0.75rem; border: 1px solid #e2e8f0; }
        progress { accent-color: #3b82f6; width: 100%; height: 8px; }
        .batch-bar { margin-bottom: 1rem; display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; }
        input[type="checkbox"] { transform: scale(1.2); }
        .checkbox-col { width: 40px; text-align: center; }
        .progress-bar { width: 100%; height: 6px; background: #e2e8f0; border-radius: 3px; overflow: hidden; margin-top: 8px; }
        .progress-fill { height: 100%; background: #3b82f6; transition: width 0.3s; }
        .download-progress { margin-top: 10px; padding: 10px; background: #f1f5f9; border-radius: 8px; }
    </style>
</head>
<body>
    <div class="card">
        <h1>📁 公共文件空间 (24小时有效)</h1>
        <div class="upload-area" id="uploadArea">
            <p>📤 点击或拖拽上传文件 (最大25MB，支持多文件)</p>
            <input type="file" id="fileInput" class="file-input" multiple />
        </div>
        <div id="uploadProgressArea" style="margin-top: 1rem;">
            <h3>上传队列</h3>
            <div id="uploadQueue"></div>
        </div>
        <div style="margin-top: 1rem;">
            <button class="btn" id="refreshBtn">🔄 刷新列表</button>
        </div>
    </div>
    <div class="card">
        <h2>📄 文件列表</h2>
        <div class="batch-bar">
            <button class="btn btn-success" id="batchDownloadBtn">📦 批量下载选中</button>
            <span id="selectedCount">已选择 0 个文件</span>
        </div>
        <div id="fileList">
            <p>加载中...</p>
        </div>
        <div id="downloadProgress" class="download-progress" style="display: none;">
            <div>正在打包下载...</div>
            <div class="progress-bar"><div class="progress-fill" id="downloadProgressFill" style="width: 0%"></div></div>
            <div id="downloadStatus">准备中...</div>
        </div>
    </div>

    <div id="shareModal" class="modal">
        <div class="modal-content">
            <h3>分享链接</h3>
            <input type="text" id="shareLink" readonly />
            <button class="btn" id="copyLinkBtn">复制链接</button>
            <button class="btn" style="background:#94a3b8;" id="closeModalBtn">关闭</button>
        </div>
    </div>

    <script>
        const API_BASE = '';
        const MAX_FILE_SIZE = ${MAX_FILE_SIZE};
        let fileList = [];
        let selectedIds = new Set();
        let activeUploads = new Map();

        function showToast(msg) {
            const toast = document.createElement('div');
            toast.className = 'toast';
            toast.innerText = msg;
            document.body.appendChild(toast);
            setTimeout(() => toast.remove(), 3000);
        }

        function formatRemaining(expiresAt, permanent) {
            if (permanent) return '♾️ 永久';
            const now = Math.floor(Date.now() / 1000);
            const diff = expiresAt - now;
            if (diff <= 0) return '已过期';
            const hours = Math.floor(diff / 3600);
            const minutes = Math.floor((diff % 3600) / 60);
            return \`⏳ \${hours}h \${minutes}m\`;
        }

        async function loadFiles() {
            try {
                const res = await fetch('/api/files');
                const data = await res.json();
                fileList = data.files;
                renderFileList();
            } catch (err) {
                console.error(err);
                document.getElementById('fileList').innerHTML = '<p>加载失败</p>';
            }
        }

        function renderFileList() {
            const container = document.getElementById('fileList');
            if (!fileList.length) {
                container.innerHTML = '<p>暂无文件</p>';
                return;
            }
            const html = \`
                <table>
                    <thead>
                        <tr>
                            <th class="checkbox-col"><input type="checkbox" id="selectAll"></th>
                            <th>文件名</th>
                            <th>大小</th>
                            <th>剩余时间</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody>
                        \${fileList.map(file => \`
                            <tr data-id="\${file.id}">
                                <td class="checkbox-col"><input type="checkbox" class="file-checkbox" value="\${file.id}" \${selectedIds.has(file.id) ? 'checked' : ''}></td>
                                <td>\${escapeHtml(file.filename)}</td>
                                <td>\${(file.size / 1024).toFixed(1)} KB</td>
                                <td><span class="time-badge">\${formatRemaining(file.expiresAt, file.permanent)}</span></td>
                                <td class="file-actions">
                                    <button class="btn btn-small" onclick="downloadFile('\${file.id}')">下载</button>
                                    <button class="btn btn-small" onclick="shareFile('\${file.id}')">分享</button>
                                </td>
                            </tr>
                        \`).join('')}
                    </tbody>
                </table>
            \`;
            container.innerHTML = html;
            
            const selectAllCheckbox = document.getElementById('selectAll');
            if (selectAllCheckbox) {
                selectAllCheckbox.addEventListener('change', (e) => {
                    const checkboxes = document.querySelectorAll('.file-checkbox');
                    checkboxes.forEach(cb => cb.checked = e.target.checked);
                    updateSelected();
                });
            }
            document.querySelectorAll('.file-checkbox').forEach(cb => {
                cb.addEventListener('change', updateSelected);
            });
            updateSelected();
        }

        function updateSelected() {
            selectedIds.clear();
            document.querySelectorAll('.file-checkbox:checked').forEach(cb => selectedIds.add(cb.value));
            document.getElementById('selectedCount').innerText = \`已选择 \${selectedIds.size} 个文件\`;
        }

        function escapeHtml(str) {
            return str.replace(/[&<>]/g, function(m) {
                if (m === '&') return '&amp;';
                if (m === '<') return '&lt;';
                if (m === '>') return '&gt;';
                return m;
            });
        }

        function addToQueue(file) {
            if (file.size > MAX_FILE_SIZE) {
                showToast(\`文件 "\${file.name}" 超过 25MB，已跳过\`);
                return;
            }
            const queueItem = {
                id: Date.now() + Math.random(),
                file: file,
                status: 'waiting',
                progress: 0,
                xhr: null
            };
            renderQueueItem(queueItem);
            processQueue(queueItem);
        }

        function renderQueueItem(item) {
            const queueDiv = document.getElementById('uploadQueue');
            let existing = document.getElementById(\`upload-item-\${item.id}\`);
            if (!existing) {
                existing = document.createElement('div');
                existing.id = \`upload-item-\${item.id}\`;
                existing.className = 'queue-item';
                queueDiv.appendChild(existing);
            }
            const statusText = {
                waiting: '等待中',
                uploading: '上传中',
                success: '✅ 完成',
                error: '❌ 失败'
            };
            existing.innerHTML = \`
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                    <span><strong>\${escapeHtml(item.file.name)}</strong> (\${(item.file.size / 1024).toFixed(1)} KB)</span>
                    <span>\${statusText[item.status]}</span>
                </div>
                \${item.status === 'uploading' || item.status === 'waiting' ? \`
                    <progress value="\${item.progress}" max="100"></progress>
                    <div style="display: flex; justify-content: flex-end; margin-top: 4px;">
                        <button class="btn-small" onclick="cancelUpload(\${item.id})">取消</button>
                    </div>
                \` : ''}
                \${item.status === 'success' ? '<div style="color: green;">上传成功</div>' : ''}
                \${item.status === 'error' ? '<div style="color: red;">上传失败，请重试</div>' : ''}
            \`;
        }

        function cancelUpload(id) {
            const item = activeUploads.get(id);
            if (item && item.xhr) {
                item.xhr.abort();
            }
            removeQueueItem(id);
        }

        function removeQueueItem(id) {
            const elem = document.getElementById(\`upload-item-\${id}\`);
            if (elem) elem.remove();
            activeUploads.delete(id);
        }

        async function processQueue(item) {
            if (item.status !== 'waiting') return;
            item.status = 'uploading';
            activeUploads.set(item.id, item);
            renderQueueItem(item);

            const formData = new FormData();
            formData.append('file', item.file);

            const xhr = new XMLHttpRequest();
            item.xhr = xhr;

            xhr.upload.addEventListener('progress', (e) => {
                if (e.lengthComputable) {
                    item.progress = Math.round((e.loaded / e.total) * 100);
                    renderQueueItem(item);
                }
            });

            xhr.onload = () => {
                if (xhr.status === 200) {
                    item.status = 'success';
                    renderQueueItem(item);
                    setTimeout(() => removeQueueItem(item.id), 2000);
                    loadFiles();
                } else {
                    item.status = 'error';
                    renderQueueItem(item);
                    setTimeout(() => removeQueueItem(item.id), 3000);
                }
                activeUploads.delete(item.id);
            };

            xhr.onerror = () => {
                item.status = 'error';
                renderQueueItem(item);
                setTimeout(() => removeQueueItem(item.id), 3000);
                activeUploads.delete(item.id);
            };

            xhr.onabort = () => {
                removeQueueItem(item.id);
            };

            xhr.open('POST', '/api/upload');
            xhr.send(formData);
        }

        function handleFiles(files) {
            for (let file of files) {
                addToQueue(file);
            }
        }

        async function batchDownload() {
            if (selectedIds.size === 0) {
                showToast('请先选择要下载的文件');
                return;
            }
            
            const progressDiv = document.getElementById('downloadProgress');
            const progressFill = document.getElementById('downloadProgressFill');
            const statusDiv = document.getElementById('downloadStatus');
            
            progressDiv.style.display = 'block';
            progressFill.style.width = '0%';
            statusDiv.innerText = '正在准备下载...';
            
            try {
                const selectedFiles = fileList.filter(f => selectedIds.has(f.id));
                let downloaded = 0;
                const filesData = [];
                
                for (const file of selectedFiles) {
                    statusDiv.innerText = \`正在下载: \${file.filename} (\${downloaded + 1}/\${selectedFiles.length})\`;
                    const progress = (downloaded / selectedFiles.length) * 100;
                    progressFill.style.width = progress + '%';
                    
                    const response = await fetch(\`/api/download/\${file.id}\`);
                    if (!response.ok) throw new Error(\`下载 \${file.filename} 失败\`);
                    
                    const blob = await response.blob();
                    filesData.push({
                        filename: file.filename,
                        data: await blob.arrayBuffer()
                    });
                    
                    downloaded++;
                    const newProgress = (downloaded / selectedFiles.length) * 100;
                    progressFill.style.width = newProgress + '%';
                }
                
                statusDiv.innerText = '正在打包成 ZIP 文件...';
                progressFill.style.width = '90%';
                
                const zipBlob = await createZip(filesData);
                
                statusDiv.innerText = '下载中...';
                progressFill.style.width = '100%';
                
                const downloadUrl = URL.createObjectURL(zipBlob);
                const a = document.createElement('a');
                a.href = downloadUrl;
                a.download = \`files_\${new Date().getTime()}.zip\`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(downloadUrl);
                
                setTimeout(() => {
                    progressDiv.style.display = 'none';
                }, 2000);
                
                showToast(\`成功下载 \${selectedFiles.length} 个文件\`);
            } catch (err) {
                console.error('批量下载失败:', err);
                statusDiv.innerText = '下载失败: ' + err.message;
                showToast('批量下载失败: ' + err.message);
                setTimeout(() => {
                    progressDiv.style.display = 'none';
                }, 3000);
            }
        }
        
        async function createZip(filesData) {
            return new Promise((resolve, reject) => {
                // 检查是否已加载 JSZip
                if (window.JSZip) {
                    const zip = new JSZip();
                    for (const file of filesData) {
                        zip.file(file.filename, file.data);
                    }
                    zip.generateAsync({ type: 'blob' })
                        .then(resolve)
                        .catch(reject);
                } else {
                    const script = document.createElement('script');
                    script.src = 'https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js';
                    script.onload = () => {
                        const zip = new JSZip();
                        for (const file of filesData) {
                            zip.file(file.filename, file.data);
                        }
                        zip.generateAsync({ type: 'blob' })
                            .then(resolve)
                            .catch(reject);
                    };
                    script.onerror = () => reject(new Error('加载 JSZip 失败'));
                    document.head.appendChild(script);
                }
            });
        }

        function downloadFile(id) { 
            window.open(\`/api/download/\${id}\`, '_blank'); 
        }
        
        function shareFile(id) {
            const link = \`\${window.location.origin}/api/download/\${id}\`;
            document.getElementById('shareLink').value = link;
            document.getElementById('shareModal').style.display = 'flex';
        }

        document.getElementById('uploadArea').addEventListener('click', () => document.getElementById('fileInput').click());
        document.getElementById('fileInput').addEventListener('change', (e) => {
            if (e.target.files.length) {
                handleFiles(Array.from(e.target.files));
            }
            e.target.value = '';
        });
        document.getElementById('refreshBtn').addEventListener('click', loadFiles);
        document.getElementById('batchDownloadBtn').addEventListener('click', batchDownload);
        document.getElementById('copyLinkBtn').addEventListener('click', () => {
            const input = document.getElementById('shareLink');
            input.select();
            document.execCommand('copy');
            showToast('已复制链接');
        });
        document.getElementById('closeModalBtn').addEventListener('click', () => document.getElementById('shareModal').style.display = 'none');
        window.addEventListener('click', (e) => { if (e.target === document.getElementById('shareModal')) document.getElementById('shareModal').style.display = 'none'; });

        const dropZone = document.getElementById('uploadArea');
        dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.style.borderColor = '#3b82f6'; });
        dropZone.addEventListener('dragleave', () => dropZone.style.borderColor = '#cbd5e1');
        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.style.borderColor = '#cbd5e1';
            if (e.dataTransfer.files.length) {
                handleFiles(Array.from(e.dataTransfer.files));
            }
        });

        loadFiles();
    </script>
</body>
</html>`;
}

function getAdminPage() {
  return `<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>管理员面板 - 文件管理</title>
    <style>
        * { box-sizing: border-box; font-family: system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif; }
        body { max-width: 1200px; margin: 0 auto; padding: 2rem; background: #f5f7fb; }
        .card { background: white; border-radius: 1rem; box-shadow: 0 4px 12px rgba(0,0,0,0.05); padding: 1.5rem; margin-bottom: 2rem; }
        h1 { margin-top: 0; color: #1e293b; }
        .upload-area { border: 2px dashed #cbd5e1; border-radius: 1rem; padding: 2rem; text-align: center; cursor: pointer; transition: 0.2s; }
        .upload-area:hover { border-color: #3b82f6; background: #f8fafc; }
        .file-input { display: none; }
        .btn { background: #3b82f6; color: white; border: none; padding: 0.5rem 1rem; border-radius: 0.5rem; cursor: pointer; font-size: 0.9rem; transition: 0.2s; margin-right: 0.5rem; }
        .btn-danger { background: #ef4444; }
        .btn-danger:hover { background: #dc2626; }
        .btn-warning { background: #eab308; color: black; }
        .btn-warning:hover { background: #ca8a04; }
        .btn-success { background: #10b981; }
        .btn-success:hover { background: #059669; }
        .btn-small { padding: 0.25rem 0.75rem; font-size: 0.8rem; }
        table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
        th, td { text-align: left; padding: 0.75rem; border-bottom: 1px solid #e2e8f0; vertical-align: middle; }
        th { background: #f1f5f9; font-weight: 600; }
        .checkbox-col { width: 40px; text-align: center; }
        .file-actions button { margin: 0 0.25rem; }
        .time-badge { font-size: 0.8rem; color: #475569; background: #e2e8f0; padding: 0.2rem 0.5rem; border-radius: 1rem; white-space: nowrap; }
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); justify-content: center; align-items: center; z-index: 1000; }
        .modal-content { background: white; border-radius: 1rem; padding: 1.5rem; max-width: 400px; width: 90%; }
        .toast { position: fixed; bottom: 20px; right: 20px; background: #1e293b; color: white; padding: 0.75rem 1.5rem; border-radius: 2rem; z-index: 1100; animation: fadeOut 3s forwards; }
        @keyframes fadeOut { 0% { opacity: 1; } 70% { opacity: 1; } 100% { opacity: 0; visibility: hidden; } }
        .queue-item { background: #f8fafc; border-radius: 0.5rem; padding: 0.75rem; margin-bottom: 0.75rem; border: 1px solid #e2e8f0; }
        progress { accent-color: #3b82f6; width: 100%; height: 8px; }
        .batch-bar { margin-bottom: 1rem; display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; }
        input[type="checkbox"] { transform: scale(1.2); }
        .progress-bar { width: 100%; height: 6px; background: #e2e8f0; border-radius: 3px; overflow: hidden; margin-top: 8px; }
        .progress-fill { height: 100%; background: #3b82f6; transition: width 0.3s; }
        .download-progress { margin-top: 10px; padding: 10px; background: #f1f5f9; border-radius: 8px; }
    </style>
</head>
<body>
    <div id="loginModal" class="modal" style="display: flex;">
        <div class="modal-content">
            <h3>🔐 管理员验证</h3>
            <p>请输入TOTP动态码</p>
            <input type="text" id="totpInput" placeholder="6位数字" autocomplete="off" />
            <button class="btn" id="loginBtn">验证</button>
            <div id="loginError" style="color:red; margin-top:0.5rem;"></div>
        </div>
    </div>

    <div id="adminContent" style="display: none;">
        <div class="card">
            <h1>🔧 管理员面板 (永久/删除/批量操作)</h1>
            <div class="upload-area" id="uploadArea">
                <p>📤 点击或拖拽上传文件 (最大25MB，支持多文件)</p>
                <input type="file" id="fileInput" class="file-input" multiple />
            </div>
            <div id="uploadProgressArea" style="margin-top: 1rem;">
                <h3>上传队列</h3>
                <div id="uploadQueue"></div>
            </div>
            <div style="margin-top: 1rem;">
                <button class="btn" id="refreshBtn">🔄 刷新列表</button>
            </div>
        </div>
        <div class="card">
            <h2>📄 文件管理</h2>
            <div class="batch-bar">
                <button class="btn btn-danger" id="batchDeleteBtn">🗑️ 批量删除</button>
                <button class="btn btn-warning" id="batchPermanentBtn">⭐ 批量转永久</button>
                <button class="btn btn-success" id="batchDownloadBtn">📦 批量下载选中</button>
                <span id="selectedCount">已选择 0 个文件</span>
            </div>
            <div id="fileList"><p>加载中...</p></div>
            <div id="downloadProgress" class="download-progress" style="display: none;">
                <div>正在打包下载...</div>
                <div class="progress-bar"><div class="progress-fill" id="downloadProgressFill" style="width: 0%"></div></div>
                <div id="downloadStatus">准备中...</div>
            </div>
        </div>
    </div>

    <div id="shareModal" class="modal">
        <div class="modal-content">
            <h3>分享链接</h3>
            <input type="text" id="shareLink" readonly />
            <button class="btn" id="copyLinkBtn">复制链接</button>
            <button class="btn" style="background:#94a3b8;" id="closeModalBtn">关闭</button>
        </div>
    </div>

    <script>
        const MAX_FILE_SIZE = ${MAX_FILE_SIZE};
        let fileList = [];
        let selectedIds = new Set();
        let activeUploads = new Map();

        function showToast(msg) {
            const toast = document.createElement('div');
            toast.className = 'toast';
            toast.innerText = msg;
            document.body.appendChild(toast);
            setTimeout(() => toast.remove(), 3000);
        }

        function formatRemaining(expiresAt, permanent) {
            if (permanent) return '♾️ 永久';
            const now = Math.floor(Date.now() / 1000);
            const diff = expiresAt - now;
            if (diff <= 0) return '已过期';
            const hours = Math.floor(diff / 3600);
            const minutes = Math.floor((diff % 3600) / 60);
            return \`⏳ \${hours}h \${minutes}m\`;
        }

        async function loadFiles() {
            try {
                const res = await fetch('/api/admin/files');
                if (!res.ok) throw new Error('无权访问');
                const data = await res.json();
                fileList = data.files;
                renderFileList();
            } catch (err) {
                console.error(err);
                document.getElementById('fileList').innerHTML = '<p>加载失败，请刷新重试</p>';
            }
        }

        function renderFileList() {
            const container = document.getElementById('fileList');
            if (!fileList.length) {
                container.innerHTML = '<p>暂无文件</p>';
                return;
            }
            const html = \`
                <table>
                    <thead>
                        <tr>
                            <th class="checkbox-col"><input type="checkbox" id="selectAll"></th>
                            <th>文件名</th>
                            <th>大小</th>
                            <th>剩余时间</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody>
                        \${fileList.map(file => \`
                            <tr data-id="\${file.id}">
                                <td class="checkbox-col"><input type="checkbox" class="file-checkbox" value="\${file.id}" \${selectedIds.has(file.id) ? 'checked' : ''}> </td>
                                <td>\${escapeHtml(file.filename)}</td>
                                <td>\${(file.size / 1024).toFixed(1)} KB</td>
                                <td><span class="time-badge">\${formatRemaining(file.expiresAt, file.permanent)}</span></td>
                                <td class="file-actions">
                                    <button class="btn btn-small" onclick="downloadFile('\${file.id}')">下载</button>
                                    <button class="btn btn-small" onclick="shareFile('\${file.id}')">分享</button>
                                    <button class="btn btn-small btn-warning" onclick="makePermanent('\${file.id}')">转永久</button>
                                    <button class="btn btn-small btn-danger" onclick="deleteFileSingle('\${file.id}')">删除</button>
                                </td>
                            </tr>
                        \`).join('')}
                    </tbody>
                 </table>
            \`;
            container.innerHTML = html;
            document.getElementById('selectAll')?.addEventListener('change', (e) => {
                const checkboxes = document.querySelectorAll('.file-checkbox');
                checkboxes.forEach(cb => cb.checked = e.target.checked);
                updateSelected();
            });
            document.querySelectorAll('.file-checkbox').forEach(cb => {
                cb.addEventListener('change', updateSelected);
            });
            updateSelected();
        }

        function updateSelected() {
            selectedIds.clear();
            document.querySelectorAll('.file-checkbox:checked').forEach(cb => selectedIds.add(cb.value));
            document.getElementById('selectedCount').innerText = \`已选择 \${selectedIds.size} 个文件\`;
        }

        function escapeHtml(str) {
            return str.replace(/[&<>]/g, function(m) {
                if (m === '&') return '&amp;';
                if (m === '<') return '&lt;';
                if (m === '>') return '&gt;';
                return m;
            });
        }

        function addToQueue(file) {
            if (file.size > MAX_FILE_SIZE) {
                showToast(\`文件 "\${file.name}" 超过 25MB，已跳过\`);
                return;
            }
            const queueItem = {
                id: Date.now() + Math.random(),
                file: file,
                status: 'waiting',
                progress: 0,
                xhr: null
            };
            renderQueueItem(queueItem);
            processQueue(queueItem);
        }

        function renderQueueItem(item) {
            const queueDiv = document.getElementById('uploadQueue');
            let existing = document.getElementById(\`upload-item-\${item.id}\`);
            if (!existing) {
                existing = document.createElement('div');
                existing.id = \`upload-item-\${item.id}\`;
                existing.className = 'queue-item';
                queueDiv.appendChild(existing);
            }
            const statusText = {
                waiting: '等待中',
                uploading: '上传中',
                success: '✅ 完成',
                error: '❌ 失败'
            };
            existing.innerHTML = \`
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                    <span><strong>\${escapeHtml(item.file.name)}</strong> (\${(item.file.size / 1024).toFixed(1)} KB)</span>
                    <span>\${statusText[item.status]}</span>
                </div>
                \${item.status === 'uploading' || item.status === 'waiting' ? \`
                    <progress value="\${item.progress}" max="100"></progress>
                    <div style="display: flex; justify-content: flex-end; margin-top: 4px;">
                        <button class="btn-small" onclick="cancelUpload(\${item.id})">取消</button>
                    </div>
                \` : ''}
                \${item.status === 'success' ? '<div style="color: green;">上传成功</div>' : ''}
                \${item.status === 'error' ? '<div style="color: red;">上传失败，请重试</div>' : ''}
            \`;
        }

        function cancelUpload(id) {
            const item = activeUploads.get(id);
            if (item && item.xhr) {
                item.xhr.abort();
            }
            removeQueueItem(id);
        }

        function removeQueueItem(id) {
            const elem = document.getElementById(\`upload-item-\${id}\`);
            if (elem) elem.remove();
            activeUploads.delete(id);
        }

        async function processQueue(item) {
            if (item.status !== 'waiting') return;
            item.status = 'uploading';
            activeUploads.set(item.id, item);
            renderQueueItem(item);

            const formData = new FormData();
            formData.append('file', item.file);

            const xhr = new XMLHttpRequest();
            item.xhr = xhr;

            xhr.upload.addEventListener('progress', (e) => {
                if (e.lengthComputable) {
                    item.progress = Math.round((e.loaded / e.total) * 100);
                    renderQueueItem(item);
                }
            });

            xhr.onload = () => {
                if (xhr.status === 200) {
                    item.status = 'success';
                    renderQueueItem(item);
                    setTimeout(() => removeQueueItem(item.id), 2000);
                    loadFiles();
                } else {
                    item.status = 'error';
                    renderQueueItem(item);
                    setTimeout(() => removeQueueItem(item.id), 3000);
                }
                activeUploads.delete(item.id);
            };

            xhr.onerror = () => {
                item.status = 'error';
                renderQueueItem(item);
                setTimeout(() => removeQueueItem(item.id), 3000);
                activeUploads.delete(item.id);
            };

            xhr.onabort = () => {
                removeQueueItem(item.id);
            };

            xhr.open('POST', '/api/upload');
            xhr.send(formData);
        }

        function handleFiles(files) {
            for (let file of files) {
                addToQueue(file);
            }
        }

        async function batchDownload() {
            if (selectedIds.size === 0) {
                showToast('请先选择要下载的文件');
                return;
            }
            
            const progressDiv = document.getElementById('downloadProgress');
            const progressFill = document.getElementById('downloadProgressFill');
            const statusDiv = document.getElementById('downloadStatus');
            
            progressDiv.style.display = 'block';
            progressFill.style.width = '0%';
            statusDiv.innerText = '正在准备下载...';
            
            try {
                const selectedFiles = fileList.filter(f => selectedIds.has(f.id));
                let downloaded = 0;
                const filesData = [];
                
                for (const file of selectedFiles) {
                    statusDiv.innerText = \`正在下载: \${file.filename} (\${downloaded + 1}/\${selectedFiles.length})\`;
                    const progress = (downloaded / selectedFiles.length) * 100;
                    progressFill.style.width = progress + '%';
                    
                    const response = await fetch(\`/api/download/\${file.id}\`);
                    if (!response.ok) throw new Error(\`下载 \${file.filename} 失败\`);
                    
                    const blob = await response.blob();
                    filesData.push({
                        filename: file.filename,
                        data: await blob.arrayBuffer()
                    });
                    
                    downloaded++;
                    const newProgress = (downloaded / selectedFiles.length) * 100;
                    progressFill.style.width = newProgress + '%';
                }
                
                statusDiv.innerText = '正在打包成 ZIP 文件...';
                progressFill.style.width = '90%';
                
                const zipBlob = await createZip(filesData);
                
                statusDiv.innerText = '下载中...';
                progressFill.style.width = '100%';
                
                const downloadUrl = URL.createObjectURL(zipBlob);
                const a = document.createElement('a');
                a.href = downloadUrl;
                a.download = \`admin_files_\${new Date().getTime()}.zip\`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(downloadUrl);
                
                setTimeout(() => {
                    progressDiv.style.display = 'none';
                }, 2000);
                
                showToast(\`成功下载 \${selectedFiles.length} 个文件\`);
            } catch (err) {
                console.error('批量下载失败:', err);
                statusDiv.innerText = '下载失败: ' + err.message;
                showToast('批量下载失败: ' + err.message);
                setTimeout(() => {
                    progressDiv.style.display = 'none';
                }, 3000);
            }
        }
        
        async function createZip(filesData) {
            return new Promise((resolve, reject) => {
                if (window.JSZip) {
                    const zip = new JSZip();
                    for (const file of filesData) {
                        zip.file(file.filename, file.data);
                    }
                    zip.generateAsync({ type: 'blob' })
                        .then(resolve)
                        .catch(reject);
                } else {
                    const script = document.createElement('script');
                    script.src = 'https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js';
                    script.onload = () => {
                        const zip = new JSZip();
                        for (const file of filesData) {
                            zip.file(file.filename, file.data);
                        }
                        zip.generateAsync({ type: 'blob' })
                            .then(resolve)
                            .catch(reject);
                    };
                    script.onerror = () => reject(new Error('加载 JSZip 失败'));
                    document.head.appendChild(script);
                }
            });
        }

        async function makePermanent(id) {
            if (!confirm('确认将文件转为永久？')) return;
            const res = await fetch(\`/api/file/\${id}/permanent\`, { method: 'POST' });
            if (res.ok) { showToast('已转为永久'); loadFiles(); }
            else showToast('操作失败');
        }

        async function deleteFileSingle(id) {
            if (!confirm('确认删除此文件？')) return;
            const res = await fetch(\`/api/file/\${id}\`, { method: 'DELETE' });
            if (res.ok) { showToast('已删除'); loadFiles(); }
            else showToast('删除失败');
        }

        async function batchDelete() {
            if (selectedIds.size === 0) return showToast('未选择任何文件');
            if (!confirm(\`确认删除 \${selectedIds.size} 个文件？\`)) return;
            for (let id of selectedIds) {
                await fetch(\`/api/file/\${id}\`, { method: 'DELETE' });
            }
            selectedIds.clear();
            loadFiles();
            showToast('批量删除完成');
        }

        async function batchPermanent() {
            if (selectedIds.size === 0) return showToast('未选择任何文件');
            if (!confirm(\`确认将 \${selectedIds.size} 个文件转为永久？\`)) return;
            for (let id of selectedIds) {
                await fetch(\`/api/file/\${id}/permanent\`, { method: 'POST' });
            }
            loadFiles();
            showToast('批量转永久完成');
        }

        function downloadFile(id) { 
            window.open(\`/api/download/\${id}\`, '_blank'); 
        }
        
        function shareFile(id) {
            const link = \`\${window.location.origin}/api/download/\${id}\`;
            document.getElementById('shareLink').value = link;
            document.getElementById('shareModal').style.display = 'flex';
        }

        document.getElementById('loginBtn').addEventListener('click', async () => {
            const token = document.getElementById('totpInput').value.trim();
            if (!token) return;
            const res = await fetch('/api/admin/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) });
            if (res.ok) {
                document.getElementById('loginModal').style.display = 'none';
                document.getElementById('adminContent').style.display = 'block';
                loadFiles();
                document.getElementById('uploadArea').addEventListener('click', () => document.getElementById('fileInput').click());
                document.getElementById('fileInput').addEventListener('change', (e) => {
                    if (e.target.files.length) {
                        handleFiles(Array.from(e.target.files));
                    }
                    e.target.value = '';
                });
                document.getElementById('refreshBtn').addEventListener('click', loadFiles);
                document.getElementById('batchDeleteBtn').addEventListener('click', batchDelete);
                document.getElementById('batchPermanentBtn').addEventListener('click', batchPermanent);
                document.getElementById('batchDownloadBtn').addEventListener('click', batchDownload);
                const dropZone = document.getElementById('uploadArea');
                dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.style.borderColor = '#3b82f6'; });
                dropZone.addEventListener('dragleave', () => dropZone.style.borderColor = '#cbd5e1');
                dropZone.addEventListener('drop', (e) => {
                    e.preventDefault();
                    dropZone.style.borderColor = '#cbd5e1';
                    if (e.dataTransfer.files.length) {
                        handleFiles(Array.from(e.dataTransfer.files));
                    }
                });
            } else {
                document.getElementById('loginError').innerText = 'TOTP 验证失败';
            }
        });

        document.getElementById('copyLinkBtn').addEventListener('click', () => {
            const input = document.getElementById('shareLink');
            input.select();
            document.execCommand('copy');
            showToast('已复制链接');
        });
        document.getElementById('closeModalBtn').addEventListener('click', () => document.getElementById('shareModal').style.display = 'none');
        window.addEventListener('click', (e) => { if (e.target === document.getElementById('shareModal')) document.getElementById('shareModal').style.display = 'none'; });
    </script>
</body>
</html>`;
}

// ==================== 路由处理 ====================

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // 公共页面
    if (path === '/' || path === '/index') {
      return new Response(getIndexPage(), { headers: { 'Content-Type': 'text/html' } });
    }

    // 管理员页面
    if (path === '/main') {
      return new Response(getAdminPage(), { headers: { 'Content-Type': 'text/html' } });
    }

    // API: 管理员登录 (TOTP)
    if (path === '/api/admin/login' && request.method === 'POST') {
      const { token } = await request.json();
      const secret = env.TOTP_SECRET;
      if (!secret) return new Response('TOTP未配置', { status: 500 });
      const valid = await verifyTOTP(token, secret);
      if (!valid) return new Response('Invalid TOTP', { status: 401 });
      const sessionId = await createAdminSession(env);
      return new Response(JSON.stringify({ success: true }), {
        headers: { 'Set-Cookie': `admin_session=${sessionId}; HttpOnly; Path=/; Max-Age=${env.ADMIN_SESSION_TTL || 3600}`, 'Content-Type': 'application/json' }
      });
    }

    // API: 公共文件列表
    if (path === '/api/files' && request.method === 'GET') {
      const files = await listPublicFiles(env);
      return new Response(JSON.stringify({ files }), { headers: { 'Content-Type': 'application/json' } });
    }

    // API: 管理员文件列表 (需要会话)
    if (path === '/api/admin/files' && request.method === 'GET') {
      const isAdmin = await verifyAdminSession(request, env);
      if (!isAdmin) return new Response('Unauthorized', { status: 401 });
      const files = await listAdminFiles(env);
      return new Response(JSON.stringify({ files }), { headers: { 'Content-Type': 'application/json' } });
    }

    // API: 上传文件
    if (path === '/api/upload' && request.method === 'POST') {
      const formData = await request.formData();
      const file = formData.get('file');
      if (!file) return new Response('No file', { status: 400 });
      if (file.size > MAX_FILE_SIZE) return new Response('File too large (max 25MB)', { status: 413 });
      const fileId = generateUUID();
      const buffer = await file.arrayBuffer();
      const meta = await saveFile(env, fileId, buffer, file.name, file.type, file.size, false);
      return new Response(JSON.stringify({ id: fileId, filename: file.name }), { headers: { 'Content-Type': 'application/json' } });
    }

    // API: 下载文件 (公开)
    if (path.startsWith('/api/download/')) {
      const fileId = path.split('/').pop();
      const meta = await getFileMeta(env, fileId, true);
      if (!meta) return new Response('File not found or expired', { status: 404 });
      const data = await env.FILE_STORAGE.get(`data:${fileId}`, 'arrayBuffer');
      if (!data) return new Response('File data missing', { status: 404 });
      return new Response(data, {
        headers: {
          'Content-Type': meta.contentType || 'application/octet-stream',
          'Content-Disposition': `attachment; filename="${encodeURIComponent(meta.filename)}"`,
          'Cache-Control': 'public, max-age=3600'
        }
      });
    }

    // 需要管理员验证的操作
    const isAdmin = await verifyAdminSession(request, env);
    if (!isAdmin) return new Response('Unauthorized', { status: 401 });

    // 删除文件
    if (path.startsWith('/api/file/') && request.method === 'DELETE') {
      const fileId = path.split('/').pop();
      await deleteFile(env, fileId);
      return new Response('OK');
    }

    // 转永久
    if (path.startsWith('/api/file/') && path.endsWith('/permanent') && request.method === 'POST') {
      const fileId = path.split('/')[3];
      const meta = await env.FILE_STORAGE.get(`meta:${fileId}`, 'json');
      if (!meta) return new Response('File not found', { status: 404 });
      meta.permanent = true;
      meta.expiresAt = PERMANENT_EXPIRY;
      await env.FILE_STORAGE.put(`meta:${fileId}`, JSON.stringify(meta));
      return new Response('OK');
    }

    return new Response('Not Found', { status: 404 });
  }
};