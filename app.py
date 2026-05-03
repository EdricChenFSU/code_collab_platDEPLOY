import re
import sqlite3
import subprocess
import time
import threading
import json
import io
import zipfile
import shutil
import bcrypt
from flask import Flask, request, jsonify, session, send_from_directory, redirect, send_file
from flask_sock import Sock
import os

app = Flask(__name__, static_folder='public')
app.secret_key = os.environ.get('SECRET_KEY', 'change-this-in-production')
# config app for additional security
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SECRET_KEY') is not None

sock = Sock(app)

DATA_DIR = os.environ.get('DATA_DIR', '.')
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, 'users.db')
ACCOUNTS_DIR = os.path.join(DATA_DIR, 'accounts')
HEARTBEAT_TIMEOUT = 30

active_users = {}
_signaling_topics = {}
_signaling_lock = threading.Lock()
_project_channels = {}
_project_live_files = {}
_project_edit_locks = {}
_project_channels_lock = threading.Lock()
PROJECT_NAME_RE = re.compile(r'^[a-zA-Z0-9_-]{1,64}$')
FILE_PATH_RE = re.compile(r'^[a-zA-Z0-9_./-]{1,160}$')
DEFAULT_FILES = {
    'README.md': '# New Project\n\nDescribe what this project does here.\n'
}


def get_db():
    """Open a SQLite connection with row_factory set to sqlite3.Row."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def user_exists(username):
    """Return True if a username still exists in the database."""
    if not username:
        return False
    with get_db() as conn:
        return bool(conn.execute('SELECT 1 FROM users WHERE username = ?', (username,)).fetchone())


def clear_stale_session():
    """Clear a browser session whose user no longer exists."""
    username = session.get('username')
    if username and not user_exists(username):
        active_users.pop(username, None)
        session.clear()
        return True
    return False


@app.before_request
def guard_stale_session():
    """Log out stale browser sessions before protected routes run."""
    if not clear_stale_session():
        return None
    if request.path.startswith('/api/'):
        return jsonify(error='Session user no longer exists.'), 401
    if request.path.startswith('/home') or request.path.startswith('/projects') or request.path.startswith('/collaborate'):
        return redirect('/login.html')
    return None


def is_safe_file_path(file_path):
    """Return True if file_path is safe to use within a project's files directory.

    Rejects paths with '..', absolute paths, trailing slashes, and characters
    outside the FILE_PATH_RE allowlist.
    """
    return (
        FILE_PATH_RE.match(file_path)
        and '..' not in file_path.split('/')
        and not file_path.startswith('/')
        and not file_path.endswith('/')
    )


def build_file_tree(files_dir, relative_dir=''):
    """Recursively build a JSON-serialisable file tree for a project's files directory.

    Returns a list of nodes, each with 'name', 'path', and 'type' ('file' or 'folder').
    Folders include a 'children' list. Files are sorted before folders at each level.
    """
    tree = []
    current_dir = os.path.join(files_dir, relative_dir)
    entries = sorted(
        os.listdir(current_dir),
        key=lambda entry: (
            os.path.isdir(os.path.join(current_dir, entry)),
            entry.lower()
        )
    )

    for name in entries:
        full_path = os.path.join(current_dir, name)
        relative_path = os.path.join(relative_dir, name).replace(os.sep, '/')
        if os.path.isdir(full_path):
            tree.append({
                'name': name,
                'path': relative_path,
                'type': 'folder',
                'children': build_file_tree(files_dir, relative_path)
            })
        else:
            tree.append({'name': name, 'path': relative_path, 'type': 'file'})

    return tree


def project_files_dir(username, project_name):
    """Return the filesystem path to a project's files directory."""
    return os.path.join(ACCOUNTS_DIR, username, 'projects', project_name, 'files')


def persist_project_file(owner, project_name, file_path, content):
    """Persist saved editor content to disk."""
    if not is_safe_file_path(file_path):
        return False
    if len(content) > 100000:
        return False

    files_dir = project_files_dir(owner, project_name)
    if not os.path.isdir(files_dir):
        return False

    full_path = os.path.join(files_dir, file_path)
    if os.path.isdir(full_path):
        return False

    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    with open(full_path, 'w') as f:
        f.write(content)
    return True


def read_project_file(owner, project_name, file_path):
    """Read saved file content from disk."""
    if not is_safe_file_path(file_path):
        return ''
    full_path = os.path.join(project_files_dir(owner, project_name), file_path)
    if not os.path.isfile(full_path):
        return ''
    with open(full_path) as f:
        return f.read()


def download_project_path(files_dir, item_path='', archive_name='project'):
    """Return a file download or zipped folder download from a project files directory."""
    if item_path and not is_safe_file_path(item_path):
        return jsonify(error='Invalid path.'), 400
    if not os.path.isdir(files_dir):
        return jsonify(error='Project not found.'), 404

    full_path = os.path.join(files_dir, item_path) if item_path else files_dir
    if item_path and os.path.isfile(full_path):
        return send_file(full_path, as_attachment=True, download_name=os.path.basename(full_path))
    if not os.path.isdir(full_path):
        return jsonify(error='File or folder not found.'), 404

    archive = io.BytesIO()
    folder_name = os.path.basename(item_path.rstrip('/')) if item_path else archive_name
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for root, _, filenames in os.walk(full_path):
            for filename in filenames:
                source_path = os.path.join(root, filename)
                relative_path = os.path.relpath(source_path, files_dir)
                zip_file.write(source_path, relative_path)
    archive.seek(0)

    return send_file(
        archive,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f'{folder_name}.zip'
    )


def delete_project_path(files_dir, item_path):
    """Delete a file or folder inside a project files directory."""
    if not is_safe_file_path(item_path):
        return jsonify(error='Invalid path.'), 400
    if not os.path.isdir(files_dir):
        return jsonify(error='Project not found.'), 404

    full_path = os.path.join(files_dir, item_path)
    if os.path.isfile(full_path):
        os.remove(full_path)
    elif os.path.isdir(full_path):
        shutil.rmtree(full_path)
    else:
        return jsonify(error='File or folder not found.'), 404

    parent_dir = os.path.dirname(full_path)
    while parent_dir != files_dir and os.path.isdir(parent_dir) and not os.listdir(parent_dir):
        os.rmdir(parent_dir)
        parent_dir = os.path.dirname(parent_dir)
    return jsonify(ok=True)


def has_collab_access(username, owner, project_name):
    """Return True if username is the owner or has an accepted invitation for owner/project_name."""
    if username == owner:
        return True
    if not PROJECT_NAME_RE.match(project_name):
        return False
    with get_db() as conn:
        return bool(conn.execute(
            'SELECT 1 FROM invitations WHERE sender=? AND recipient=? AND project_name=? AND status=?',
            (owner, username, project_name, 'accepted')
        ).fetchone())


def workspace_html(title, back_url, files_api, folders_api, yjs_owner, yjs_project):
    """Generate a project workspace HTML page with Monaco editor and live sync.

    files_api  — base path for file CRUD (e.g. /api/projects/foo or /api/collaborate/alice/foo)
    folders_api — base path for folder creation
    yjs_owner / yjs_project — identify the owner/project sync room shared by collaborators
    """
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{title}</title>
  <link rel="stylesheet" href="/style.css" />
</head>
<body class="workspace-body">
  <div class="workspace-shell">
    <header class="workspace-topbar">
      <div>
        <p class="eyebrow">Collaborative Workspace</p>
        <h1>{title}</h1>
      </div>
      <div class="topbar-actions">
        <span id="collab-status" class="collab-status"></span>
        <a id="back-link" href="{back_url}" class="btn btn-outline">Back</a>
      </div>
    </header>

    <div class="workspace">
      <aside class="sidebar explorer-sidebar">
        <div class="panel-heading">
          <h2>Files</h2>
          <span class="panel-subtitle">Project explorer</span>
        </div>
        <div class="folder-context">
          <button id="root-folder" class="folder-select active-folder" type="button">/</button>
          <p class="current-folder">Current folder: <span id="current-folder">/</span></p>
        </div>
        <div id="selected-actions" class="selected-actions hidden">
          <p>Selected: <span id="selected-item-label">/</span></p>
          <div>
            <button id="download-selected" class="file-download" type="button">Download</button>
            <button id="delete-selected" class="file-delete" type="button">Delete</button>
          </div>
        </div>
        <ul id="file-list" class="file-list"></ul>
        <div class="create-stack">
          <form id="create-file-form">
            <input type="text" id="file-name" placeholder="File name" autocomplete="off" required />
            <button type="submit" class="btn">Add File</button>
          </form>
          <form id="create-folder-form">
            <input type="text" id="folder-name" placeholder="Folder name" autocomplete="off" required />
            <button type="submit" class="btn btn-outline">Add Folder</button>
          </form>
        </div>
      </aside>
      <main class="editor-panel">
        <div class="editor-toolbar">
          <div>
            <p class="eyebrow">Active File</p>
            <strong id="active-file">Select a file</strong>
          </div>
          <div class="editor-actions">
            <button id="run" class="btn btn-run" type="button" disabled>Run</button>
            <button id="revert" class="btn btn-outline" type="button">Revert</button>
            <button id="save" class="btn" type="button">Save File</button>
          </div>
        </div>
        <div id="editor-lock-banner" class="editor-lock-banner hidden"></div>
        <div id="content" class="code-editor"></div>
        <p id="status" class="status"></p>
      </main>
    </div>

    <div class="console-panel">
      <div class="console-toolbar">
        <span class="console-label">Console</span>
        <button id="clear-console" class="btn btn-sm btn-outline" type="button">Clear</button>
      </div>
      <pre id="console-output" class="console-output">Output will appear here.</pre>
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/monaco-editor@0.52.0/min/vs/loader.js"></script>

  <script>
    let editor;
    let projectSocket = null;
    let applyingRemoteChange = false;
    let editorChangeTimer = null;
    let savedContent = '';
    let hasUnsavedChanges = false;
    let activeEditorName = '';
    const CLIENT_ID = window.crypto && crypto.randomUUID ? crypto.randomUUID() : String(Date.now() + Math.random());
    const PROJECT_SOCKET_URL = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws/projects/{yjs_owner}/{yjs_project}';

    require.config({{
      paths: {{ vs: 'https://cdn.jsdelivr.net/npm/monaco-editor@0.52.0/min/vs' }}
    }});

    require(['vs/editor/editor.main'], function () {{
      editor = monaco.editor.create(document.getElementById('content'), {{
        value: '',
        language: 'python',
        theme: 'vs-dark',
        automaticLayout: true,
        minimap: {{ enabled: false }}
      }});

      editor.onDidChangeModelContent(() => {{
        if (applyingRemoteChange || !currentFile) return;
        hasUnsavedChanges = editor.getValue() !== savedContent;
        updateDirtyStatus();
        clearTimeout(editorChangeTimer);
        editorChangeTimer = setTimeout(() => {{
          sendProjectMessage({{
            type: 'file_update',
            file: currentFile,
            content: editor.getValue()
          }});
        }}, 120);
      }});

      connectProjectSocket();
      loadFiles();
    }});

    fetch('/api/me').then(r => {{
      if (!r.ok) {{ window.location.href = '/login.html'; }}
    }});

    function connectProjectSocket() {{
      projectSocket = new WebSocket(PROJECT_SOCKET_URL);
      projectSocket.addEventListener('open', () => {{
        document.getElementById('collab-status').textContent = 'Live sync connected';
        if (currentFile) sendProjectMessage({{ type: 'open_file', file: currentFile }});
      }});
      projectSocket.addEventListener('message', event => {{
        const message = JSON.parse(event.data);

        if (message.type === 'file_update' && message.file === currentFile) {{
          if (message.sender === CLIENT_ID) return;
          applyingRemoteChange = true;
          if (editor.getValue() !== message.content) {{
            editor.setValue(message.content);
          }}
          applyingRemoteChange = false;
          setReadOnlyViewer(message.editor || 'A collaborator');
        }}

        if (message.type === 'lock_state' && message.file === currentFile) {{
          if (message.editor_client === CLIENT_ID || !message.editor) {{
            clearReadOnlyViewer();
          }} else {{
            setReadOnlyViewer(message.editor);
          }}
          if (message.content !== undefined && message.editor_client !== CLIENT_ID) {{
            applyingRemoteChange = true;
            editor.setValue(message.content);
            applyingRemoteChange = false;
          }}
        }}

        if (message.type === 'file_saved' && message.file === currentFile) {{
          savedContent = message.content;
          hasUnsavedChanges = false;
          applyingRemoteChange = true;
          editor.setValue(message.content);
          applyingRemoteChange = false;
          clearReadOnlyViewer();
          updateDirtyStatus();
        }}

        if (message.type === 'edit_reverted' && message.file === currentFile) {{
          savedContent = message.content;
          hasUnsavedChanges = false;
          applyingRemoteChange = true;
          editor.setValue(message.content);
          applyingRemoteChange = false;
          clearReadOnlyViewer();
          updateDirtyStatus();
        }}

        if (message.type === 'files_changed') {{
          loadFiles();
        }}
      }});
      projectSocket.addEventListener('close', () => {{
        document.getElementById('collab-status').textContent = 'Reconnecting live sync...';
        setTimeout(connectProjectSocket, 1500);
      }});
    }}

    function sendProjectMessage(message) {{
      if (!projectSocket || projectSocket.readyState !== WebSocket.OPEN) return;
      projectSocket.send(JSON.stringify({{ ...message, sender: CLIENT_ID }}));
    }}

    const status = document.getElementById('status');
    const save = document.getElementById('save');
    const revert = document.getElementById('revert');
    const activeFile = document.getElementById('active-file');
    const fileList = document.getElementById('file-list');
    const rootFolder = document.getElementById('root-folder');
    const currentFolderLabel = document.getElementById('current-folder');
    const lockBanner = document.getElementById('editor-lock-banner');
    const backLink = document.getElementById('back-link');
    const selectedActions = document.getElementById('selected-actions');
    const selectedItemLabel = document.getElementById('selected-item-label');
    const downloadSelected = document.getElementById('download-selected');
    const deleteSelected = document.getElementById('delete-selected');
    let currentFile = '';
    let selectedFolder = '';
    let selectedItem = {{ path: '', type: 'root' }};
    const openFolders = new Set();

    rootFolder.addEventListener('click', () => {{
      selectFolder('');
      selectItem('', 'root');
    }});
    downloadSelected.addEventListener('click', () => downloadPath(selectedItem.path));
    deleteSelected.addEventListener('click', () => deletePath(selectedItem.path, selectedItem.type));
    backLink.addEventListener('click', handleBackNavigation);
    window.addEventListener('beforeunload', e => {{
      if (!hasUnsavedChanges) return;
      e.preventDefault();
      e.returnValue = '';
    }});

    function updateDirtyStatus() {{
      if (!currentFile) return;
      status.textContent = hasUnsavedChanges ? 'Unsaved changes.' : '';
    }}

    function setReadOnlyViewer(editorName) {{
      activeEditorName = editorName;
      editor.updateOptions({{ readOnly: true }});
      lockBanner.textContent = `${{editorName}} is currently editing. You can watch their changes live.`;
      lockBanner.classList.remove('hidden');
    }}

    function clearReadOnlyViewer() {{
      activeEditorName = '';
      editor.updateOptions({{ readOnly: false }});
      lockBanner.classList.add('hidden');
      lockBanner.textContent = '';
    }}

    async function handleBackNavigation(event) {{
      if (!hasUnsavedChanges) return;
      event.preventDefault();
      const keep = window.confirm('You have unsaved changes. Press OK to save them before leaving, or Cancel to discard them.');
      if (keep) {{
        const saved = await saveCurrentFile();
        if (!saved) return;
      }} else {{
        revertCurrentFile();
      }}
      window.location.href = backLink.href;
    }}

    function joinPath(folderPath, itemName) {{
      return folderPath ? `${{folderPath}}/${{itemName}}` : itemName;
    }}

    function selectFolder(folderPath) {{
      selectedFolder = folderPath;
      currentFolderLabel.textContent = selectedFolder || '/';
      rootFolder.classList.toggle('active-folder', selectedFolder === '');
      for (const button of document.querySelectorAll('.folder-select[data-path]')) {{
        button.classList.toggle('active-folder', button.dataset.path === selectedFolder);
      }}
    }}

    function selectItem(itemPath, itemType) {{
      selectedItem = {{ path: itemPath, type: itemType }};
      selectedActions.classList.remove('hidden');
      selectedItemLabel.textContent = itemPath || '/';
      deleteSelected.classList.toggle('hidden', itemType === 'root');
      for (const item of document.querySelectorAll('.selected-tree-item')) {{
        item.classList.remove('selected-tree-item');
      }}
      const selector = itemPath ? `[data-path="${{CSS.escape(itemPath)}}"]` : '#root-folder';
      const selectedElement = document.querySelector(selector);
      if (selectedElement) selectedElement.classList.add('selected-tree-item');
    }}

    function toggleFolder(folderPath) {{
      if (openFolders.has(folderPath)) {{
        openFolders.delete(folderPath);
      }} else {{
        openFolders.add(folderPath);
      }}
      selectFolder(folderPath);
      selectItem(folderPath, 'folder');
      loadFiles();
    }}

    async function loadFiles() {{
      const res = await fetch('{files_api}/files');
      const data = await res.json();
      fileList.innerHTML = '';
      renderTree(data.tree, fileList);
      selectFolder(selectedFolder);
      if (!selectedActions.classList.contains('hidden')) {{
        selectItem(selectedItem.path, selectedItem.type);
      }}
      if (data.files.length === 0) {{
        currentFile = '';
        activeFile.textContent = 'Select a file';
        savedContent = '';
        hasUnsavedChanges = false;
        clearReadOnlyViewer();
        editor.setValue('');
        updateRunButton();
      }} else if (!currentFile || !data.files.includes(currentFile)) {{
        loadFile(data.files[0]);
      }}
    }}

    function renderTree(nodes, parent) {{
      for (const node of nodes) {{
        const li = document.createElement('li');
        li.className = node.type === 'folder' ? 'tree-folder' : 'file-item';

        if (node.type === 'folder') {{
          const folderButton = document.createElement('button');
          folderButton.type = 'button';
          const isOpen = openFolders.has(node.path);
          folderButton.className = isOpen ? 'folder-select folder-open' : 'folder-select';
          folderButton.dataset.path = node.path;
          folderButton.textContent = node.name + '/';
          folderButton.title = node.path;
          folderButton.addEventListener('click', () => toggleFolder(node.path));
          li.appendChild(folderButton);

          if (isOpen) {{
            const childList = document.createElement('ul');
            childList.className = 'file-list nested-file-list';
            renderTree(node.children, childList);
            li.appendChild(childList);
          }}
        }} else {{
          const button = document.createElement('button');
          button.type = 'button';
          button.className = 'file-open';
          button.textContent = node.name;
          button.title = node.path;
          button.addEventListener('click', () => {{
            selectItem(node.path, 'file');
            loadFile(node.path);
          }});
          li.appendChild(button);
        }}

        parent.appendChild(li);
      }}
    }}

    async function loadFile(filePath) {{
      if (hasUnsavedChanges) {{
        const discard = window.confirm('Discard unsaved changes and open another file?');
        if (!discard) return;
        revertCurrentFile();
      }}
      const res = await fetch(`{files_api}/files/${{encodeURIComponent(filePath)}}`);
      const data = await res.json();
      if (!data.ok) {{
        status.textContent = data.error;
        return;
      }}
      currentFile = filePath;
      activeFile.textContent = filePath;
      savedContent = data.content;
      hasUnsavedChanges = false;
      clearReadOnlyViewer();
      applyingRemoteChange = true;
      editor.setValue(data.content);
      applyingRemoteChange = false;
      status.textContent = '';
      sendProjectMessage({{ type: 'open_file', file: currentFile }});
      updateRunButton();
    }}

    async function saveCurrentFile() {{
      if (activeEditorName) {{
        status.textContent = `${{activeEditorName}} is currently editing this file.`;
        return false;
      }}
      if (!currentFile) {{
        status.textContent = 'Select a file first.';
        return false;
      }}
      status.textContent = 'Saving...';
      const res = await fetch(`{files_api}/files/${{encodeURIComponent(currentFile)}}`, {{
        method: 'PUT',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ content: editor.getValue() }})
      }});
      const data = await res.json();
      if (data.ok) {{
        savedContent = editor.getValue();
        hasUnsavedChanges = false;
        sendProjectMessage({{ type: 'file_saved', file: currentFile, content: savedContent }});
        clearReadOnlyViewer();
        status.textContent = 'Saved.';
        return true;
      }} else {{
        status.textContent = data.error;
        return false;
      }}
    }}

    function revertCurrentFile() {{
      if (!currentFile) return;
      if (activeEditorName) {{
        status.textContent = `${{activeEditorName}} is currently editing this file.`;
        return;
      }}
      applyingRemoteChange = true;
      editor.setValue(savedContent);
      applyingRemoteChange = false;
      hasUnsavedChanges = false;
      sendProjectMessage({{ type: 'edit_reverted', file: currentFile, content: savedContent }});
      clearReadOnlyViewer();
      status.textContent = 'Reverted to last saved version.';
    }}

    save.addEventListener('click', saveCurrentFile);
    revert.addEventListener('click', revertCurrentFile);

    const runBtn = document.getElementById('run');
    const consoleOutput = document.getElementById('console-output');

    function updateRunButton() {{
      runBtn.disabled = !currentFile || !currentFile.endsWith('.py');
    }}

    function clearConsole() {{
      consoleOutput.innerHTML = '';
    }}

    function appendConsole(text, type) {{
      const span = document.createElement('span');
      if (type) span.className = 'console-line-' + type;
      span.textContent = text;
      consoleOutput.appendChild(span);
      consoleOutput.scrollTop = consoleOutput.scrollHeight;
    }}

    async function runCurrentFile() {{
      if (!currentFile || !currentFile.endsWith('.py')) return;
      clearConsole();
      appendConsole('$ python3 ' + currentFile + '\\n', 'info');
      runBtn.disabled = true;
      runBtn.textContent = 'Running...';
      if (hasUnsavedChanges && !activeEditorName) {{
        appendConsole('Saving...\\n', 'muted');
        const saved = await saveCurrentFile();
        if (!saved) {{
          appendConsole('Run cancelled: save failed.\\n', 'stderr');
          runBtn.textContent = 'Run';
          updateRunButton();
          return;
        }}
      }}
      try {{
        const res = await fetch(`{files_api}/run/${{encodeURIComponent(currentFile)}}`, {{
          method: 'POST'
        }});
        const data = await res.json();
        if (!res.ok) {{
          appendConsole((data.error || 'Server error.') + '\\n', 'stderr');
          return;
        }}
        if (data.stdout) appendConsole(data.stdout, 'stdout');
        if (data.stderr) appendConsole(data.stderr, 'stderr');
        if (!data.stdout && !data.stderr) appendConsole('(no output)\\n', 'muted');
        appendConsole('\\n─── exit ' + data.exit_code + ' ───\\n', data.exit_code === 0 ? 'success' : 'error');
      }} catch (e) {{
        appendConsole('Request failed: ' + e.message + '\\n', 'stderr');
      }} finally {{
        runBtn.textContent = 'Run';
        updateRunButton();
      }}
    }}

    runBtn.addEventListener('click', runCurrentFile);
    document.getElementById('clear-console').addEventListener('click', clearConsole);

    function downloadPath(itemPath) {{
      window.location.href = itemPath ? `{files_api}/download/${{encodeURIComponent(itemPath)}}` : `{files_api}/download`;
    }}

    async function deletePath(itemPath, itemType) {{
      if (!itemPath || itemType === 'root') return;
      const confirmed = window.confirm(`Delete ${{itemType}} ${{itemPath}}?`);
      if (!confirmed) return;

      const res = await fetch(`{files_api}/files/${{encodeURIComponent(itemPath)}}`, {{
        method: 'DELETE'
      }});
      const data = await res.json();
      if (!data.ok) {{
        status.textContent = data.error;
        return;
      }}

      if (currentFile === itemPath || currentFile.startsWith(itemPath + '/')) {{
        currentFile = '';
        activeFile.textContent = 'Select a file';
        editor.setValue('');
      }}
      selectedItem = {{ path: '', type: 'root' }};
      selectedActions.classList.add('hidden');
      sendProjectMessage({{ type: 'files_changed' }});
      status.textContent = 'Deleted.';
      await loadFiles();
    }}

    document.getElementById('create-file-form').addEventListener('submit', async e => {{
      e.preventDefault();
      const fileName = document.getElementById('file-name').value.trim();
      const filePath = joinPath(selectedFolder, fileName);
      const res = await fetch(`{files_api}/files/${{encodeURIComponent(filePath)}}`, {{
        method: 'PUT',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ content: '' }})
      }});
      const data = await res.json();
      if (data.ok) {{
        document.getElementById('file-name').value = '';
        currentFile = filePath;
        sendProjectMessage({{ type: 'files_changed' }});
        await loadFiles();
        await loadFile(currentFile);
      }} else {{
        status.textContent = data.error;
      }}
    }});

    document.getElementById('create-folder-form').addEventListener('submit', async e => {{
      e.preventDefault();
      const folderName = document.getElementById('folder-name').value.trim();
      const folderPath = joinPath(selectedFolder, folderName);
      const res = await fetch(`{folders_api}/folders/${{encodeURIComponent(folderPath)}}`, {{
        method: 'POST'
      }});
      const data = await res.json();
      if (data.ok) {{
        document.getElementById('folder-name').value = '';
        selectFolder(folderPath);
        sendProjectMessage({{ type: 'files_changed' }});
        status.textContent = 'Folder created.';
        await loadFiles();
      }} else {{
        status.textContent = data.error;
      }}
    }});
  </script>
</body>
</html>"""


def create_user_home(username):
    """Generate and write the user's home page HTML to accounts/<username>/home.html.

    Called on registration and on every server startup for all existing users.
    The page includes the online users list, My Projects tab, and Invitations tab.
    """
    user_dir = os.path.join(ACCOUNTS_DIR, username)
    os.makedirs(user_dir, exist_ok=True)
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{username}</title>
  <link rel="stylesheet" href="/style.css" />
</head>
<body class="dashboard-body">
  <div class="dashboard-shell">
    <aside class="app-rail">
      <div class="brand-block">
        <span class="brand-mark">AI</span>
        <div>
          <strong>CodeSpace</strong>
          <span>{username}</span>
        </div>
      </div>
      <nav class="tabs">
        <button class="tab-btn active" data-tab="projects">Projects</button>
        <button class="tab-btn" data-tab="shared">Shared</button>
        <button class="tab-btn" data-tab="invitations">Invites <span id="invite-badge" class="badge hidden">0</span></button>
      </nav>
      <button id="logout" class="btn btn-outline rail-logout">Logout</button>
    </aside>

    <main class="dashboard-main">
      <header class="dashboard-hero">
        <div>
          <p class="eyebrow">Workspace Dashboard</p>
          <h1>Build with your team</h1>
          <p class="muted">Create projects, invite collaborators, and edit files live from one workspace.</p>
        </div>
        <form id="create-project-form" class="quick-create">
          <input type="text" id="project-name" placeholder="New project name" autocomplete="off" required />
          <button type="submit" class="btn">Create Project</button>
          <p id="error" class="error hidden"></p>
        </form>
      </header>

      <section id="tab-projects" class="tab-panel dashboard-section">
        <div class="section-header">
          <div>
            <p class="eyebrow">Owned by you</p>
            <h2>My Projects</h2>
          </div>
        </div>
        <ul id="project-list" class="project-list project-grid"></ul>
      </section>

      <section id="tab-shared" class="tab-panel dashboard-section hidden">
        <div class="section-header">
          <div>
            <p class="eyebrow">Collaborating</p>
            <h2>Shared Projects</h2>
          </div>
        </div>
        <ul id="shared-project-list" class="project-list project-grid"><li class="empty">No shared projects yet.</li></ul>
      </section>

      <section id="tab-invitations" class="tab-panel dashboard-section hidden">
        <div class="section-header">
          <div>
            <p class="eyebrow">Pending access</p>
            <h2>Invitations</h2>
          </div>
        </div>
        <ul id="invitation-list" class="invitation-list"><li class="empty">No pending invitations.</li></ul>
      </section>
    </main>

    <aside class="dashboard-side">
      <section class="side-panel">
        <div class="section-header compact">
          <div>
            <p class="eyebrow">Presence</p>
            <h2>Online Users</h2>
          </div>
        </div>
        <ul id="active-users" class="active-users-list"><li class="empty">No other users online.</li></ul>
      </section>
    </aside>
  </div>
  <script>
    fetch('/api/me').then(r => {{
      if (!r.ok) {{ window.location.href = '/login.html'; return null; }}
      return r.json();
    }}).then(d => {{
      if (!d) return;
      if (d.username !== '{username}') window.location.href = `/home/${{d.username}}`;
    }});

    document.getElementById('logout').addEventListener('click', async () => {{
      await fetch('/api/logout', {{ method: 'POST' }});
      window.location.href = '/index.html';
    }});

    function showTab(name) {{
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.add('hidden'));
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.getElementById('tab-' + name).classList.remove('hidden');
      document.querySelector(`[data-tab="${{name}}"]`).classList.add('active');
    }}
    document.querySelectorAll('.tab-btn').forEach(btn =>
      btn.addEventListener('click', () => showTab(btn.dataset.tab))
    );

    let myProjects = [];

    async function sendHeartbeat() {{
      await fetch('/api/heartbeat', {{ method: 'POST' }});
    }}

    async function loadActiveUsers() {{
      const res = await fetch('/api/active_users');
      const data = await res.json();
      const list = document.getElementById('active-users');
      list.innerHTML = '';
      if (!data.users || data.users.length === 0) {{
        list.innerHTML = '<li class="empty">No other users online.</li>';
        return;
      }}
      for (const u of data.users) {{
        const li = document.createElement('li');
        const nameSpan = document.createElement('span');
        nameSpan.textContent = u;
        const inviteBtn = document.createElement('button');
        inviteBtn.className = 'btn btn-sm';
        inviteBtn.textContent = 'Invite';
        inviteBtn.addEventListener('click', () => showInviteForm(li, u));
        li.appendChild(nameSpan);
        li.appendChild(inviteBtn);
        list.appendChild(li);
      }}
    }}

    function showInviteForm(li, recipient) {{
      document.querySelectorAll('.invite-form').forEach(f => f.remove());
      const form = document.createElement('div');
      form.className = 'invite-form';
      if (myProjects.length === 0) {{
        form.innerHTML = '<span class="error">You have no projects to invite to.</span>';
        li.after(form);
        return;
      }}
      const select = document.createElement('select');
      select.className = 'invite-select';
      for (const p of myProjects) {{
        const opt = document.createElement('option');
        opt.value = p;
        opt.textContent = p;
        select.appendChild(opt);
      }}
      const sendBtn = document.createElement('button');
      sendBtn.className = 'btn btn-sm';
      sendBtn.textContent = 'Send';
      const cancelBtn = document.createElement('button');
      cancelBtn.className = 'btn btn-sm btn-outline';
      cancelBtn.textContent = 'Cancel';
      cancelBtn.addEventListener('click', () => form.remove());
      sendBtn.addEventListener('click', async () => {{
        const res = await fetch('/api/invitations', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ recipient, project_name: select.value }})
        }});
        const result = await res.json();
        form.innerHTML = `<span class="${{result.ok ? 'invite-sent' : 'error'}}">${{result.ok ? 'Invite sent!' : result.error}}</span>`;
        if (result.ok) loadProjects();
      }});
      form.appendChild(select);
      form.appendChild(sendBtn);
      form.appendChild(cancelBtn);
      li.after(form);
    }}

    sendHeartbeat();
    loadActiveUsers();
    setInterval(sendHeartbeat, 20000);
    setInterval(loadActiveUsers, 10000);

    async function loadProjects() {{
      const res = await fetch('/api/projects');
      const data = await res.json();
      myProjects = (data.projects || []).map(p => p.name);
      const list = document.getElementById('project-list');
      list.innerHTML = '';
      if (myProjects.length === 0) {{
        list.innerHTML = '<li class="empty">No projects yet.</li>';
        return;
      }}
      for (const p of data.projects) {{
        const li = document.createElement('li');
        li.className = 'project-item';
        const a = document.createElement('a');
        a.href = p.url;
        a.textContent = p.name;
        li.appendChild(a);
        const collaborators = document.createElement('div');
        collaborators.className = 'collaborator-list';
        collaborators.textContent = 'Loading collaborators...';
        li.appendChild(collaborators);
        const inviteForm = document.createElement('form');
        inviteForm.className = 'project-invite-form';
        inviteForm.innerHTML = '<div class="user-search"><input type="text" placeholder="Search username" autocomplete="off" required /><ul class="user-search-results hidden"></ul></div><button class="btn btn-sm" type="submit">Invite</button><span class="project-invite-status"></span>';
        setupUserSearch(inviteForm);
        inviteForm.addEventListener('submit', e => inviteToProject(e, p.name, inviteForm));
        li.appendChild(inviteForm);
        list.appendChild(li);
        loadProjectCollaborators(p.name, collaborators);
      }}
    }}
    loadProjects();

    function setupUserSearch(form) {{
      const input = form.querySelector('input');
      const results = form.querySelector('.user-search-results');
      let searchTimer;

      input.addEventListener('input', () => {{
        clearTimeout(searchTimer);
        const query = input.value.trim();
        if (query.length === 0) {{
          results.classList.add('hidden');
          results.innerHTML = '';
          return;
        }}
        searchTimer = setTimeout(() => loadUserMatches(query, input, results), 160);
      }});

      input.addEventListener('blur', () => {{
        setTimeout(() => results.classList.add('hidden'), 140);
      }});
    }}

    async function loadUserMatches(query, input, results) {{
      const res = await fetch(`/api/users/search?q=${{encodeURIComponent(query)}}`);
      const data = await res.json();
      results.innerHTML = '';
      if (!data.users || data.users.length === 0) {{
        results.innerHTML = '<li class="user-search-empty">No matching users</li>';
        results.classList.remove('hidden');
        return;
      }}
      for (const user of data.users) {{
        const li = document.createElement('li');
        const button = document.createElement('button');
        button.type = 'button';
        button.textContent = user;
        button.addEventListener('mousedown', e => {{
          e.preventDefault();
          input.value = user;
          results.classList.add('hidden');
        }});
        li.appendChild(button);
        results.appendChild(li);
      }}
      results.classList.remove('hidden');
    }}

    async function inviteToProject(event, projectName, form) {{
      event.preventDefault();
      const input = form.querySelector('input');
      const message = form.querySelector('.project-invite-status');
      const recipient = input.value.trim();
      message.className = 'project-invite-status';
      message.textContent = 'Sending invite...';
      try {{
        const res = await fetch('/api/invitations', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ recipient, project_name: projectName }})
        }});
        const data = await res.json();
        message.className = data.ok ? 'project-invite-status invite-sent' : 'project-invite-status error';
        message.textContent = data.ok ? 'Invite sent.' : data.error;
        if (data.ok) input.value = '';
      }} catch (error) {{
        message.className = 'project-invite-status error';
        message.textContent = 'Could not send invite. Try refreshing.';
      }}
    }}

    async function loadProjectCollaborators(projectName, container) {{
      try {{
        const res = await fetch(`/api/projects/${{projectName}}/collaborators`);
        const data = await res.json();
        if (!res.ok) {{
          container.innerHTML = `<span class="error">${{data.error || 'Could not load collaborators.'}}</span>`;
          return;
        }}
        if (!data.collaborators || data.collaborators.length === 0) {{
          container.textContent = 'No collaborators.';
          return;
        }}
        container.innerHTML = '';
        for (const collaborator of data.collaborators) {{
          const row = document.createElement('div');
          row.className = 'collaborator-row';
          const name = document.createElement('span');
          name.textContent = collaborator;
          const remove = document.createElement('button');
          remove.className = 'btn btn-sm btn-outline';
          remove.textContent = 'Remove';
          remove.addEventListener('click', () => removeCollaborator(projectName, collaborator, container));
          row.appendChild(name);
          row.appendChild(remove);
          container.appendChild(row);
        }}
      }} catch (error) {{
        container.innerHTML = '<span class="error">Could not load collaborators.</span>';
      }}
    }}

    async function removeCollaborator(projectName, collaborator, container) {{
      const confirmed = window.confirm(`Remove ${{collaborator}} from ${{projectName}}?`);
      if (!confirmed) return;
      const res = await fetch(`/api/projects/${{projectName}}/collaborators/${{encodeURIComponent(collaborator)}}`, {{
        method: 'DELETE'
      }});
      const data = await res.json();
      if (data.ok) {{
        loadProjectCollaborators(projectName, container);
      }} else {{
        container.innerHTML = `<span class="error">${{data.error}}</span>`;
      }}
    }}

    document.getElementById('create-project-form').addEventListener('submit', async e => {{
      e.preventDefault();
      const err = document.getElementById('error');
      err.classList.add('hidden');
      const name = document.getElementById('project-name').value.trim();
      const res = await fetch('/api/projects', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ name }})
      }});
      const data = await res.json();
      if (data.ok) {{
        document.getElementById('project-name').value = '';
        loadProjects();
      }} else {{
        err.textContent = data.error;
        err.classList.remove('hidden');
      }}
    }});

    async function loadInvitations() {{
      const res = await fetch('/api/invitations');
      const data = await res.json();
      const list = document.getElementById('invitation-list');
      const badge = document.getElementById('invite-badge');
      list.innerHTML = '';
      if (!data.invitations || data.invitations.length === 0) {{
        list.innerHTML = '<li class="empty">No pending invitations.</li>';
        badge.classList.add('hidden');
        return;
      }}
      badge.textContent = data.invitations.length;
      badge.classList.remove('hidden');
      for (const inv of data.invitations) {{
        const li = document.createElement('li');
        li.className = 'invitation-item';
        li.dataset.id = inv.id;
        const text = document.createElement('span');
        text.textContent = `${{inv.sender}} invited you to collaborate on ${{inv.project_name}}`;
        const acceptBtn = document.createElement('button');
        acceptBtn.className = 'btn btn-sm';
        acceptBtn.textContent = 'Accept';
        acceptBtn.addEventListener('click', () => acceptInvitation(inv.id, inv.sender, inv.project_name));
        li.appendChild(text);
        li.appendChild(acceptBtn);
        list.appendChild(li);
      }}
    }}

    async function acceptInvitation(id, sender, projectName) {{
      const res = await fetch(`/api/invitations/${{id}}/accept`, {{ method: 'POST' }});
      const data = await res.json();
      if (!data.ok) return;
      const li = document.querySelector(`[data-id="${{id}}"]`);
      if (li) {{
        li.innerHTML = `<span class="collab-msg">You are now collaborating with ${{sender}} on ${{projectName}}. <a href="/collaborate/${{sender}}/${{projectName}}">Open Project →</a></span>`;
      }}
      loadSharedProjects();
      const badge = document.getElementById('invite-badge');
      const count = parseInt(badge.textContent) - 1;
      if (count <= 0) {{
        badge.classList.add('hidden');
      }} else {{
        badge.textContent = count;
      }}
    }}

    async function loadSharedProjects() {{
      const res = await fetch('/api/shared_projects');
      const data = await res.json();
      const list = document.getElementById('shared-project-list');
      list.innerHTML = '';
      if (!data.projects || data.projects.length === 0) {{
        list.innerHTML = '<li class="empty">No shared projects yet.</li>';
        return;
      }}
      for (const p of data.projects) {{
        const li = document.createElement('li');
        const a = document.createElement('a');
        a.href = p.url;
        a.textContent = `${{p.project_name}} owned by ${{p.owner}}`;
        li.appendChild(a);
        list.appendChild(li);
      }}
    }}

    loadInvitations();
    loadSharedProjects();
    setInterval(loadInvitations, 5000);
    setInterval(loadSharedProjects, 10000);
  </script>
</body>
</html>"""
    with open(os.path.join(user_dir, 'home.html'), 'w') as f:
        f.write(html)


def create_project(username, name):
    """Create a new project directory, seed it with default files, and write its workspace HTML.

    Creates accounts/<username>/projects/<name>/files/ and writes index.html containing
    the Monaco editor workspace. Safe to call on an existing project — default files are
    only written if they don't already exist.
    """
    project_dir = os.path.join(ACCOUNTS_DIR, username, 'projects', name)
    files_dir = project_files_dir(username, name)
    os.makedirs(files_dir, exist_ok=True)

    for file_path, content in DEFAULT_FILES.items():
        full_path = os.path.join(files_dir, file_path)
        if not os.path.exists(full_path):
            with open(full_path, 'w') as f:
                f.write(content)

    html = workspace_html(
        title=name,
        back_url=f'/home/{username}',
        files_api=f'/api/projects/{name}',
        folders_api=f'/api/projects/{name}',
        yjs_owner=username,
        yjs_project=name,
    )
    with open(os.path.join(project_dir, 'index.html'), 'w') as f:
        f.write(html)


def migrate_legacy_pages(username):
    """Convert old subpages/+content/ account layout to the current projects/ layout.

    Only runs if a legacy subpages/ directory exists. Each .html file in subpages/
    becomes a project, and its matching content/<name>.txt is copied to notes.txt.
    """
    subpages_dir = os.path.join(ACCOUNTS_DIR, username, 'subpages')
    content_dir = os.path.join(ACCOUNTS_DIR, username, 'content')
    if not os.path.isdir(subpages_dir):
        return

    for fname in os.listdir(subpages_dir):
        if not fname.endswith('.html'):
            continue
        project_name = fname[:-5]
        if not PROJECT_NAME_RE.match(project_name):
            continue

        files_dir = project_files_dir(username, project_name)
        create_project(username, project_name)

        legacy_content_path = os.path.join(content_dir, f'{project_name}.txt')
        notes_path = os.path.join(files_dir, 'notes.txt')
        if os.path.exists(legacy_content_path) and not os.path.exists(notes_path):
            with open(legacy_content_path) as source:
                with open(notes_path, 'w') as target:
                    target.write(source.read())


def init_db():
    """Initialise the database and regenerate all on-disk HTML files on startup.

    Creates the users and invitations tables if they don't exist, then regenerates
    home pages and project workspaces for every registered user.
    """
    with get_db() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS invitations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                project_name TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        for row in conn.execute('SELECT username FROM users').fetchall():
            username = row['username']
            create_user_home(username)
            migrate_legacy_pages(username)
            projects_dir = os.path.join(ACCOUNTS_DIR, username, 'projects')
            if os.path.isdir(projects_dir):
                for project_name in os.listdir(projects_dir):
                    if PROJECT_NAME_RE.match(project_name):
                        create_project(username, project_name)


@sock.route('/ws/signaling')
def signaling(ws):
    """WebRTC signaling relay: subscribe/unsubscribe/publish messages to named rooms."""
    subscribed = set()
    try:
        while True:
            data = ws.receive()
            if data is None:
                break
            try:
                msg = json.loads(data)
            except (json.JSONDecodeError, ValueError):
                continue
            t = msg.get('type')
            if t == 'ping':
                ws.send(json.dumps({'type': 'pong'}))
            elif t == 'subscribe':
                with _signaling_lock:
                    for topic in msg.get('topics', []):
                        _signaling_topics.setdefault(topic, set()).add(ws)
                        subscribed.add(topic)
            elif t == 'unsubscribe':
                with _signaling_lock:
                    for topic in msg.get('topics', []):
                        _signaling_topics.get(topic, set()).discard(ws)
                        subscribed.discard(topic)
            elif t == 'publish':
                topic = msg.get('topic')
                if topic:
                    with _signaling_lock:
                        peers = set(_signaling_topics.get(topic, set()))
                    for peer in peers:
                        if peer is not ws:
                            try:
                                peer.send(json.dumps(msg))
                            except Exception:
                                pass
    finally:
        with _signaling_lock:
            for topic in subscribed:
                _signaling_topics.get(topic, set()).discard(ws)


@sock.route('/ws/projects/<owner>/<project_name>')
def project_sync(ws, owner, project_name):
    """Relay live editor messages between users working in the same project."""
    if clear_stale_session():
        return
    if 'username' not in session:
        return
    if not PROJECT_NAME_RE.match(project_name):
        return
    if not has_collab_access(session['username'], owner, project_name):
        return

    room = (owner, project_name)
    with _project_channels_lock:
        _project_channels.setdefault(room, set()).add(ws)

    client_ids = set()
    try:
        while True:
            data = ws.receive()
            if data is None:
                break
            try:
                message = json.loads(data)
            except (json.JSONDecodeError, ValueError):
                continue

            message_type = message.get('type')
            client_id = message.get('sender')
            if client_id:
                client_ids.add(client_id)
            if message_type not in {'open_file', 'file_update', 'file_saved', 'edit_reverted', 'files_changed'}:
                continue

            if message_type == 'open_file':
                file_path = message.get('file') or ''
                if not is_safe_file_path(file_path):
                    continue
                live_key = (owner, project_name, file_path)
                with _project_channels_lock:
                    live_state = _project_live_files.get(live_key)
                    lock_state = _project_edit_locks.get(live_key)
                if live_state:
                    ws.send(json.dumps({
                        'type': 'lock_state',
                        'file': file_path,
                        'content': live_state['content'],
                        'editor': live_state['editor'],
                        'editor_client': live_state['client']
                    }))
                elif lock_state:
                    ws.send(json.dumps({
                        'type': 'lock_state',
                        'file': file_path,
                        'editor': lock_state['editor'],
                        'editor_client': lock_state['client']
                    }))
                continue

            if message_type == 'file_update':
                file_path = message.get('file') or ''
                content = message.get('content') or ''
                if not is_safe_file_path(file_path) or len(content) > 100000:
                    continue
                live_key = (owner, project_name, file_path)
                with _project_channels_lock:
                    lock_state = _project_edit_locks.get(live_key)
                    if lock_state and lock_state['client'] != client_id:
                        lock_message = {
                            'type': 'lock_state',
                            'file': file_path,
                            'editor': lock_state['editor'],
                            'editor_client': lock_state['client']
                        }
                        live_state = _project_live_files.get(live_key)
                        if live_state:
                            lock_message['content'] = live_state['content']
                        ws.send(json.dumps(lock_message))
                        continue
                    _project_edit_locks[live_key] = {'client': client_id, 'editor': session['username']}
                    _project_live_files[live_key] = {
                        'client': client_id,
                        'editor': session['username'],
                        'content': content
                    }
                message['editor'] = session['username']
                message['editor_client'] = client_id

            if message_type == 'file_saved':
                file_path = message.get('file') or ''
                content = message.get('content') or ''
                if not persist_project_file(owner, project_name, file_path, content):
                    continue
                live_key = (owner, project_name, file_path)
                with _project_channels_lock:
                    _project_live_files.pop(live_key, None)
                    _project_edit_locks.pop(live_key, None)

            if message_type == 'edit_reverted':
                file_path = message.get('file') or ''
                if not is_safe_file_path(file_path):
                    continue
                live_key = (owner, project_name, file_path)
                with _project_channels_lock:
                    _project_live_files.pop(live_key, None)
                    _project_edit_locks.pop(live_key, None)

            with _project_channels_lock:
                peers = set(_project_channels.get(room, set()))
            for peer in peers:
                if peer is ws:
                    continue
                try:
                    peer.send(json.dumps(message))
                except Exception:
                    pass
    finally:
        release_messages = []
        with _project_channels_lock:
            _project_channels.get(room, set()).discard(ws)
            for live_key, lock_state in list(_project_edit_locks.items()):
                if live_key[0] == owner and live_key[1] == project_name and lock_state['client'] in client_ids:
                    _project_edit_locks.pop(live_key, None)
                    _project_live_files.pop(live_key, None)
                    release_messages.append({
                        'type': 'edit_reverted',
                        'file': live_key[2],
                        'content': read_project_file(owner, project_name, live_key[2])
                    })
            peers = set(_project_channels.get(room, set()))
        for message in release_messages:
            for peer in peers:
                try:
                    peer.send(json.dumps(message))
                except Exception:
                    pass


@app.route('/')
def index():
    """Serve the landing page."""
    return send_from_directory('public', 'index.html')


@app.route('/home/<username>')
def user_home(username):
    """Serve a user's generated home page."""
    if clear_stale_session():
        return redirect('/login.html')
    if 'username' not in session:
        return redirect('/login.html')
    if session['username'] != username:
        return redirect(f"/home/{session['username']}")
    if not user_exists(username):
        session.clear()
        return redirect('/login.html')

    home_path = os.path.join(ACCOUNTS_DIR, username, 'home.html')
    if not os.path.exists(home_path):
        create_user_home(username)
    return send_from_directory(os.path.join(ACCOUNTS_DIR, username), 'home.html')


@app.route('/projects/<username>/<name>')
def user_project(username, name):
    """Serve a project's generated workspace page."""
    if clear_stale_session():
        return redirect('/login.html')
    if 'username' not in session:
        return redirect('/login.html')
    if session['username'] != username:
        return 'Forbidden', 403
    if not PROJECT_NAME_RE.match(name):
        return 'Not found', 404
    if not user_exists(username):
        session.clear()
        return redirect('/login.html')
    return send_from_directory(os.path.join(ACCOUNTS_DIR, username, 'projects', name), 'index.html')


@app.route('/collaborate/<owner>/<project_name>')
def collab_project(owner, project_name):
    """Serve the collaboration workspace for an invited user."""
    if clear_stale_session():
        return redirect('/login.html')
    if 'username' not in session:
        return redirect('/login.html')
    if not PROJECT_NAME_RE.match(project_name):
        return 'Not found', 404
    collab_user = session['username']
    if not has_collab_access(collab_user, owner, project_name):
        return 'Forbidden', 403
    return workspace_html(
        title=project_name,
        back_url=f'/home/{collab_user}',
        files_api=f'/api/collaborate/{owner}/{project_name}',
        folders_api=f'/api/collaborate/{owner}/{project_name}',
        yjs_owner=owner,
        yjs_project=project_name,
    )


@app.route('/<path:filename>')
def static_files(filename):
    """Serve static files from the public/ directory."""
    return send_from_directory('public', filename)


@app.post('/api/register')
def register():
    """Create a new user account, hash the password, and start a session."""
    data = request.get_json()
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''

    if not username or not password:
        return jsonify(error='Username and password are required.'), 400
    if not (3 <= len(username) <= 32):
        return jsonify(error='Username must be 3–32 characters.'), 400
    if len(password) < 6:
        return jsonify(error='Password must be at least 6 characters.'), 400

    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    try:
        with get_db() as conn:
            conn.execute(
                'INSERT INTO users (username, password_hash) VALUES (?, ?)',
                (username, password_hash)
            )
        create_user_home(username)
        session['username'] = username
        return jsonify(ok=True, username=username)
    except sqlite3.IntegrityError:
        return jsonify(error='Username already taken.'), 409


@app.post('/api/login')
def login():
    """Authenticate a user and start a session."""
    data = request.get_json()
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''

    if not username or not password:
        return jsonify(error='Username and password are required.'), 400

    with get_db() as conn:
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()

    if not user or not bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
        return jsonify(error='Invalid username or password.'), 401

    session['username'] = user['username']
    return jsonify(ok=True, username=user['username'])


@app.post('/api/logout')
def logout():
    """Clear the session and remove the user from the active users list."""
    if 'username' in session:
        active_users.pop(session['username'], None)
    session.clear()
    return jsonify(ok=True)


@app.post('/api/heartbeat')
def heartbeat():
    """Update the logged-in user's last-seen timestamp to mark them as online."""
    if 'username' not in session:
        return jsonify(error='Not logged in.'), 401
    active_users[session['username']] = time.time()
    return jsonify(ok=True)


@app.get('/api/active_users')
def get_active_users():
    """Return users who sent a heartbeat within the last HEARTBEAT_TIMEOUT seconds, excluding self."""
    if 'username' not in session:
        return jsonify(error='Not logged in.'), 401
    cutoff = time.time() - HEARTBEAT_TIMEOUT
    others = [u for u, t in active_users.items() if t > cutoff and u != session['username']]
    return jsonify(users=sorted(others))


@app.get('/api/users/search')
def search_users():
    """Return username matches for invite autocomplete, excluding the logged-in user."""
    if 'username' not in session:
        return jsonify(error='Not logged in.'), 401
    query = (request.args.get('q') or '').strip()
    if not query:
        return jsonify(users=[])

    with get_db() as conn:
        rows = conn.execute(
            '''
            SELECT username
            FROM users
            WHERE username != ? AND username LIKE ?
            ORDER BY username
            LIMIT 8
            ''',
            (session['username'], f'%{query}%')
        ).fetchall()
    return jsonify(users=[row['username'] for row in rows])


@app.post('/api/invitations')
def send_invitation():
    """Send a collaboration invite from the logged-in user to another user for one of their projects."""
    if 'username' not in session:
        return jsonify(error='Not logged in.'), 401
    sender = session['username']
    data = request.get_json()
    recipient = (data.get('recipient') or '').strip()
    project_name = (data.get('project_name') or '').strip()

    if not recipient or not project_name:
        return jsonify(error='Recipient and project name are required.'), 400
    if not PROJECT_NAME_RE.match(project_name):
        return jsonify(error='Invalid project name.'), 400
    if recipient == sender:
        return jsonify(error='Cannot invite yourself.'), 400

    project_dir = os.path.join(ACCOUNTS_DIR, sender, 'projects', project_name)
    if not os.path.isdir(project_dir):
        return jsonify(error='Project not found.'), 404

    with get_db() as conn:
        if not conn.execute('SELECT 1 FROM users WHERE username = ?', (recipient,)).fetchone():
            return jsonify(error='User not found.'), 404
        if conn.execute(
            'SELECT 1 FROM invitations WHERE sender=? AND recipient=? AND project_name=? AND status=?',
            (sender, recipient, project_name, 'pending')
        ).fetchone():
            return jsonify(error='Invitation already sent.'), 409
        if conn.execute(
            'SELECT 1 FROM invitations WHERE sender=? AND recipient=? AND project_name=? AND status=?',
            (sender, recipient, project_name, 'accepted')
        ).fetchone():
            return jsonify(error='User already has access.'), 409
        conn.execute(
            'INSERT INTO invitations (sender, recipient, project_name) VALUES (?, ?, ?)',
            (sender, recipient, project_name)
        )
    return jsonify(ok=True)


@app.get('/api/invitations')
def get_invitations():
    """Return all pending invitations addressed to the logged-in user."""
    if 'username' not in session:
        return jsonify(error='Not logged in.'), 401
    with get_db() as conn:
        rows = conn.execute(
            'SELECT id, sender, project_name FROM invitations WHERE recipient=? AND status=? ORDER BY created_at DESC',
            (session['username'], 'pending')
        ).fetchall()
    return jsonify(invitations=[dict(r) for r in rows])


@app.post('/api/invitations/<int:invite_id>/accept')
def accept_invitation(invite_id):
    """Mark a pending invitation as accepted. Only the recipient may accept."""
    if 'username' not in session:
        return jsonify(error='Not logged in.'), 401
    with get_db() as conn:
        row = conn.execute(
            'SELECT sender, project_name FROM invitations WHERE id=? AND recipient=? AND status=?',
            (invite_id, session['username'], 'pending')
        ).fetchone()
        if not row:
            return jsonify(error='Invitation not found.'), 404
        conn.execute('UPDATE invitations SET status=? WHERE id=?', ('accepted', invite_id))
    return jsonify(ok=True, sender=row['sender'], project_name=row['project_name'])


@app.get('/api/shared_projects')
def list_shared_projects():
    """Return projects the logged-in user has accepted access to."""
    if 'username' not in session:
        return jsonify(error='Not logged in.'), 401
    with get_db() as conn:
        rows = conn.execute(
            '''
            SELECT sender AS owner, project_name
            FROM invitations
            WHERE recipient=? AND status=?
            ORDER BY sender, project_name
            ''',
            (session['username'], 'accepted')
        ).fetchall()
    projects = [
        {
            'owner': row['owner'],
            'project_name': row['project_name'],
            'url': f"/collaborate/{row['owner']}/{row['project_name']}"
        }
        for row in rows
    ]
    return jsonify(projects=projects)


@app.get('/api/me')
def me():
    """Return the username of the currently logged-in user."""
    if clear_stale_session():
        return jsonify(error='Session user no longer exists.'), 401
    if 'username' not in session:
        return jsonify(error='Not logged in.'), 401
    return jsonify(username=session['username'])


@app.get('/api/projects')
def list_projects():
    """Return a list of the logged-in user's projects with their names and URLs."""
    if 'username' not in session:
        return jsonify(error='Not logged in.'), 401
    username = session['username']
    projects_dir = os.path.join(ACCOUNTS_DIR, username, 'projects')
    projects = []
    if os.path.isdir(projects_dir):
        for name in sorted(os.listdir(projects_dir)):
            if PROJECT_NAME_RE.match(name):
                projects.append({'name': name, 'url': f'/projects/{username}/{name}'})
    return jsonify(projects=projects)


@app.post('/api/projects')
def create_project_route():
    """Create a new project for the logged-in user."""
    if 'username' not in session:
        return jsonify(error='Not logged in.'), 401
    username = session['username']
    data = request.get_json()
    name = (data.get('name') or '').strip()

    if not PROJECT_NAME_RE.match(name):
        return jsonify(error='Project name must be 1–64 characters: letters, numbers, hyphens, underscores.'), 400

    project_dir = os.path.join(ACCOUNTS_DIR, username, 'projects', name)
    if os.path.exists(project_dir):
        return jsonify(error='A project with that name already exists.'), 409

    create_project(username, name)
    return jsonify(ok=True, url=f'/projects/{username}/{name}')


@app.get('/api/projects/<name>/collaborators')
def list_project_collaborators(name):
    """Return accepted collaborators for a project owned by the logged-in user."""
    if 'username' not in session:
        return jsonify(error='Not logged in.'), 401
    if not PROJECT_NAME_RE.match(name):
        return jsonify(error='Invalid project name.'), 400

    owner = session['username']
    project_dir = os.path.join(ACCOUNTS_DIR, owner, 'projects', name)
    if not os.path.isdir(project_dir):
        return jsonify(error='Project not found.'), 404

    with get_db() as conn:
        rows = conn.execute(
            '''
            SELECT recipient
            FROM invitations
            WHERE sender=? AND project_name=? AND status=?
            ORDER BY recipient
            ''',
            (owner, name, 'accepted')
        ).fetchall()
    return jsonify(collaborators=[row['recipient'] for row in rows])


@app.delete('/api/projects/<name>/collaborators/<path:collaborator>')
def remove_project_collaborator(name, collaborator):
    """Remove accepted and pending project access for a collaborator."""
    if 'username' not in session:
        return jsonify(error='Not logged in.'), 401
    if not PROJECT_NAME_RE.match(name):
        return jsonify(error='Invalid project name.'), 400

    owner = session['username']
    project_dir = os.path.join(ACCOUNTS_DIR, owner, 'projects', name)
    if not os.path.isdir(project_dir):
        return jsonify(error='Project not found.'), 404

    with get_db() as conn:
        cursor = conn.execute(
            '''
            DELETE FROM invitations
            WHERE sender=? AND recipient=? AND project_name=? AND status IN (?, ?)
            ''',
            (owner, collaborator, name, 'accepted', 'pending')
        )
    if cursor.rowcount == 0:
        return jsonify(error='Collaborator not found.'), 404
    return jsonify(ok=True)


@app.get('/api/projects/<name>/files')
def list_project_files(name):
    """Return a flat file list and nested file tree for a project."""
    if 'username' not in session:
        return jsonify(error='Not logged in.'), 401
    if not PROJECT_NAME_RE.match(name):
        return jsonify(error='Invalid project name.'), 400

    username = session['username']
    files_dir = project_files_dir(username, name)
    if not os.path.isdir(files_dir):
        return jsonify(error='Project not found.'), 404

    files = []
    for root, _, filenames in os.walk(files_dir):
        for filename in filenames:
            full_path = os.path.join(root, filename)
            files.append(os.path.relpath(full_path, files_dir).replace(os.sep, '/'))
    return jsonify(ok=True, files=sorted(files), tree=build_file_tree(files_dir))


@app.post('/api/projects/<name>/folders/<path:folder_path>')
def create_project_folder(name, folder_path):
    """Create a folder inside a project's files directory."""
    if 'username' not in session:
        return jsonify(error='Not logged in.'), 401
    if not PROJECT_NAME_RE.match(name):
        return jsonify(error='Invalid project name.'), 400
    if not is_safe_file_path(folder_path):
        return jsonify(error='Invalid folder name.'), 400

    username = session['username']
    files_dir = project_files_dir(username, name)
    if not os.path.isdir(files_dir):
        return jsonify(error='Project not found.'), 404

    full_path = os.path.join(files_dir, folder_path)
    if os.path.isfile(full_path):
        return jsonify(error='A file already exists at that path.'), 409

    os.makedirs(full_path, exist_ok=True)
    return jsonify(ok=True)


@app.get('/api/projects/<name>/files/<path:file_path>')
def get_project_file(name, file_path):
    """Return the text content of a file within a project."""
    if 'username' not in session:
        return jsonify(error='Not logged in.'), 401
    if not PROJECT_NAME_RE.match(name):
        return jsonify(error='Invalid project name.'), 400
    if not is_safe_file_path(file_path):
        return jsonify(error='Invalid file name.'), 400

    username = session['username']
    full_path = os.path.join(project_files_dir(username, name), file_path)
    if not os.path.isfile(full_path):
        return jsonify(error='File not found.'), 404

    with open(full_path) as f:
        return jsonify(ok=True, content=f.read())


@app.put('/api/projects/<name>/files/<path:file_path>')
def update_project_file(name, file_path):
    """Create or overwrite a file in a project. Content is capped at 100,000 characters."""
    if 'username' not in session:
        return jsonify(error='Not logged in.'), 401
    if not PROJECT_NAME_RE.match(name):
        return jsonify(error='Invalid project name.'), 400
    if not is_safe_file_path(file_path):
        return jsonify(error='Invalid file name.'), 400

    username = session['username']
    files_dir = project_files_dir(username, name)
    if not os.path.isdir(files_dir):
        return jsonify(error='Project not found.'), 404
    data = request.get_json()
    content = data.get('content') or ''
    if len(content) > 100000:
        return jsonify(error='File content must be 100,000 characters or fewer.'), 400

    full_path = os.path.join(files_dir, file_path)
    if os.path.isdir(full_path):
        return jsonify(error='A folder already exists at that path.'), 409

    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    with open(full_path, 'w') as f:
        f.write(content)
    return jsonify(ok=True)


@app.delete('/api/projects/<name>/files/<path:file_path>')
def delete_project_file(name, file_path):
    """Delete a file or folder and remove any empty parent directories up to the files root."""
    if 'username' not in session:
        return jsonify(error='Not logged in.'), 401
    if not PROJECT_NAME_RE.match(name):
        return jsonify(error='Invalid project name.'), 400

    username = session['username']
    return delete_project_path(project_files_dir(username, name), file_path)


@app.get('/api/projects/<name>/download')
def download_project_root(name):
    """Download the whole project as a zip archive."""
    if 'username' not in session:
        return jsonify(error='Not logged in.'), 401
    if not PROJECT_NAME_RE.match(name):
        return jsonify(error='Invalid project name.'), 400

    username = session['username']
    return download_project_path(project_files_dir(username, name), archive_name=name)


@app.get('/api/projects/<name>/download/<path:item_path>')
def download_project_item(name, item_path):
    """Download a project file directly, or a folder as a zip archive."""
    if 'username' not in session:
        return jsonify(error='Not logged in.'), 401
    if not PROJECT_NAME_RE.match(name):
        return jsonify(error='Invalid project name.'), 400

    username = session['username']
    return download_project_path(project_files_dir(username, name), item_path, archive_name=name)


@app.post('/api/projects/<name>/run/<path:file_path>')
def run_project_file(name, file_path):
    """Run a Python file in a project and return its stdout, stderr, and exit code."""
    if 'username' not in session:
        return jsonify(error='Not logged in.'), 401
    if not PROJECT_NAME_RE.match(name):
        return jsonify(error='Invalid project name.'), 400
    if not is_safe_file_path(file_path):
        return jsonify(error='Invalid file path.'), 400
    if not file_path.endswith('.py'):
        return jsonify(error='Only Python (.py) files can be run.'), 400

    username = session['username']
    files_dir = project_files_dir(username, name)
    full_path = os.path.join(files_dir, file_path)
    if not os.path.isfile(full_path):
        return jsonify(error='File not found.'), 404

    try:
        result = subprocess.run(
            ['python3', file_path],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=files_dir
        )
        return jsonify(
            ok=True,
            stdout=result.stdout[:50000],
            stderr=result.stderr[:50000],
            exit_code=result.returncode
        )
    except subprocess.TimeoutExpired:
        return jsonify(ok=True, stdout='', stderr='Execution timed out (10s limit).', exit_code=1)
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.get('/api/collaborate/<owner>/<project_name>/files')
def collab_list_files(owner, project_name):
    """List files in a collaborated project."""
    if 'username' not in session:
        return jsonify(error='Not logged in.'), 401
    if not has_collab_access(session['username'], owner, project_name):
        return jsonify(error='Forbidden.'), 403
    files_dir = project_files_dir(owner, project_name)
    if not os.path.isdir(files_dir):
        return jsonify(error='Project not found.'), 404
    files = []
    for root, _, filenames in os.walk(files_dir):
        for filename in filenames:
            full_path = os.path.join(root, filename)
            files.append(os.path.relpath(full_path, files_dir).replace(os.sep, '/'))
    return jsonify(ok=True, files=sorted(files), tree=build_file_tree(files_dir))


@app.get('/api/collaborate/<owner>/<project_name>/files/<path:file_path>')
def collab_get_file(owner, project_name, file_path):
    """Get file content from a collaborated project."""
    if 'username' not in session:
        return jsonify(error='Not logged in.'), 401
    if not has_collab_access(session['username'], owner, project_name):
        return jsonify(error='Forbidden.'), 403
    if not is_safe_file_path(file_path):
        return jsonify(error='Invalid file name.'), 400
    full_path = os.path.join(project_files_dir(owner, project_name), file_path)
    if not os.path.isfile(full_path):
        return jsonify(error='File not found.'), 404
    with open(full_path) as f:
        return jsonify(ok=True, content=f.read())


@app.put('/api/collaborate/<owner>/<project_name>/files/<path:file_path>')
def collab_update_file(owner, project_name, file_path):
    """Create or overwrite a file in a collaborated project."""
    if 'username' not in session:
        return jsonify(error='Not logged in.'), 401
    if not has_collab_access(session['username'], owner, project_name):
        return jsonify(error='Forbidden.'), 403
    if not is_safe_file_path(file_path):
        return jsonify(error='Invalid file name.'), 400
    files_dir = project_files_dir(owner, project_name)
    if not os.path.isdir(files_dir):
        return jsonify(error='Project not found.'), 404
    data = request.get_json()
    content = data.get('content') or ''
    if len(content) > 100000:
        return jsonify(error='File content must be 100,000 characters or fewer.'), 400
    full_path = os.path.join(files_dir, file_path)
    if os.path.isdir(full_path):
        return jsonify(error='A folder already exists at that path.'), 409
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    with open(full_path, 'w') as f:
        f.write(content)
    return jsonify(ok=True)


@app.delete('/api/collaborate/<owner>/<project_name>/files/<path:file_path>')
def collab_delete_file(owner, project_name, file_path):
    """Delete a file or folder in a collaborated project."""
    if 'username' not in session:
        return jsonify(error='Not logged in.'), 401
    if not has_collab_access(session['username'], owner, project_name):
        return jsonify(error='Forbidden.'), 403
    return delete_project_path(project_files_dir(owner, project_name), file_path)


@app.get('/api/collaborate/<owner>/<project_name>/download')
def collab_download_root(owner, project_name):
    """Download the whole collaborated project as a zip archive."""
    if 'username' not in session:
        return jsonify(error='Not logged in.'), 401
    if not has_collab_access(session['username'], owner, project_name):
        return jsonify(error='Forbidden.'), 403
    return download_project_path(project_files_dir(owner, project_name), archive_name=project_name)


@app.get('/api/collaborate/<owner>/<project_name>/download/<path:item_path>')
def collab_download_item(owner, project_name, item_path):
    """Download a collaborated project file directly, or a folder as a zip archive."""
    if 'username' not in session:
        return jsonify(error='Not logged in.'), 401
    # additional validation on owner and project_name
    if not PROJECT_NAME_RE.match(owner) or not PROJECT_NAME_RE.match(project_name):
        return jsonify(error='Project not found.'), 404
    if not has_collab_access(session['username'], owner, project_name):
        return jsonify(error='Forbidden.'), 403
    return download_project_path(project_files_dir(owner, project_name), item_path, archive_name=project_name)


@app.post('/api/collaborate/<owner>/<project_name>/run/<path:file_path>')
def collab_run_file(owner, project_name, file_path):
    """Run a Python file in a collaborated project and return its stdout, stderr, and exit code."""
    if 'username' not in session:
        return jsonify(error='Not logged in.'), 401
    if not has_collab_access(session['username'], owner, project_name):
        return jsonify(error='Forbidden.'), 403
    if not is_safe_file_path(file_path):
        return jsonify(error='Invalid file path.'), 400
    if not file_path.endswith('.py'):
        return jsonify(error='Only Python (.py) files can be run.'), 400

    files_dir = project_files_dir(owner, project_name)
    full_path = os.path.join(files_dir, file_path)
    if not os.path.isfile(full_path):
        return jsonify(error='File not found.'), 404

    try:
        result = subprocess.run(
            ['python3', file_path],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=files_dir
        )
        return jsonify(
            ok=True,
            stdout=result.stdout[:50000],
            stderr=result.stderr[:50000],
            exit_code=result.returncode
        )
    except subprocess.TimeoutExpired:
        return jsonify(ok=True, stdout='', stderr='Execution timed out (10s limit).', exit_code=1)
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.post('/api/collaborate/<owner>/<project_name>/folders/<path:folder_path>')
def collab_create_folder(owner, project_name, folder_path):
    """Create a folder in a collaborated project."""
    if 'username' not in session:
        return jsonify(error='Not logged in.'), 401
    if not has_collab_access(session['username'], owner, project_name):
        return jsonify(error='Forbidden.'), 403
    if not is_safe_file_path(folder_path):
        return jsonify(error='Invalid folder name.'), 400
    files_dir = project_files_dir(owner, project_name)
    if not os.path.isdir(files_dir):
        return jsonify(error='Project not found.'), 404
    full_path = os.path.join(files_dir, folder_path)
    if os.path.isfile(full_path):
        return jsonify(error='A file already exists at that path.'), 409
    os.makedirs(full_path, exist_ok=True)
    return jsonify(ok=True)


init_db()


if __name__ == '__main__':
    app.run(debug=True, port=3000)
