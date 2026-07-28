const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { db, hashPassword, verifyPassword } = require('./db');

const PORT = process.env.PORT || 4000;
const SECRET_KEY = 'mahfaza_app_secret_key_2026';

function generateToken(userId, email) {
  const payload = Buffer.from(JSON.stringify({ id: userId, email, exp: Date.now() + 30 * 24 * 3600 * 1000 })).toString('base64url');
  const signature = crypto.createHmac('sha256', SECRET_KEY).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

function verifyToken(token) {
  if (!token || !token.includes('.')) return null;
  const [payload, signature] = token.split('.');
  const expectedSignature = crypto.createHmac('sha256', SECRET_KEY).update(payload).digest('base64url');
  if (signature !== expectedSignature) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (data.exp && Date.now() > data.exp) return null;
    return data;
  } catch (e) {
    return null;
  }
}

function sendJSON(res, data, status = 200) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  });
  res.end(JSON.stringify(data));
}

function parseBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try { resolve(body ? JSON.parse(body) : {}); }
      catch (e) { resolve({}); }
    });
  });
}

function logAudit(actorId, action, target, meta, workspaceId) {
  try {
    const id = 'log_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7);
    db.prepare('INSERT INTO audit_log (id, actor_id, action, target, meta, workspace_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
      id, actorId, action, target || '', meta || '', workspaceId || null, new Date().toISOString()
    );
  } catch (e) {
    try {
      const id = 'log_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7);
      db.prepare('INSERT INTO audit_log (id, actor_id, action, target, meta, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(
        id, actorId, action, target || '', meta || '', new Date().toISOString()
      );
    } catch (err) {}
  }
}

function recalcAccountBalance(accountId) {
  const acc = db.prepare('SELECT initial_balance FROM accounts WHERE id = ?').get(accountId);
  if (!acc) return;
  const incomeSum = db.prepare("SELECT COALESCE(SUM(amount), 0) as total FROM transactions WHERE account_id = ? AND type = 'income' AND is_deleted = 0").get(accountId).total;
  const expenseSum = db.prepare("SELECT COALESCE(SUM(amount), 0) as total FROM transactions WHERE account_id = ? AND type = 'expense' AND is_deleted = 0").get(accountId).total;
  const newBal = acc.initial_balance + incomeSum - expenseSum;
  db.prepare('UPDATE accounts SET current_balance = ? WHERE id = ?').run(newBal, accountId);
}

function authenticate(req, query = {}) {
  const authHeader = req.headers['authorization'];
  let token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
  if (!token && query && (query.token || query.t)) {
    token = query.token || query.t;
  }
  const payload = verifyToken(token);
  if (!payload) return null;
  const user = db.prepare('SELECT id, name, email, global_role, status FROM users WHERE id = ?').get(payload.id);
  if (!user || user.status === 'suspended') return null;
  return user;
}

function getMemberMembership(userId, workspaceId) {
  if (!userId || !workspaceId) return null;
  return db.prepare('SELECT role, status FROM workspace_members WHERE workspace_id = ? AND user_id = ?').get(workspaceId, userId);
}

function verifyWorkspaceAccess(currentUser, workspaceId, isWriteOperation = false) {
  if (!currentUser) return { allowed: false, error: 'غير مصرح (سجّل الدخول أولاً)', status: 401 };
  if (currentUser.global_role === 'super_admin') return { allowed: true, role: 'super_admin' };

  if (!workspaceId) return { allowed: false, error: 'معرف المساحة (workspace_id) مطلوب', status: 400 };

  const mem = getMemberMembership(currentUser.id, workspaceId);
  if (!mem || mem.status !== 'approved') {
    return { allowed: false, error: 'غير مصرح لك بالوصول لبيانات هذه المساحة', status: 403 };
  }

  if (isWriteOperation && mem.role === 'viewer') {
    return { allowed: false, error: 'صلاحيات مشاهد فقط (Viewer) - لا يمكنك الإضافة أو التعديل أو الحذف', status: 403 };
  }

  return { allowed: true, role: mem.role };
}

function generateJoinCode(prefix = 'WS') {
  return prefix.toUpperCase() + '-' + Math.floor(1000 + Math.random() * 9000);
}

function notifyUser(userId, title, message, type = 'info') {
  try {
    const id = 'notif_' + Date.now() + '_' + Math.random().toString(36).substring(2, 6);
    const now = new Date().toISOString();
    db.prepare('INSERT INTO notifications (id, user_id, title, message, type, is_read, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)').run(
      id, userId, title, message, type, now
    );
  } catch (e) {
    console.error('Notification insert error:', e);
  }
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    });
    return res.end();
  }

  const parsedUrl = new URL(req.url, `http://${req.headers.host}`);
  const pathname = parsedUrl.pathname;
  const method = req.method;
  const query = Object.fromEntries(parsedUrl.searchParams.entries());

  if (pathname === '/manifest.json') {
    const manifestPath = path.join(__dirname, 'manifest.json');
    if (fs.existsSync(manifestPath)) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(fs.readFileSync(manifestPath));
    }
  }

  if (pathname === '/sw.js') {
    const swPath = path.join(__dirname, 'sw.js');
    if (fs.existsSync(swPath)) {
      res.writeHead(200, { 'Content-Type': 'application/javascript' });
      return res.end(fs.readFileSync(swPath));
    }
  }

  if (pathname.startsWith('/api/')) {
    const body = await parseBody(req);

    // Auth Routes
    if (pathname === '/api/auth/demo-users' && method === 'GET') {
      const users = db.prepare('SELECT id, name, email, global_role, status FROM users').all();
      return sendJSON(res, users);
    }

    if (pathname === '/api/auth/register' && method === 'POST') {
      const { name, email, password } = body;
      if (!name || !email || !password) return sendJSON(res, { error: 'جميع الحقول مطلوبة' }, 400);

      const existing = db.prepare('SELECT id FROM users WHERE LOWER(email) = LOWER(?)').get(email);
      if (existing) return sendJSON(res, { error: 'هذا البريد مستخدم بالفعل' }, 400);

      const userId = 'u_' + Date.now();
      const pHash = hashPassword(password);
      const now = new Date().toISOString();

      db.prepare('INSERT INTO users (id, name, email, password_hash, global_role, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
        userId, name.trim(), email.trim().toLowerCase(), pHash, 'user', 'active', now
      );

      const wsId = 'ws_' + userId + '_personal';
      const code = generateJoinCode('P');
      db.prepare('INSERT INTO workspaces (id, name, type, icon, join_code, owner_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
        wsId, 'مساحتي الشخصية', 'personal', '👤', code, userId, now
      );
      db.prepare('INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES (?, ?, ?, ?)').run(
        'wm_' + wsId + '_' + userId, wsId, userId, 'owner'
      );

      db.prepare('INSERT INTO accounts (id, workspace_id, name, type, initial_balance, current_balance, color, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').run(
        'acc_' + userId + '_cash', wsId, 'الخزينة الشخصية', 'cash', 0, 0, '#0E9A73', 1, now
      );

      db.prepare('INSERT INTO categories (id, workspace_id, name, type, color, icon, sort_order, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(
        'cat_' + userId + '_sal', wsId, 'الراتب', 'income', '#0E9A73', '💼', 1, 1
      );
      db.prepare('INSERT INTO categories (id, workspace_id, name, type, color, icon, sort_order, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(
        'cat_' + userId + '_groc', wsId, 'المستلزمات والمعيشة', 'expense', '#E1503F', '🛒', 1, 1
      );

      logAudit(userId, 'signup', name);
      const token = generateToken(userId, email);
      const user = db.prepare('SELECT id, name, email, username, phone, job_title, bio, global_role, avatar, status FROM users WHERE id = ?').get(userId);
      return sendJSON(res, { token, user });
    }

    // INSTANT JOIN BY WORKSPACE CODE
    if (pathname === '/api/auth/join-by-code' && method === 'POST') {
      const { join_code, name, password, username, phone } = body;
      if (!join_code || !name || !password) return sendJSON(res, { error: 'كود الدعوة والاسم وكلمة السر حقول مطلوبة' }, 400);

      const targetWs = db.prepare('SELECT * FROM workspaces WHERE UPPER(join_code) = UPPER(?)').get(join_code.trim());
      if (!targetWs) return sendJSON(res, { error: 'كود الدعوة غير صحيح أو المساحة غير موجودة' }, 404);

      const userId = 'u_' + Date.now();
      const pHash = hashPassword(password);
      const now = new Date().toISOString();
      const userEmail = `user_${Date.now()}@mahfaza.app`;
      const finalUsername = (username || `user_${Math.floor(1000 + Math.random() * 9000)}`).trim().toLowerCase();

      if (username) {
        const existingU = db.prepare('SELECT id FROM users WHERE LOWER(username) = LOWER(?)').get(finalUsername);
        if (existingU) return sendJSON(res, { error: 'اسم المستخدم هذا مأخوذ بالفعل، اختر اسماً آخر' }, 400);
      }

      db.prepare('INSERT INTO users (id, name, email, username, phone, job_title, bio, password_hash, global_role, avatar, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(
        userId, name.trim(), userEmail, finalUsername, phone || '', 'عضو أسرة', '', pHash, 'user', '', 'active', now
      );

      // Create membership with status = 'pending' until workspace owner approves
      db.prepare('INSERT INTO workspace_members (id, workspace_id, user_id, role, status, monthly_spending_limit, can_add_expenses, can_view_reports) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(
        'wm_' + targetWs.id + '_' + userId, targetWs.id, userId, 'member', 'pending', 0, 1, 1
      );

      db.prepare("INSERT INTO invites (id, workspace_id, user_id, email, role, status, invited_by, created_at) VALUES (?, ?, ?, ?, 'member', 'pending_approval', ?, ?)").run(
        'req_' + Date.now(), targetWs.id, userId, userEmail, userId, now
      );

      logAudit(userId, 'join_by_code', name.trim(), 'مساحة: ' + targetWs.name);
      const token = generateToken(userId, userEmail);
      const user = db.prepare('SELECT id, name, email, username, phone, job_title, bio, global_role, avatar, status FROM users WHERE id = ?').get(userId);
      return sendJSON(res, { token, user, workspace: targetWs, status: 'pending' });
    }

    if (pathname === '/api/auth/login' && method === 'POST') {
      const { email, password, demoUserId } = body;
      let user;

      if (demoUserId) {
        user = db.prepare('SELECT * FROM users WHERE id = ?').get(demoUserId);
      } else {
        if (!email || !password) return sendJSON(res, { error: 'يرجى إدخال البريد الإلكتروني/اسم المستخدم وكلمة المرور' }, 400);
        const loginQuery = email.trim().toLowerCase();
        user = db.prepare('SELECT * FROM users WHERE LOWER(email) = ? OR LOWER(username) = ?').get(loginQuery, loginQuery);
        if (!user || !verifyPassword(password, user.password_hash)) {
          return sendJSON(res, { error: 'البريد الإلكتروني/اسم المستخدم أو كلمة المرور غير صحيحة' }, 400);
        }
      }

      if (!user) return sendJSON(res, { error: 'المستخدم غير موجود' }, 404);
      if (user.status === 'suspended') return sendJSON(res, { error: 'الحساب معلّق من السوبر أدمن' }, 403);

      logAudit(user.id, 'login', user.name);
      const token = generateToken(user.id, user.email);
      return sendJSON(res, { token, user: { id: user.id, name: user.name, email: user.email, username: user.username, phone: user.phone, job_title: user.job_title, bio: user.bio, global_role: user.global_role, avatar: user.avatar, status: user.status } });
    }

    // Authenticated API Routes
    const currentUser = authenticate(req, query);
    if (!currentUser) return sendJSON(res, { error: 'غير مصرح: يرجى تسجيل الدخول' }, 401);

    if (pathname === '/api/auth/me' && method === 'GET') {
      const authUser = currentUser;
      const fullUser = db.prepare('SELECT id, name, email, username, phone, job_title, bio, global_role, avatar, status FROM users WHERE id = ?').get(authUser.id);

      const workspaces = db.prepare(`
        SELECT w.*, wm.role as my_role, wm.status as my_membership_status, wm.monthly_spending_limit, wm.can_add_expenses, wm.can_view_reports
        FROM workspaces w
        JOIN workspace_members wm ON w.id = wm.workspace_id
        WHERE wm.user_id = ?
      `).all(authUser.id);

      return sendJSON(res, { user: fullUser, workspaces });
    }

    if (pathname === '/api/auth/profile' && method === 'PUT') {
      const authUser = authenticate(req);
      if (!authUser) return sendJSON(res, { error: 'غير مصرح' }, 401);
      const { name, email, username, phone, job_title, bio, avatar } = body;
      if (!name || !name.trim()) return sendJSON(res, { error: 'الاسم مطلوب' }, 400);

      const cleanEmail = email ? email.trim().toLowerCase() : '';
      if (cleanEmail) {
        const existingEmail = db.prepare('SELECT id FROM users WHERE LOWER(email) = ? AND id != ?').get(cleanEmail, authUser.id);
        if (existingEmail) return sendJSON(res, { error: 'البريد الإلكتروني مستخدم بالفعل بحساب آخر' }, 400);
      }

      const cleanUsername = username ? username.trim().toLowerCase() : '';
      if (cleanUsername) {
        const existingUsername = db.prepare('SELECT id FROM users WHERE LOWER(username) = ? AND id != ?').get(cleanUsername, authUser.id);
        if (existingUsername) return sendJSON(res, { error: 'اسم المستخدم مأخوذ بالفعل، اختر اسماً آخر' }, 400);
      }

      db.prepare("UPDATE users SET name = ?, email = COALESCE(NULLIF(?, ''), email), username = ?, phone = ?, job_title = ?, bio = ?, avatar = ? WHERE id = ?").run(
        name.trim(), cleanEmail, cleanUsername, phone || '', job_title || '', bio || '', avatar || '', authUser.id
      );
      logAudit(authUser.id, 'update_profile', name.trim());
      const updated = db.prepare('SELECT id, name, email, username, phone, job_title, bio, global_role, avatar, status FROM users WHERE id = ?').get(authUser.id);
      return sendJSON(res, updated);
    }

    // Super Admin Commands
    if (pathname === '/api/admin/overview' && method === 'GET') {
      if (currentUser.global_role !== 'super_admin') return sendJSON(res, { error: 'صلاحيات سوبر أدمن فقط' }, 403);
      const usersCount = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
      const workspacesCount = db.prepare('SELECT COUNT(*) as c FROM workspaces').get().c;
      const totalBalance = db.prepare('SELECT COALESCE(SUM(current_balance), 0) as s FROM accounts').get().s;
      const totalTxs = db.prepare('SELECT COUNT(*) as c FROM transactions WHERE is_deleted = 0').get().c;

      return sendJSON(res, { usersCount, workspacesCount, totalBalance, totalTxs, dbStatus: 'نشطة ومستقرة (SQLite WAL)' });
    }

    if (pathname === '/api/admin/all-transactions' && method === 'GET') {
      if (currentUser.global_role !== 'super_admin') return sendJSON(res, { error: 'صلاحيات سوبر أدمن فقط' }, 403);
      const txs = db.prepare(`
        SELECT t.*, u.name as creator_name, w.name as workspace_name, c.name as category_name, c.icon as category_icon, a.name as account_name
        FROM transactions t
        LEFT JOIN users u ON t.created_by = u.id
        LEFT JOIN workspaces w ON t.workspace_id = w.id
        LEFT JOIN categories c ON t.category_id = c.id
        LEFT JOIN accounts a ON t.account_id = a.id
        WHERE t.is_deleted = 0
        ORDER BY t.date DESC, t.created_at DESC
      `).all();
      return sendJSON(res, txs);
    }

    if (pathname === '/api/admin/all-workspaces' && method === 'GET') {
      if (currentUser.global_role !== 'super_admin') return sendJSON(res, { error: 'صلاحيات سوبر أدمن فقط' }, 403);
      const ws = db.prepare(`
        SELECT w.*, u.name as owner_name, u.email as owner_email,
               (SELECT COUNT(*) FROM workspace_members WHERE workspace_id = w.id) as members_count
        FROM workspaces w
        LEFT JOIN users u ON w.owner_id = u.id
        ORDER BY w.created_at DESC
      `).all();
      return sendJSON(res, ws);
    }

    // Workspaces
    if (pathname === '/api/workspaces' && method === 'GET') {
      const workspaces = db.prepare(`
        SELECT w.*, wm.role as my_role
        FROM workspaces w
        JOIN workspace_members wm ON w.id = wm.workspace_id
        WHERE wm.user_id = ?
      `).all(currentUser.id);
      return sendJSON(res, workspaces);
    }

    if (pathname === '/api/workspaces' && method === 'POST') {
      const { name, icon, type, custom_code } = body;
      if (!name) return sendJSON(res, { error: 'اسم المساحة مطلوب' }, 400);

      const wsId = 'ws_' + Date.now();
      const code = (custom_code || generateJoinCode(name.slice(0, 3))).toUpperCase();
      const now = new Date().toISOString();

      try {
        db.prepare('INSERT INTO workspaces (id, name, type, icon, join_code, owner_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
          wsId, name.trim(), type || 'shared', icon || '👨‍👩‍👦', code, currentUser.id, now
        );
      } catch (e) {
        return sendJSON(res, { error: 'كود الانضمام المخصص مستخدم بالفعل، اختر كوداً آخر' }, 400);
      }

      db.prepare('INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES (?, ?, ?, ?)').run(
        'wm_' + wsId + '_' + currentUser.id, wsId, currentUser.id, 'owner'
      );

      logAudit(currentUser.id, 'create_workspace', name, 'الكود: ' + code);
      const newWs = db.prepare('SELECT * FROM workspaces WHERE id = ?').get(wsId);
      newWs.my_role = 'owner';
      return sendJSON(res, newWs);
    }

    // Join Code & Membership Requests
    const wsCodeMatch = pathname.match(/^\/api\/workspaces\/([^\/]+)\/code$/);
    if (wsCodeMatch && method === 'PUT') {
      const wsId = wsCodeMatch[1];
      const ws = db.prepare('SELECT owner_id FROM workspaces WHERE id = ?').get(wsId);
      if (!ws) return sendJSON(res, { error: 'المساحة غير موجودة' }, 404);
      if (ws.owner_id !== currentUser.id && currentUser.global_role !== 'super_admin') {
        return sendJSON(res, { error: 'مالك المساحة فقط هو من يستطيع تعديل كود الانضمام' }, 403);
      }

      const newCode = (body.custom_code || generateJoinCode()).toUpperCase();
      try {
        db.prepare('UPDATE workspaces SET join_code = ? WHERE id = ?').run(newCode, wsId);
        logAudit(currentUser.id, 'update_join_code', wsId, 'كود جديد: ' + newCode);
        return sendJSON(res, { join_code: newCode });
      } catch (e) {
        return sendJSON(res, { error: 'هذا الكود مستخدم في مساحة أخرى' }, 400);
      }
    }

    if (pathname === '/api/workspaces/join-request' && method === 'POST') {
      const { join_code } = body;
      if (!join_code) return sendJSON(res, { error: 'يرجى إدخال كود الانضمام' }, 400);

      const targetWs = db.prepare('SELECT * FROM workspaces WHERE UPPER(join_code) = UPPER(?)').get(join_code.trim());
      if (!targetWs) return sendJSON(res, { error: 'كود الانضمام غير صحيح أو المساحة غير موجودة' }, 404);

      const isMember = db.prepare('SELECT id, status FROM workspace_members WHERE workspace_id = ? AND user_id = ?').get(targetWs.id, currentUser.id);
      if (isMember) {
        if (isMember.status === 'pending') {
          return sendJSON(res, { error: 'تم إرسال طلب انضمام سابق لهذه المساحة وفي انتظار موافقة المالك' }, 400);
        }
        return sendJSON(res, { error: 'أنت عضو بالفعل في هذه المساحة' }, 400);
      }

      const wmId = 'wm_' + targetWs.id + '_' + currentUser.id;
      db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role, status) VALUES (?, ?, ?, 'member', 'pending')").run(
        wmId, targetWs.id, currentUser.id
      );

      const invId = 'req_' + Date.now();
      db.prepare("INSERT INTO invites (id, workspace_id, user_id, email, role, status, invited_by, created_at) VALUES (?, ?, ?, ?, 'member', 'pending_approval', ?, ?)").run(
        invId, targetWs.id, currentUser.id, currentUser.email, currentUser.id, new Date().toISOString()
      );

      logAudit(currentUser.id, 'join_request', targetWs.name);
      return sendJSON(res, { success: true, message: 'تم إرسال طلب الانضمام لمالك المساحة بنجاح' });
    }

    const wsMembersMatch = pathname.match(/^\/api\/workspaces\/([^\/]+)\/members$/);
    if (wsMembersMatch && method === 'GET') {
      const wsId = wsMembersMatch[1];
      const members = db.prepare(`
        SELECT wm.id, wm.workspace_id, wm.user_id, wm.role, wm.status, wm.monthly_spending_limit, wm.can_add_expenses, wm.can_view_reports, wm.allowed_categories,
               u.name, u.email, u.username, u.global_role,
               COALESCE((
                 SELECT SUM(t.amount)
                 FROM transactions t
                 WHERE t.workspace_id = wm.workspace_id
                   AND t.created_by = wm.user_id
                   AND t.type = 'expense'
                   AND t.is_deleted = 0
                   AND t.date >= strftime('%Y-%m-01', 'now')
               ), 0) as current_month_spent
        FROM workspace_members wm
        JOIN users u ON wm.user_id = u.id
        WHERE wm.workspace_id = ? AND (wm.status IS NULL OR wm.status = 'approved')
      `).all(wsId);

      const requests = db.prepare(`
        SELECT wm.id, wm.workspace_id, wm.user_id, wm.status, u.name, u.email, u.username
        FROM workspace_members wm
        JOIN users u ON wm.user_id = u.id
        WHERE wm.workspace_id = ? AND wm.status = 'pending'
      `).all(wsId);

      const pendingInvites = db.prepare(`
        SELECT inv.id, inv.workspace_id, inv.user_id, 'pending' as status, u.name, u.email, u.username
        FROM invites inv
        JOIN users u ON inv.user_id = u.id
        WHERE inv.workspace_id = ? AND inv.status = 'pending_approval'
          AND inv.user_id NOT IN (SELECT user_id FROM workspace_members WHERE workspace_id = ?)
      `).all(wsId, wsId);

      const allRequests = [...requests, ...pendingInvites];
      return sendJSON(res, { members, requests: allRequests });
    }

    const wsRequestActionMatch = pathname.match(/^\/api\/workspaces\/([^\/]+)\/requests\/([^\/]+)$/);
    if (wsRequestActionMatch && method === 'PUT') {
      const wsId = wsRequestActionMatch[1];
      const ws = db.prepare('SELECT owner_id FROM workspaces WHERE id = ?').get(wsId);
      if (!ws) return sendJSON(res, { error: 'المساحة غير موجودة' }, 404);
      if (ws.owner_id !== currentUser.id && currentUser.global_role !== 'super_admin') {
        return sendJSON(res, { error: 'صلاحية مالك المساحة فقط' }, 403);
      }

      const { action, role, monthly_spending_limit } = body; // action = 'approve' | 'reject'
      const reqId = wsRequestActionMatch[2];

      if (action === 'approve') {
        const wm = db.prepare('SELECT user_id FROM workspace_members WHERE id = ? AND workspace_id = ?').get(reqId, wsId);
        if (wm) {
          db.prepare("UPDATE workspace_members SET status = 'approved', role = COALESCE(?, 'member'), monthly_spending_limit = COALESCE(?, 0) WHERE id = ? AND workspace_id = ?").run(
            role || 'member', monthly_spending_limit || 0, reqId, wsId
          );
          db.prepare("UPDATE invites SET status = 'approved' WHERE workspace_id = ? AND user_id = ?").run(wsId, wm.user_id);
        } else {
          const inv = db.prepare('SELECT user_id FROM invites WHERE id = ? AND workspace_id = ?').get(reqId, wsId);
          if (inv) {
            const wmId = 'wm_' + wsId + '_' + inv.user_id;
            db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role, status, monthly_spending_limit) VALUES (?, ?, ?, ?, 'approved', ?)").run(
              wmId, wsId, inv.user_id, role || 'member', monthly_spending_limit || 0
            );
            db.prepare("UPDATE invites SET status = 'approved' WHERE id = ?").run(reqId);
          }
        }
        logAudit(currentUser.id, 'approve_join', reqId, 'دور: ' + (role || 'member'));
      } else {
        const wm = db.prepare('SELECT user_id FROM workspace_members WHERE id = ? AND workspace_id = ?').get(reqId, wsId);
        if (wm) {
          db.prepare("DELETE FROM workspace_members WHERE id = ? AND workspace_id = ?").run(reqId, wsId);
          db.prepare("UPDATE invites SET status = 'rejected' WHERE workspace_id = ? AND user_id = ?").run(wsId, wm.user_id);
        } else {
          db.prepare("UPDATE invites SET status = 'rejected' WHERE id = ? AND workspace_id = ?").run(reqId, wsId);
        }
        logAudit(currentUser.id, 'reject_join', reqId);
      }
      return sendJSON(res, { success: true });
    }

    const wsMemberRoleMatch = pathname.match(/^\/api\/workspaces\/([^\/]+)\/members\/([^\/]+)$/);
    if (wsMemberRoleMatch && (method === 'PUT' || method === 'DELETE')) {
      const wsId = wsMemberRoleMatch[1];
      const memberId = wsMemberRoleMatch[2];
      const ws = db.prepare('SELECT owner_id FROM workspaces WHERE id = ?').get(wsId);
      if (!ws) return sendJSON(res, { error: 'المساحة غير موجودة' }, 404);
      if (ws.owner_id !== currentUser.id && currentUser.global_role !== 'super_admin') {
        return sendJSON(res, { error: 'صلاحيات مالك المساحة فقط' }, 403);
      }

      if (method === 'PUT') {
        const { role, monthly_spending_limit, can_add_expenses, can_view_reports, allowed_categories } = body;
        const roleVal = role || null;
        const limitVal = (monthly_spending_limit !== undefined && monthly_spending_limit !== null) ? Number(monthly_spending_limit) : null;
        const canAddVal = (can_add_expenses !== undefined && can_add_expenses !== null) ? Number(can_add_expenses) : null;
        const canViewVal = (can_view_reports !== undefined && can_view_reports !== null) ? Number(can_view_reports) : null;
        const catsVal = (allowed_categories !== undefined && allowed_categories !== null) ? String(allowed_categories) : null;

        db.prepare(`
          UPDATE workspace_members
          SET role = COALESCE(?, role),
              monthly_spending_limit = COALESCE(?, monthly_spending_limit),
              can_add_expenses = COALESCE(?, can_add_expenses),
              can_view_reports = COALESCE(?, can_view_reports),
              allowed_categories = COALESCE(?, allowed_categories)
          WHERE id = ? AND workspace_id = ?
        `).run(roleVal, limitVal, canAddVal, canViewVal, catsVal, memberId, wsId);
        logAudit(currentUser.id, 'update_member_permissions', memberId);
        return sendJSON(res, { success: true });
      }

      if (method === 'DELETE') {
        const memberRow = db.prepare('SELECT user_id FROM workspace_members WHERE id = ? AND workspace_id = ?').get(memberId, wsId);
        if (memberRow && memberRow.user_id === ws.owner_id) {
          return sendJSON(res, { error: 'لا يمكن إزالة مالك المساحة الأساسي' }, 400);
        }
        db.prepare('DELETE FROM workspace_members WHERE id = ? AND workspace_id = ?').run(memberId, wsId);
        logAudit(currentUser.id, 'remove_member', memberId);
        return sendJSON(res, { success: true });
      }
    }

    // Fund Requests API
    if (pathname === '/api/fund-requests' && method === 'GET') {
      const wsId = query.workspace_id;
      const wsAccess = verifyWorkspaceAccess(currentUser, wsId, false);
      if (!wsAccess.allowed) return sendJSON(res, { error: wsAccess.error }, wsAccess.status);

      const reqs = db.prepare(`
        SELECT fr.*, u.name as user_name, u.email as user_email, u.username, c.name as category_name, c.icon as category_icon
        FROM fund_requests fr
        JOIN users u ON fr.user_id = u.id
        LEFT JOIN categories c ON fr.category_id = c.id
        WHERE fr.workspace_id = ?
        ORDER BY fr.created_at DESC
      `).all(wsId);
      return sendJSON(res, reqs);
    }

    if (pathname === '/api/fund-requests' && method === 'POST') {
      const { workspace_id, title, amount, category_id, note } = body;
      const wsAccess = verifyWorkspaceAccess(currentUser, workspace_id, true);
      if (!wsAccess.allowed) return sendJSON(res, { error: wsAccess.error }, wsAccess.status);

      const id = 'fr_' + Date.now();
      const now = new Date().toISOString();
      db.prepare('INSERT INTO fund_requests (id, workspace_id, user_id, title, amount, category_id, note, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').run(
        id, workspace_id, currentUser.id, title.trim(), Number(amount), category_id || null, note || '', 'pending', now
      );

      const ws = db.prepare('SELECT owner_id, name FROM workspaces WHERE id = ?').get(workspace_id);
      if (ws) {
        notifyUser(ws.owner_id, 'طلب مصروف جديد 💸', `أرسل ${currentUser.name} طلب تمويل لمبلغ ${amount} ج.م (${title})`, 'warning');
      }

      logAudit(currentUser.id, 'create_fund_request', title.trim(), 'المبلغ: ' + amount);
      return sendJSON(res, { success: true, id });
    }

    const fundReqMatch = pathname.match(/^\/api\/fund-requests\/([^\/]+)$/);
    if (fundReqMatch && method === 'PUT') {
      const { action } = body; // 'approve' | 'reject'
      const reqId = fundReqMatch[1];
      const fr = db.prepare('SELECT * FROM fund_requests WHERE id = ?').get(reqId);
      if (!fr) return sendJSON(res, { error: 'الطلب غير موجود' }, 404);

      const wsAccess = verifyWorkspaceAccess(currentUser, fr.workspace_id, true);
      if (!wsAccess.allowed) return sendJSON(res, { error: wsAccess.error }, wsAccess.status);

      const ws = db.prepare('SELECT owner_id FROM workspaces WHERE id = ?').get(fr.workspace_id);
      if (!ws || (ws.owner_id !== currentUser.id && currentUser.global_role !== 'super_admin')) {
        return sendJSON(res, { error: 'صلاحيات مالك المساحة فقط للموافقة على التمويل' }, 403);
      }

      if (action === 'approve') {
        db.prepare("UPDATE fund_requests SET status = 'approved' WHERE id = ?").run(reqId);
        const txId = 'tx_' + Date.now();
        const firstAccount = db.prepare('SELECT id FROM accounts WHERE workspace_id = ? AND is_active = 1 LIMIT 1').get(fr.workspace_id);
        const accId = firstAccount ? firstAccount.id : null;

        const firstCategory = db.prepare('SELECT id FROM categories WHERE workspace_id = ? LIMIT 1').get(fr.workspace_id);
        const catId = fr.category_id || (firstCategory ? firstCategory.id : null);

        db.prepare(`
          INSERT INTO transactions (id, workspace_id, account_id, category_id, type, amount, note, date, created_by, is_deleted, is_favorite, created_at)
          VALUES (?, ?, ?, ?, 'expense', ?, ?, strftime('%Y-%m-%d', 'now'), ?, 0, 0, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        `).run(txId, fr.workspace_id, accId, catId, fr.amount, 'طلب تمويل معتمد: ' + fr.title + (fr.note ? ' - ' + fr.note : ''), fr.user_id);

        if (accId) {
          db.prepare('UPDATE accounts SET current_balance = current_balance - ? WHERE id = ?').run(fr.amount, accId);
        }
        notifyUser(fr.user_id, 'تمت الموافقة على طلب المصروف 💸', `وافق مالك الأسرة على طلبك (${fr.title}) بمبلغ ${fr.amount} ج.م وتم إضافة المصروف.`, 'success');
        logAudit(currentUser.id, 'approve_fund_request', fr.title);
      } else {
        db.prepare("UPDATE fund_requests SET status = 'rejected' WHERE id = ?").run(reqId);
        notifyUser(fr.user_id, 'تم رفض طلب المصروف ❌', `اعتذر مالك الأسرة عن قبول طلب المصروف (${fr.title}).`, 'danger');
        logAudit(currentUser.id, 'reject_fund_request', fr.title);
      }
      return sendJSON(res, { success: true });
    }

    // NOTIFICATIONS API
    if (pathname === '/api/notifications' && method === 'GET') {
      const notifs = db.prepare('SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 30').all(currentUser.id);
      const unreadCount = db.prepare('SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = 0').get(currentUser.id).count;
      return sendJSON(res, { notifications: notifs, unread_count: unreadCount });
    }

    if (pathname === '/api/notifications/read-all' && method === 'PUT') {
      db.prepare('UPDATE notifications SET is_read = 1 WHERE user_id = ?').run(currentUser.id);
      return sendJSON(res, { success: true });
    }

    // RECURRING BILLS API
    if (pathname === '/api/recurring-bills' && method === 'GET') {
      const wsId = query.workspace_id;
      const wsAccess = verifyWorkspaceAccess(currentUser, wsId, false);
      if (!wsAccess.allowed) return sendJSON(res, { error: wsAccess.error }, wsAccess.status);

      const bills = db.prepare(`
        SELECT rb.*, c.name as category_name, c.icon as category_icon, a.name as account_name
        FROM recurring_bills rb
        LEFT JOIN categories c ON rb.category_id = c.id
        LEFT JOIN accounts a ON rb.account_id = a.id
        WHERE rb.workspace_id = ? AND rb.is_active = 1
        ORDER BY rb.due_day ASC
      `).all(wsId);
      return sendJSON(res, bills);
    }

    if (pathname === '/api/recurring-bills' && method === 'POST') {
      const { workspace_id, title, amount, due_day, category_id, account_id } = body;
      const wsAccess = verifyWorkspaceAccess(currentUser, workspace_id, true);
      if (!wsAccess.allowed) return sendJSON(res, { error: wsAccess.error }, wsAccess.status);

      const id = 'rb_' + Date.now();
      const now = new Date().toISOString();
      db.prepare('INSERT INTO recurring_bills (id, workspace_id, title, amount, due_day, category_id, account_id, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)').run(
        id, workspace_id, title.trim(), Number(amount), Number(due_day), category_id || null, account_id || null, now
      );
      logAudit(currentUser.id, 'create_recurring_bill', title.trim());
      return sendJSON(res, { success: true, id });
    }

    const updateBillMatch = pathname.match(/^\/api\/recurring-bills\/([^\/]+)$/);
    if (updateBillMatch && method === 'PUT') {
      const billId = updateBillMatch[1];
      const oldBill = db.prepare('SELECT * FROM recurring_bills WHERE id = ?').get(billId);
      if (!oldBill) return sendJSON(res, { error: 'الفاتورة غير موجودة' }, 404);

      const wsAccess = verifyWorkspaceAccess(currentUser, oldBill.workspace_id, true);
      if (!wsAccess.allowed) return sendJSON(res, { error: wsAccess.error }, wsAccess.status);

      const { title, amount, due_day, category_id, account_id } = body;
      db.prepare('UPDATE recurring_bills SET title = ?, amount = ?, due_day = ?, category_id = ?, account_id = ? WHERE id = ?').run(
        title ? title.trim() : oldBill.title,
        amount !== undefined ? Number(amount) : oldBill.amount,
        due_day !== undefined ? Number(due_day) : oldBill.due_day,
        category_id !== undefined ? (category_id || null) : oldBill.category_id,
        account_id !== undefined ? (account_id || null) : oldBill.account_id,
        billId
      );
      logAudit(currentUser.id, 'update_recurring_bill', title ? title.trim() : oldBill.title);
      return sendJSON(res, { success: true });
    }

    const payBillMatch = pathname.match(/^\/api\/recurring-bills\/([^\/]+)\/pay$/);
    if (payBillMatch && method === 'POST') {
      const billId = payBillMatch[1];
      const bill = db.prepare('SELECT * FROM recurring_bills WHERE id = ?').get(billId);
      if (!bill) return sendJSON(res, { error: 'الفاتورة غير موجودة' }, 404);

      const wsAccess = verifyWorkspaceAccess(currentUser, bill.workspace_id, true);
      if (!wsAccess.allowed) return sendJSON(res, { error: wsAccess.error }, wsAccess.status);

      const currentMonth = new Date().toISOString().substring(0, 7);
      const txId = 'tx_' + Date.now();
      const firstAcc = db.prepare('SELECT id FROM accounts WHERE workspace_id = ? AND is_active = 1 LIMIT 1').get(bill.workspace_id);
      const accId = bill.account_id || (firstAcc ? firstAcc.id : null);
      const firstCat = db.prepare('SELECT id FROM categories WHERE workspace_id = ? LIMIT 1').get(bill.workspace_id);
      const catId = bill.category_id || (firstCat ? firstCat.id : null);

      db.prepare(`
        INSERT INTO transactions (id, workspace_id, account_id, category_id, type, amount, note, date, created_by, is_deleted, is_favorite, created_at)
        VALUES (?, ?, ?, ?, 'expense', ?, ?, strftime('%Y-%m-%d', 'now'), ?, 0, 0, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
      `).run(txId, bill.workspace_id, accId, catId, bill.amount, 'سداد فاتورة دورية: ' + bill.title, currentUser.id);

      if (accId) {
        db.prepare('UPDATE accounts SET current_balance = current_balance - ? WHERE id = ?').run(bill.amount, accId);
      }
      db.prepare('UPDATE recurring_bills SET last_paid_month = ? WHERE id = ?').run(currentMonth, billId);

      notifyUser(currentUser.id, 'تم سداد الفاتورة ⚡', `تم سداد فاتورة (${bill.title}) بمبلغ ${bill.amount} ج.م بنجاح!`, 'success');
      logAudit(currentUser.id, 'pay_recurring_bill', bill.title);
      return sendJSON(res, { success: true });
    }

    const deleteBillMatch = pathname.match(/^\/api\/recurring-bills\/([^\/]+)$/);
    if (deleteBillMatch && method === 'DELETE') {
      const bill = db.prepare('SELECT workspace_id FROM recurring_bills WHERE id = ?').get(deleteBillMatch[1]);
      if (!bill) return sendJSON(res, { error: 'الفاتورة غير موجودة' }, 404);

      const wsAccess = verifyWorkspaceAccess(currentUser, bill.workspace_id, true);
      if (!wsAccess.allowed) return sendJSON(res, { error: wsAccess.error }, wsAccess.status);

      db.prepare('DELETE FROM recurring_bills WHERE id = ?').run(deleteBillMatch[1]);
      return sendJSON(res, { success: true });
    }

    const wsCurrencyMatch = pathname.match(/^\/api\/workspaces\/([^\/]+)\/currency$/);
    if (wsCurrencyMatch && method === 'PUT') {
      const wsId = wsCurrencyMatch[1];
      const { currency } = body;
      const wsAccess = verifyWorkspaceAccess(currentUser, wsId, true);
      if (!wsAccess.allowed) return sendJSON(res, { error: wsAccess.error }, wsAccess.status);
      if (!currency) return sendJSON(res, { error: 'العملة مطلوبة' }, 400);

      db.prepare('UPDATE workspaces SET currency = ? WHERE id = ?').run(currency, wsId);
      logAudit(currentUser.id, 'update_workspace_currency', wsId, currency);
      return sendJSON(res, { success: true, currency });
    }

    // EXPORT TO EXCEL / CSV API
    if (pathname === '/api/export/excel' && method === 'GET') {
      const wsId = query.workspace_id;
      const wsAccess = verifyWorkspaceAccess(currentUser, wsId, false);
      if (!wsAccess.allowed) return sendJSON(res, { error: wsAccess.error }, wsAccess.status);

      const txs = db.prepare(`
        SELECT t.date, t.type, t.amount, t.note, c.name as category_name, a.name as account_name, u.name as user_name
        FROM transactions t
        LEFT JOIN categories c ON t.category_id = c.id
        LEFT JOIN accounts a ON t.account_id = a.id
        LEFT JOIN users u ON t.created_by = u.id
        WHERE t.workspace_id = ? AND t.is_deleted = 0
        ORDER BY t.date DESC
      `).all(wsId);

      let csv = '\uFEFFالتاريخ,النوع,المبلغ,الفئة,الحساب,البيان / الملاحظات,المسجل بواسطة\n';
      txs.forEach(t => {
        const typeLabel = t.type === 'expense' ? 'مصروف' : 'دخل';
        const noteClean = (t.note || '').replace(/"/g, '""');
        csv += `"${t.date}","${typeLabel}","${t.amount}","${t.category_name || ''}","${t.account_name || ''}","${noteClean}","${t.user_name || ''}"\n`;
      });

      res.writeHead(200, {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': 'attachment; filename="mahfaza_report_' + Date.now() + '.csv"'
      });
      return res.end(csv);
    }

    // AUDIT LOG API (Scoped Security)
    if (pathname === '/api/audit-log' && method === 'GET') {
      if (currentUser.global_role === 'super_admin') {
        const logs = db.prepare(`
          SELECT al.*, u.name as actor_name, u.email as actor_email
          FROM audit_log al
          LEFT JOIN users u ON al.actor_id = u.id
          ORDER BY al.created_at DESC LIMIT 100
        `).all();
        return sendJSON(res, logs);
      } else {
        const logs = db.prepare(`
          SELECT al.*, u.name as actor_name, u.email as actor_email
          FROM audit_log al
          LEFT JOIN users u ON al.actor_id = u.id
          WHERE al.actor_id = ? OR al.target IN (
            SELECT id FROM workspaces WHERE id IN (
              SELECT workspace_id FROM workspace_members WHERE user_id = ? AND status = 'approved'
            )
          )
          ORDER BY al.created_at DESC LIMIT 100
        `).all(currentUser.id, currentUser.id);
        return sendJSON(res, logs);
      }
    }

    // Accounts
    if (pathname === '/api/accounts' && method === 'GET') {
      const wsAccess = verifyWorkspaceAccess(currentUser, query.workspace_id, false);
      if (!wsAccess.allowed) return sendJSON(res, { error: wsAccess.error }, wsAccess.status);

      const accounts = db.prepare('SELECT * FROM accounts WHERE workspace_id = ?').all(query.workspace_id);
      return sendJSON(res, accounts);
    }
    if (pathname === '/api/accounts' && method === 'POST') {
      const { workspace_id, name, type, initial_balance, color } = body;
      const wsAccess = verifyWorkspaceAccess(currentUser, workspace_id, true);
      if (!wsAccess.allowed) return sendJSON(res, { error: wsAccess.error }, wsAccess.status);

      const id = 'acc_' + Date.now();
      const bal = parseFloat(initial_balance) || 0;
      const now = new Date().toISOString();
      db.prepare('INSERT INTO accounts (id, workspace_id, name, type, initial_balance, current_balance, color, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)').run(
        id, workspace_id, name.trim(), type || 'cash', bal, bal, color || '#0E9A73', now
      );
      return sendJSON(res, db.prepare('SELECT * FROM accounts WHERE id = ?').get(id));
    }
    if (pathname === '/api/accounts/transfer' && method === 'POST') {
      const { workspace_id, from_account_id, to_account_id, amount, date, note } = body;
      const wsAccess = verifyWorkspaceAccess(currentUser, workspace_id, true);
      if (!wsAccess.allowed) return sendJSON(res, { error: wsAccess.error }, wsAccess.status);

      if (!from_account_id || !to_account_id || !amount || Number(amount) <= 0) {
        return sendJSON(res, { error: 'يرجى تحديد حساب المصدر وحساب الوجهة ومبلغ تحويل أكبر من صفر' }, 400);
      }
      if (from_account_id === to_account_id) {
        return sendJSON(res, { error: 'لا يمكن التحويل لنفس الحساب، اختر حساب وجهة مختلف' }, 400);
      }

      const fromAcc = db.prepare('SELECT * FROM accounts WHERE id = ? AND workspace_id = ?').get(from_account_id, workspace_id);
      const toAcc = db.prepare('SELECT * FROM accounts WHERE id = ? AND workspace_id = ?').get(to_account_id, workspace_id);

      if (!fromAcc || !toAcc) {
        return sendJSON(res, { error: 'أحد الحسابات المحددة غير موجود في هذه المساحة' }, 404);
      }

      let transferCategory = db.prepare("SELECT id FROM categories WHERE workspace_id = ? AND (LOWER(name) LIKE '%تحويل%' OR LOWER(name) LIKE '%تحويلات%') LIMIT 1").get(workspace_id);
      if (!transferCategory) {
        transferCategory = db.prepare("SELECT id FROM categories WHERE workspace_id = ? LIMIT 1").get(workspace_id);
      }
      const catId = transferCategory ? transferCategory.id : 'cat_transfer';

      const transferAmount = parseFloat(amount);
      const transferDate = date || new Date().toISOString().slice(0, 10);
      const now = new Date().toISOString();
      const customNote = note ? note.trim() : '';

      const txFromId = 'tx_' + Date.now() + '_from';
      const txToId = 'tx_' + (Date.now() + 1) + '_to';

      const noteFrom = `تحويل إلى: (${toAcc.name})` + (customNote ? ` - ${customNote}` : '');
      const noteTo = `تحويل من: (${fromAcc.name})` + (customNote ? ` - ${customNote}` : '');

      db.prepare(`
        INSERT INTO transactions (id, workspace_id, account_id, category_id, type, amount, date, note, is_deleted, is_favorite, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?)
      `).run(txFromId, workspace_id, from_account_id, catId, 'expense', transferAmount, transferDate, noteFrom, currentUser.id, now);

      db.prepare(`
        INSERT INTO transactions (id, workspace_id, account_id, category_id, type, amount, date, note, is_deleted, is_favorite, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?)
      `).run(txToId, workspace_id, to_account_id, catId, 'income', transferAmount, transferDate, noteTo, currentUser.id, now);

      recalcAccountBalance(from_account_id);
      recalcAccountBalance(to_account_id);

      logAudit(currentUser.id, 'تحويل بين الحسابات ↔️', `${fromAcc.name} ⬅️ ${toAcc.name} (${transferAmount} ج.م)`, customNote, workspace_id);

      return sendJSON(res, {
        success: true,
        message: `تم تحويل ${transferAmount} ج.م من (${fromAcc.name}) إلى (${toAcc.name}) بنجاح!`,
        from_account_id,
        to_account_id
      });
    }

    const accMatch = pathname.match(/^\/api\/accounts\/([^\/]+)$/);
    if (accMatch && method === 'PUT') {
      const oldAcc = db.prepare('SELECT * FROM accounts WHERE id = ?').get(accMatch[1]);
      if (!oldAcc) return sendJSON(res, { error: 'الحساب غير موجود' }, 404);

      const wsAccess = verifyWorkspaceAccess(currentUser, oldAcc.workspace_id, true);
      if (!wsAccess.allowed) return sendJSON(res, { error: wsAccess.error }, wsAccess.status);

      const { name, type, color, initial_balance } = body;
      const initBal = initial_balance !== undefined ? parseFloat(initial_balance) : oldAcc.initial_balance;
      db.prepare('UPDATE accounts SET name = ?, type = ?, color = ?, initial_balance = ? WHERE id = ?').run(
        name.trim(), type || oldAcc.type, color || oldAcc.color, initBal, accMatch[1]
      );
      recalcAccountBalance(accMatch[1]);
      return sendJSON(res, db.prepare('SELECT * FROM accounts WHERE id = ?').get(accMatch[1]));
    }
    if (accMatch && method === 'DELETE') {
      const oldAcc = db.prepare('SELECT workspace_id FROM accounts WHERE id = ?').get(accMatch[1]);
      if (!oldAcc) return sendJSON(res, { error: 'الحساب غير موجود' }, 404);

      const wsAccess = verifyWorkspaceAccess(currentUser, oldAcc.workspace_id, true);
      if (!wsAccess.allowed) return sendJSON(res, { error: wsAccess.error }, wsAccess.status);

      db.prepare('DELETE FROM accounts WHERE id = ?').run(accMatch[1]);
      return sendJSON(res, { success: true });
    }

    // Categories
    if (pathname === '/api/categories' && method === 'GET') {
      const wsAccess = verifyWorkspaceAccess(currentUser, query.workspace_id, false);
      if (!wsAccess.allowed) return sendJSON(res, { error: wsAccess.error }, wsAccess.status);

      const categories = db.prepare('SELECT * FROM categories WHERE workspace_id = ? ORDER BY sort_order ASC').all(query.workspace_id);
      return sendJSON(res, categories);
    }
    if (pathname === '/api/categories' && method === 'POST') {
      const { workspace_id, name, type, color, icon } = body;
      const wsAccess = verifyWorkspaceAccess(currentUser, workspace_id, true);
      if (!wsAccess.allowed) return sendJSON(res, { error: wsAccess.error }, wsAccess.status);

      const id = 'cat_' + Date.now();
      const maxRow = db.prepare('SELECT COALESCE(MAX(sort_order), 0) as m FROM categories WHERE workspace_id = ?').get(workspace_id);
      const maxOrder = maxRow ? maxRow.m : 0;
      db.prepare('INSERT INTO categories (id, workspace_id, name, type, color, icon, sort_order, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, 1)').run(
        id, workspace_id, name.trim(), type, color || '#0E9A73', icon || '📂', maxOrder + 1
      );
      return sendJSON(res, db.prepare('SELECT * FROM categories WHERE id = ?').get(id));
    }
    const catMatch = pathname.match(/^\/api\/categories\/([^\/]+)$/);
    if (catMatch && method === 'PUT') {
      const oldCat = db.prepare('SELECT workspace_id FROM categories WHERE id = ?').get(catMatch[1]);
      if (!oldCat) return sendJSON(res, { error: 'الفئة غير موجودة' }, 404);

      const wsAccess = verifyWorkspaceAccess(currentUser, oldCat.workspace_id, true);
      if (!wsAccess.allowed) return sendJSON(res, { error: wsAccess.error }, wsAccess.status);

      const { name, type, color, icon } = body;
      db.prepare('UPDATE categories SET name = ?, type = ?, color = ?, icon = ? WHERE id = ?').run(name.trim(), type, color, icon, catMatch[1]);
      return sendJSON(res, db.prepare('SELECT * FROM categories WHERE id = ?').get(catMatch[1]));
    }
    if (catMatch && method === 'DELETE') {
      const oldCat = db.prepare('SELECT workspace_id FROM categories WHERE id = ?').get(catMatch[1]);
      if (!oldCat) return sendJSON(res, { error: 'الفئة غير موجودة' }, 404);

      const wsAccess = verifyWorkspaceAccess(currentUser, oldCat.workspace_id, true);
      if (!wsAccess.allowed) return sendJSON(res, { error: wsAccess.error }, wsAccess.status);

      db.prepare('DELETE FROM categories WHERE id = ?').run(catMatch[1]);
      return sendJSON(res, { success: true });
    }

    // Transactions & Favorites
    if (pathname === '/api/transactions' && method === 'GET') {
      const wsAccess = verifyWorkspaceAccess(currentUser, query.workspace_id, false);
      if (!wsAccess.allowed) return sendJSON(res, { error: wsAccess.error }, wsAccess.status);

      const txs = db.prepare(`
        SELECT t.*, u.name as creator_name
        FROM transactions t
        LEFT JOIN users u ON t.created_by = u.id
        WHERE t.workspace_id = ? AND t.is_deleted = 0
        ORDER BY t.date DESC, t.created_at DESC
      `).all(query.workspace_id);

      for (const t of txs) {
        const tagRows = db.prepare('SELECT tag_id FROM transaction_tags WHERE transaction_id = ?').all(t.id);
        t.tag_ids = tagRows.map(x => x.tag_id);
      }
      return sendJSON(res, txs);
    }

    if (pathname === '/api/favorites' && method === 'GET') {
      const txs = db.prepare(`
        SELECT t.*, u.name as creator_name, c.name as category_name, c.icon as category_icon, c.color as category_color, a.name as account_name
        FROM transactions t
        JOIN workspace_members wm ON t.workspace_id = wm.workspace_id AND wm.user_id = ?
        LEFT JOIN users u ON t.created_by = u.id
        LEFT JOIN categories c ON t.category_id = c.id
        LEFT JOIN accounts a ON t.account_id = a.id
        WHERE t.is_favorite = 1 AND t.is_deleted = 0
        ORDER BY t.date DESC
      `).all(currentUser.id);
      return sendJSON(res, txs);
    }

    const txFavMatch = pathname.match(/^\/api\/transactions\/([^\/]+)\/favorite$/);
    if (txFavMatch && method === 'PUT') {
      const tx = db.prepare('SELECT * FROM transactions WHERE id = ?').get(txFavMatch[1]);
      if (!tx) return sendJSON(res, { error: 'المعاملة غير موجودة' }, 404);
      const newStatus = tx.is_favorite ? 0 : 1;
      db.prepare('UPDATE transactions SET is_favorite = ? WHERE id = ?').run(newStatus, txFavMatch[1]);
      return sendJSON(res, { id: tx.id, is_favorite: newStatus });
    }

    if (pathname === '/api/transactions' && method === 'POST') {
      const { workspace_id, account_id, category_id, type, amount, date, note, is_favorite } = body;
      const wsAccess = verifyWorkspaceAccess(currentUser, workspace_id, true);
      if (!wsAccess.allowed) return sendJSON(res, { error: wsAccess.error }, wsAccess.status);
      if (!workspace_id || !account_id || !category_id || !amount) return sendJSON(res, { error: 'يرجى استكمال الحقول' }, 400);

      const id = 'tx_' + Date.now();
      const now = new Date().toISOString();

      db.prepare(`
        INSERT INTO transactions (id, workspace_id, account_id, category_id, type, amount, date, note, is_deleted, is_favorite, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
      `).run(id, workspace_id, account_id, category_id, type, parseFloat(amount), date || now.slice(0, 10), note || '', is_favorite ? 1 : 0, currentUser.id, now);

      recalcAccountBalance(account_id);
      const actionType = type === 'income' ? 'تسجيل إيراد 💰' : 'تسجيل مصروف 💸';
      logAudit(currentUser.id, actionType, (note || type) + ` (${amount} ج.م)`, `المبلغ: ${amount} ج.م`, workspace_id);
      return sendJSON(res, db.prepare('SELECT * FROM transactions WHERE id = ?').get(id));
    }

    const txMatch = pathname.match(/^\/api\/transactions\/([^\/]+)$/);
    if (txMatch && method === 'PUT') {
      const oldTx = db.prepare('SELECT * FROM transactions WHERE id = ?').get(txMatch[1]);
      if (!oldTx) return sendJSON(res, { error: 'المعاملة غير موجودة' }, 404);

      const wsAccess = verifyWorkspaceAccess(currentUser, oldTx.workspace_id, true);
      if (!wsAccess.allowed) return sendJSON(res, { error: wsAccess.error }, wsAccess.status);

      const { account_id, category_id, type, amount, date, note, is_favorite } = body;
      db.prepare(`
        UPDATE transactions
        SET account_id = ?, category_id = ?, type = ?, amount = ?, date = ?, note = ?, is_favorite = ?
        WHERE id = ?
      `).run(account_id, category_id, type, parseFloat(amount), date, note || '', is_favorite !== undefined ? (is_favorite ? 1 : 0) : oldTx.is_favorite, txMatch[1]);

      recalcAccountBalance(oldTx.account_id);
      if (account_id !== oldTx.account_id) recalcAccountBalance(account_id);
      logAudit(currentUser.id, 'تعديل معاملة ✏️', (note || type) + ` (${amount} ج.م)`, `المبلغ: ${amount} ج.م`, oldTx.workspace_id);
      return sendJSON(res, db.prepare('SELECT * FROM transactions WHERE id = ?').get(txMatch[1]));
    }

    if (txMatch && method === 'DELETE') {
      const tx = db.prepare('SELECT * FROM transactions WHERE id = ?').get(txMatch[1]);
      if (!tx) return sendJSON(res, { error: 'المعاملة غير موجودة' }, 404);

      const wsAccess = verifyWorkspaceAccess(currentUser, tx.workspace_id, true);
      if (!wsAccess.allowed) return sendJSON(res, { error: wsAccess.error }, wsAccess.status);

      db.prepare('UPDATE transactions SET is_deleted = 1 WHERE id = ?').run(txMatch[1]);
      recalcAccountBalance(tx.account_id);
      logAudit(currentUser.id, 'حذف معاملة 🗑️', (tx.note || tx.type) + ` (${tx.amount} ج.م)`, `المبلغ: ${tx.amount} ج.م`, tx.workspace_id);
      return sendJSON(res, { success: true });
    }

    // Budgets
    if (pathname === '/api/budgets' && method === 'GET') {
      const wsAccess = verifyWorkspaceAccess(currentUser, query.workspace_id, false);
      if (!wsAccess.allowed) return sendJSON(res, { error: wsAccess.error }, wsAccess.status);

      const budgets = db.prepare('SELECT * FROM budgets WHERE workspace_id = ?').all(query.workspace_id);
      return sendJSON(res, budgets);
    }
    if (pathname === '/api/budgets' && method === 'POST') {
      const { workspace_id, name, category_id, amount, period } = body;
      const wsAccess = verifyWorkspaceAccess(currentUser, workspace_id, true);
      if (!wsAccess.allowed) return sendJSON(res, { error: wsAccess.error }, wsAccess.status);

      const id = 'b_' + Date.now();
      db.prepare('INSERT INTO budgets (id, workspace_id, name, category_id, amount, period, start_date, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, 1)').run(
        id, workspace_id, name.trim(), category_id, parseFloat(amount), period || 'monthly', new Date().toISOString().slice(0, 7) + '-01'
      );
      return sendJSON(res, db.prepare('SELECT * FROM budgets WHERE id = ?').get(id));
    }
    const budMatch = pathname.match(/^\/api\/budgets\/([^\/]+)$/);
    if (budMatch && method === 'PUT') {
      const oldBud = db.prepare('SELECT workspace_id FROM budgets WHERE id = ?').get(budMatch[1]);
      if (!oldBud) return sendJSON(res, { error: 'الميزانية غير موجودة' }, 404);

      const wsAccess = verifyWorkspaceAccess(currentUser, oldBud.workspace_id, true);
      if (!wsAccess.allowed) return sendJSON(res, { error: wsAccess.error }, wsAccess.status);

      const { name, category_id, amount } = body;
      db.prepare('UPDATE budgets SET name = ?, category_id = ?, amount = ? WHERE id = ?').run(name.trim(), category_id, parseFloat(amount), budMatch[1]);
      return sendJSON(res, db.prepare('SELECT * FROM budgets WHERE id = ?').get(budMatch[1]));
    }
    if (budMatch && method === 'DELETE') {
      const oldBud = db.prepare('SELECT workspace_id FROM budgets WHERE id = ?').get(budMatch[1]);
      if (!oldBud) return sendJSON(res, { error: 'الميزانية غير موجودة' }, 404);

      const wsAccess = verifyWorkspaceAccess(currentUser, oldBud.workspace_id, true);
      if (!wsAccess.allowed) return sendJSON(res, { error: wsAccess.error }, wsAccess.status);

      db.prepare('DELETE FROM budgets WHERE id = ?').run(budMatch[1]);
      return sendJSON(res, { success: true });
    }

    // Tags
    if (pathname === '/api/tags' && method === 'GET') {
      const wsAccess = verifyWorkspaceAccess(currentUser, query.workspace_id, false);
      if (!wsAccess.allowed) return sendJSON(res, { error: wsAccess.error }, wsAccess.status);

      const tags = db.prepare('SELECT * FROM tags WHERE workspace_id = ?').all(query.workspace_id);
      return sendJSON(res, tags);
    }
    if (pathname === '/api/tags' && method === 'POST') {
      const { workspace_id, name, color, icon } = body;
      const wsAccess = verifyWorkspaceAccess(currentUser, workspace_id, true);
      if (!wsAccess.allowed) return sendJSON(res, { error: wsAccess.error }, wsAccess.status);

      const id = 'tag_' + Date.now();
      db.prepare('INSERT INTO tags (id, workspace_id, name, color, icon) VALUES (?, ?, ?, ?, ?)').run(
        id, workspace_id, name.trim(), color || '#0E9A73', icon || '🏷️'
      );
      return sendJSON(res, db.prepare('SELECT * FROM tags WHERE id = ?').get(id));
    }
    const tagMatch = pathname.match(/^\/api\/tags\/([^\/]+)$/);
    if (tagMatch && method === 'PUT') {
      const oldTag = db.prepare('SELECT workspace_id FROM tags WHERE id = ?').get(tagMatch[1]);
      if (!oldTag) return sendJSON(res, { error: 'الوسم غير موجود' }, 404);

      const wsAccess = verifyWorkspaceAccess(currentUser, oldTag.workspace_id, true);
      if (!wsAccess.allowed) return sendJSON(res, { error: wsAccess.error }, wsAccess.status);

      const { name, color, icon } = body;
      db.prepare('UPDATE tags SET name = ?, color = ?, icon = ? WHERE id = ?').run(name.trim(), color, icon, tagMatch[1]);
      return sendJSON(res, db.prepare('SELECT * FROM tags WHERE id = ?').get(tagMatch[1]));
    }
    if (tagMatch && method === 'DELETE') {
      const oldTag = db.prepare('SELECT workspace_id FROM tags WHERE id = ?').get(tagMatch[1]);
      if (!oldTag) return sendJSON(res, { error: 'الوسم غير موجود' }, 404);

      const wsAccess = verifyWorkspaceAccess(currentUser, oldTag.workspace_id, true);
      if (!wsAccess.allowed) return sendJSON(res, { error: wsAccess.error }, wsAccess.status);

      db.prepare('DELETE FROM tags WHERE id = ?').run(tagMatch[1]);
      return sendJSON(res, { success: true });
    }

    // Admin Users Management & Full CRUD
    if (pathname === '/api/admin/users' && method === 'GET') {
      if (currentUser.global_role !== 'super_admin') return sendJSON(res, { error: 'صلاحيات سوبر أدمن فقط' }, 403);
      const users = db.prepare('SELECT id, name, email, global_role, status, avatar, created_at FROM users ORDER BY created_at DESC').all();
      return sendJSON(res, users);
    }

    if (pathname === '/api/admin/users' && method === 'POST') {
      if (currentUser.global_role !== 'super_admin') return sendJSON(res, { error: 'صلاحيات سوبر أدمن فقط' }, 403);
      const { name, email, password, global_role } = body;
      if (!name || !email || !password) return sendJSON(res, { error: 'اسم المستخدم والبريد وكلمة السر حقول مطلوبة' }, 400);

      const existing = db.prepare('SELECT id FROM users WHERE LOWER(email) = LOWER(?)').get(email.trim());
      if (existing) return sendJSON(res, { error: 'هذا البريد الإلكتروني مستخدم بالفعل' }, 400);

      const userId = 'u_' + Date.now();
      const pHash = hashPassword(password);
      const now = new Date().toISOString();
      const role = global_role || 'user';

      db.prepare('INSERT INTO users (id, name, email, password_hash, global_role, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
        userId, name.trim(), email.trim().toLowerCase(), pHash, role, 'active', now
      );

      const wsId = 'ws_' + userId + '_personal';
      const code = generateJoinCode('P');
      db.prepare('INSERT INTO workspaces (id, name, type, icon, join_code, owner_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
        wsId, 'مساحة ' + name.trim() + ' الشخصية', 'personal', '👤', code, userId, now
      );
      db.prepare('INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES (?, ?, ?, ?)').run(
        'wm_' + wsId + '_' + userId, wsId, userId, 'owner'
      );

      logAudit(currentUser.id, 'admin_create_user', name.trim(), 'رتبة: ' + role);
      return sendJSON(res, { success: true, userId });
    }

    const adminUserUpdateMatch = pathname.match(/^\/api\/admin\/users\/([^\/]+)$/);
    if (adminUserUpdateMatch && method === 'PUT') {
      if (currentUser.global_role !== 'super_admin') return sendJSON(res, { error: 'صلاحيات سوبر أدمن فقط' }, 403);
      const targetId = adminUserUpdateMatch[1];
      const { name, email, global_role, status } = body;
      if (!name || !email) return sendJSON(res, { error: 'اسم المستخدم والبريد إجباريان' }, 400);

      const existing = db.prepare('SELECT id FROM users WHERE LOWER(email) = LOWER(?) AND id != ?').get(email.trim(), targetId);
      if (existing) return sendJSON(res, { error: 'البريد الإلكتروني مستخدم لحساب آخر' }, 400);

      db.prepare('UPDATE users SET name = ?, email = ?, global_role = ?, status = ? WHERE id = ?').run(
        name.trim(), email.trim().toLowerCase(), global_role || 'user', status || 'active', targetId
      );
      logAudit(currentUser.id, 'admin_update_user', name.trim(), 'تعديل البيانات والرتبة');
      return sendJSON(res, { success: true });
    }

    if (adminUserUpdateMatch && method === 'DELETE') {
      if (currentUser.global_role !== 'super_admin') return sendJSON(res, { error: 'صلاحيات سوبر أدمن فقط' }, 403);
      const targetId = adminUserUpdateMatch[1];
      if (targetId === currentUser.id) return sendJSON(res, { error: 'لا يمكنك حذف حسابك الحالي' }, 400);

      db.prepare('DELETE FROM workspace_members WHERE user_id = ?').run(targetId);
      db.prepare('DELETE FROM invites WHERE user_id = ?').run(targetId);
      db.prepare('DELETE FROM users WHERE id = ?').run(targetId);
      logAudit(currentUser.id, 'admin_delete_user', targetId);
      return sendJSON(res, { success: true });
    }

    const adminUserPassMatch = pathname.match(/^\/api\/admin\/users\/([^\/]+)\/password$/);
    if (adminUserPassMatch && method === 'PUT') {
      if (currentUser.global_role !== 'super_admin') return sendJSON(res, { error: 'صلاحيات سوبر أدمن فقط' }, 403);
      const targetId = adminUserPassMatch[1];
      const { password } = body;
      if (!password) return sendJSON(res, { error: 'كلمة السر الجديدة مطلوبة' }, 400);

      const pHash = hashPassword(password);
      db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(pHash, targetId);
      logAudit(currentUser.id, 'admin_reset_password', targetId);
      return sendJSON(res, { success: true });
    }

    const adminUserWsMatch = pathname.match(/^\/api\/admin\/users\/([^\/]+)\/workspaces$/);
    if (adminUserWsMatch && method === 'GET') {
      if (currentUser.global_role !== 'super_admin') return sendJSON(res, { error: 'صلاحيات سوبر أدمن فقط' }, 403);
      const targetId = adminUserWsMatch[1];
      const wsList = db.prepare(`
        SELECT w.*, wm.role as my_role
        FROM workspaces w
        JOIN workspace_members wm ON w.id = wm.workspace_id
        WHERE wm.user_id = ?
      `).all(targetId);
      return sendJSON(res, wsList);
    }

    const adminUserStatusMatch = pathname.match(/^\/api\/admin\/users\/([^\/]+)\/status$/);
    if (adminUserStatusMatch && method === 'PUT') {
      if (currentUser.global_role !== 'super_admin') return sendJSON(res, { error: 'صلاحيات سوبر أدمن فقط' }, 403);
      db.prepare('UPDATE users SET status = ? WHERE id = ?').run(body.status, adminUserStatusMatch[1]);
      logAudit(currentUser.id, body.status === 'suspended' ? 'suspend_user' : 'activate_user', adminUserStatusMatch[1]);
      return sendJSON(res, { success: true });
    }

    if (pathname === '/api/admin/backup' && method === 'GET') {
      if (currentUser.global_role !== 'super_admin') return sendJSON(res, { error: 'صلاحيات سوبر أدمن فقط' }, 403);
      const dbFilePath = path.join(__dirname, 'database.sqlite');
      res.writeHead(200, {
        'Content-Type': 'application/vnd.sqlite3',
        'Content-Disposition': 'attachment; filename="database.sqlite"',
      });
      return fs.createReadStream(dbFilePath).pipe(res);
    }

    if (pathname === '/api/admin/audit-log' && method === 'GET') {
      if (currentUser.global_role !== 'super_admin') return sendJSON(res, { error: 'صلاحيات سوبر أدمن فقط' }, 403);
      const logs = db.prepare(`
        SELECT a.*, u.name as actor_name
        FROM audit_log a
        LEFT JOIN users u ON a.actor_id = u.id
        ORDER BY a.created_at DESC
      `).all();
      return sendJSON(res, logs);
    }

    // Settings
    if (pathname === '/api/settings' && method === 'GET') {
      const s = db.prepare("SELECT * FROM settings WHERE id = 'global'").get() || {};
      return sendJSON(res, s);
    }
    if (pathname === '/api/settings' && method === 'PUT') {
      const { currency, date_format, timezone, week_start, fiscal_start, theme } = body;
      db.prepare(`
        INSERT INTO settings (id, currency, date_format, timezone, week_start, fiscal_start, theme)
        VALUES ('global', ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          currency = excluded.currency,
          date_format = excluded.date_format,
          timezone = excluded.timezone,
          week_start = excluded.week_start,
          fiscal_start = excluded.fiscal_start,
          theme = excluded.theme
      `).run(currency, date_format, timezone, week_start, fiscal_start, theme);
      return sendJSON(res, { success: true });
    }

    return sendJSON(res, { error: 'المسار غير موجود' }, 404);
  }

  // Serve static files
  let filePath = path.join(__dirname, pathname === '/' ? 'index.html' : pathname);
  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      filePath = path.join(__dirname, 'index.html');
    }
    const ext = path.extname(filePath).toLowerCase();
    const mimeTypes = {
      '.html': 'text/html; charset=utf-8',
      '.js': 'application/javascript',
      '.css': 'text/css',
      '.json': 'application/json',
      '.png': 'image/png',
      '.jpg': 'image/jpeg',
      '.svg': 'image/svg+xml',
    };
    res.writeHead(200, { 'Content-Type': mimeTypes[ext] || 'text/plain' });
    fs.createReadStream(filePath).pipe(res);
  });
});

server.listen(PORT, () => {
  console.log(`==================================================`);
  console.log(`🚀 منصة محفظة تعمل بنجاح على الخادم: http://localhost:${PORT}`);
  console.log(`==================================================`);
});
