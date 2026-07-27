const { DatabaseSync } = require('node:sqlite');
const crypto = require('node:crypto');
const path = require('path');

const dbPath = path.join(__dirname, 'database.sqlite');
const db = new DatabaseSync(dbPath);

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, storedHash) {
  if (!storedHash || !storedHash.includes(':')) return false;
  const [salt, hash] = storedHash.split(':');
  const verifyHash = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(verifyHash, 'hex'));
}

function daysAgoStr(n) {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return d.toISOString().slice(0, 10);
}

function initSchema() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      global_role TEXT NOT NULL DEFAULT 'user',
      avatar TEXT,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS workspaces (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      type TEXT NOT NULL DEFAULT 'personal',
      icon TEXT NOT NULL DEFAULT '👤',
      join_code TEXT UNIQUE,
      owner_id TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS workspace_members (
      id TEXT PRIMARY KEY,
      workspace_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'member',
      UNIQUE(workspace_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS invites (
      id TEXT PRIMARY KEY,
      workspace_id TEXT NOT NULL,
      email TEXT,
      user_id TEXT,
      role TEXT NOT NULL DEFAULT 'member',
      status TEXT NOT NULL DEFAULT 'pending',
      invited_by TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS accounts (
      id TEXT PRIMARY KEY,
      workspace_id TEXT NOT NULL,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      initial_balance REAL DEFAULT 0,
      current_balance REAL DEFAULT 0,
      color TEXT,
      is_active INTEGER DEFAULT 1,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS categories (
      id TEXT PRIMARY KEY,
      workspace_id TEXT NOT NULL,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      color TEXT,
      icon TEXT,
      sort_order INTEGER DEFAULT 0,
      is_active INTEGER DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id TEXT PRIMARY KEY,
      workspace_id TEXT NOT NULL,
      account_id TEXT NOT NULL,
      category_id TEXT NOT NULL,
      type TEXT NOT NULL,
      amount REAL NOT NULL,
      date TEXT NOT NULL,
      note TEXT,
      is_deleted INTEGER DEFAULT 0,
      is_favorite INTEGER DEFAULT 0,
      created_by TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS tags (
      id TEXT PRIMARY KEY,
      workspace_id TEXT NOT NULL,
      name TEXT NOT NULL,
      color TEXT,
      icon TEXT
    );

    CREATE TABLE IF NOT EXISTS transaction_tags (
      transaction_id TEXT NOT NULL,
      tag_id TEXT NOT NULL,
      PRIMARY KEY (transaction_id, tag_id)
    );

    CREATE TABLE IF NOT EXISTS budgets (
      id TEXT PRIMARY KEY,
      workspace_id TEXT NOT NULL,
      name TEXT NOT NULL,
      category_id TEXT NOT NULL,
      amount REAL NOT NULL,
      period TEXT NOT NULL DEFAULT 'monthly',
      start_date TEXT NOT NULL,
      is_active INTEGER DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id TEXT PRIMARY KEY,
      actor_id TEXT NOT NULL,
      action TEXT NOT NULL,
      target TEXT,
      meta TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS settings (
      id TEXT PRIMARY KEY DEFAULT 'global',
      currency TEXT DEFAULT 'EGP',
      date_format TEXT DEFAULT 'YYYY-MM-DD',
      timezone TEXT DEFAULT 'Africa/Cairo',
      week_start TEXT DEFAULT 'sat',
      fiscal_start TEXT DEFAULT '01-01',
      theme TEXT DEFAULT 'light'
    );
  `);

  // DYNAMIC SCHEMA MIGRATIONS FOR UPGRADES
  const columnMigrations = [
    { table: 'workspaces', column: 'join_code', def: 'TEXT' },
    { table: 'workspaces', column: 'currency', def: 'TEXT DEFAULT "EGP"' },
    { table: 'users', column: 'avatar', def: 'TEXT' },
    { table: 'users', column: 'username', def: 'TEXT' },
    { table: 'users', column: 'phone', def: 'TEXT' },
    { table: 'users', column: 'job_title', def: 'TEXT' },
    { table: 'users', column: 'bio', def: 'TEXT' },
    { table: 'workspace_members', column: 'status', def: 'TEXT DEFAULT "approved"' },
    { table: 'workspace_members', column: 'monthly_spending_limit', def: 'REAL DEFAULT 0' },
    { table: 'workspace_members', column: 'can_add_expenses', def: 'INTEGER DEFAULT 1' },
    { table: 'workspace_members', column: 'can_view_reports', def: 'INTEGER DEFAULT 1' },
    { table: 'workspace_members', column: 'allowed_categories', def: 'TEXT DEFAULT ""' },
  ];

  for (const m of columnMigrations) {
    try {
      db.exec(`ALTER TABLE ${m.table} ADD COLUMN ${m.column} ${m.def};`);
    } catch (e) {
      // Ignore if column exists
    }
  }

  db.exec(`
    CREATE TABLE IF NOT EXISTS fund_requests (
      id TEXT PRIMARY KEY,
      workspace_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      title TEXT NOT NULL,
      amount REAL NOT NULL,
      category_id TEXT,
      note TEXT,
      status TEXT DEFAULT 'pending',
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      type TEXT DEFAULT 'info',
      is_read INTEGER DEFAULT 0,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS recurring_bills (
      id TEXT PRIMARY KEY,
      workspace_id TEXT NOT NULL,
      title TEXT NOT NULL,
      amount REAL NOT NULL,
      due_day INTEGER NOT NULL,
      category_id TEXT,
      account_id TEXT,
      is_active INTEGER DEFAULT 1,
      last_paid_month TEXT,
      created_at TEXT NOT NULL
    );
  `);

  // MIGRATIONS FOR EXISTING DEMO DATA
  try {
    db.prepare('UPDATE users SET username = "admin" WHERE id = "u_admin" AND (username IS NULL OR username = "")').run();
    db.prepare('UPDATE users SET username = "ahmed" WHERE id = "u_ahmed" AND (username IS NULL OR username = "")').run();
    db.prepare('UPDATE users SET username = "sara" WHERE id = "u_sara" AND (username IS NULL OR username = "")').run();
    db.prepare('UPDATE users SET username = "youssef" WHERE id = "u_youssef" AND (username IS NULL OR username = "")').run();
    db.prepare('UPDATE users SET username = "omar" WHERE id = "u_omar" AND (username IS NULL OR username = "")').run();
    db.prepare('UPDATE users SET username = "mona" WHERE id = "u_mona" AND (username IS NULL OR username = "")').run();
    db.prepare('UPDATE users SET username = "khaled" WHERE id = "u_khaled" AND (username IS NULL OR username = "")').run();
    db.prepare('UPDATE users SET username = "amal" WHERE id = "u_amal" AND (username IS NULL OR username = "")').run();
    db.prepare('UPDATE workspaces SET join_code = "FAM-AHMED" WHERE id = "ws_ahmed_family"').run();
  } catch (e) {}

  seedRichData();
}

function seedRichData() {
  const row = db.prepare('SELECT COUNT(*) as count FROM users').get();
  if (row && row.count > 0) return;

  const defaultPassword = hashPassword('123456');
  const now = new Date().toISOString();

  // 1. Users (8 Demo Users!)
  const users = [
    { id: 'u_admin', name: 'مدير المنصة (السوبر أدمن)', email: 'admin@mahfaza.app', username: 'admin', phone: '01000000000', job_title: 'مدير المنصة الكامل', bio: 'مشرف على جميع مساحات المنصة وقواعد البيانات', role: 'super_admin', avatar: '' },
    { id: 'u_ahmed', name: 'أحمد محمود', email: 'ahmed@mahfaza.app', username: 'ahmed', phone: '01011112222', job_title: 'رب الأسرة (مالك المساحة)', bio: 'مسؤول المصروفات والميزانيات العائلية لعام 2026', role: 'user', avatar: '' },
    { id: 'u_sara', name: 'سارة أحمد', email: 'sara@mahfaza.app', username: 'sara', phone: '01033334444', job_title: 'أم الأسرة ومسؤولة الميزانية', bio: 'متابعة المشتريات ومستلزمات المنزل والأبناء', role: 'user', avatar: '' },
    { id: 'u_youssef', name: 'يوسف أحمد', email: 'youssef@mahfaza.app', username: 'youssef', phone: '01055556666', job_title: 'ابن - مساعدة في المشتريات', bio: 'تسجيل الفواتير الشخصية والدراسة', role: 'user', avatar: '' },
    { id: 'u_omar', name: 'عمر خالد', email: 'omar@mahfaza.app', username: 'omar', phone: '01077778888', job_title: 'عضو الأسرة', bio: 'تسجيل المصروفات اليومية', role: 'user', avatar: '' },
    { id: 'u_mona', name: 'منى السيد', email: 'mona@mahfaza.app', username: 'mona', phone: '01099990000', job_title: 'مسؤولة المالية بشركة الأمل', bio: 'متابعة المصروفات الرقمية', role: 'user', avatar: '' },
    { id: 'u_khaled', name: 'خالد محمود', email: 'khaled@mahfaza.app', username: 'khaled', phone: '01122223333', job_title: 'متابع مالي', bio: 'استعراض التقارير', role: 'user', avatar: '' },
    { id: 'u_amal', name: 'أمل إبراهيم', email: 'amal@mahfaza.app', username: 'amal', phone: '01144445555', job_title: 'مدير شركة الأمل', bio: 'إدارة الأعمال', role: 'user', avatar: '' },
  ];

  const insertUser = db.prepare('INSERT INTO users (id, name, email, username, phone, job_title, bio, password_hash, global_role, avatar, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
  for (const u of users) {
    insertUser.run(u.id, u.name, u.email, u.username, u.phone, u.job_title, u.bio, defaultPassword, u.role, u.avatar, 'active', now);
  }

  // 2. Workspaces
  const insertWs = db.prepare('INSERT INTO workspaces (id, name, type, icon, join_code, owner_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)');
  const insertMember = db.prepare('INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES (?, ?, ?, ?)');

  insertWs.run('ws_ahmed_personal', 'مساحة أحمد الشخصية', 'personal', '👤', 'AHMED-P1', 'u_ahmed', now);
  insertMember.run('wm_ahmed_p', 'ws_ahmed_personal', 'u_ahmed', 'owner');

  const familyWs = 'ws_ahmed_family';
  insertWs.run(familyWs, 'أسرة أحمد محمود العائلية', 'shared', '👨‍👩‍👧‍👦', 'FAM-AHMED', 'u_ahmed', now);
  insertMember.run('wm_fam_1', familyWs, 'u_ahmed', 'owner');
  insertMember.run('wm_fam_2', familyWs, 'u_sara', 'admin');
  insertMember.run('wm_fam_3', familyWs, 'u_youssef', 'member');
  insertMember.run('wm_fam_4', familyWs, 'u_omar', 'member');
  insertMember.run('wm_fam_5', familyWs, 'u_khaled', 'viewer');

  const bizWs = 'ws_digital_company';
  insertWs.run(bizWs, 'شركة الأمل للحلول الرقمية', 'shared', '🏢', 'BIZ-AMAL', 'u_amal', now);
  insertMember.run('wm_biz_1', bizWs, 'u_amal', 'owner');
  insertMember.run('wm_biz_2', bizWs, 'u_mona', 'admin');
  insertMember.run('wm_biz_3', bizWs, 'u_ahmed', 'admin');

  // 3. Accounts
  const insertAcc = db.prepare('INSERT INTO accounts (id, workspace_id, name, type, initial_balance, current_balance, color, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)');
  const accounts = [
    { id: 'acc_bank_ahli', ws: familyWs, name: 'حساب البنك الأهلي المصري', type: 'bank', init: 80000, color: '#0E9A73' },
    { id: 'acc_bank_misr', ws: familyWs, name: 'بنك مصر - حساب التوفير', type: 'bank', init: 160000, color: '#2C6FEE' },
    { id: 'acc_cash_box', ws: familyWs, name: 'الخزينة المنزلية (كاش)', type: 'cash', init: 15000, color: '#E3A63A' },
    { id: 'acc_vodafone', ws: familyWs, name: 'محفظة فودافون كاش', type: 'wallet', init: 8000, color: '#E1503F' },
    { id: 'acc_credit_card', ws: familyWs, name: 'بطاقة المشتريات الائتمانية', type: 'card', init: 25000, color: '#8854D0' },
  ];
  for (const a of accounts) {
    insertAcc.run(a.id, a.ws, a.name, a.type, a.init, a.init, a.color, now);
  }
  insertAcc.run('acc_biz_bank', bizWs, 'حساب التجاري وفا بنك', 'bank', 450000, 450000, '#2C6FEE', now);

  // 4. Categories
  const insertCat = db.prepare('INSERT INTO categories (id, workspace_id, name, type, color, icon, sort_order, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, 1)');
  const categories = [
    { id: 'cat_salary', ws: familyWs, name: 'الراتب الشهري الرئيسي', type: 'income', color: '#0E9A73', icon: '💼', order: 1 },
    { id: 'cat_investments', ws: familyWs, name: 'أرباح استثمارات وأسهم', type: 'income', color: '#20BF6B', icon: '📈', order: 2 },
    { id: 'cat_freelance', ws: familyWs, name: 'مشاريع عمل حر وتصميم', type: 'income', color: '#2C6FEE', icon: '💻', order: 3 },
    { id: 'cat_bonus', ws: familyWs, name: 'مكافآت وحوافز سنوية', type: 'income', color: '#8854D0', icon: '🎁', order: 4 },
    { id: 'cat_groceries', ws: familyWs, name: 'المواد الغذائية والسوبرماركت', type: 'expense', color: '#E1503F', icon: '🛒', order: 1 },
    { id: 'cat_bills', ws: familyWs, name: 'الفواتير والخدمات (كهرباء/نت/غاز)', type: 'expense', color: '#E3A63A', icon: '⚡', order: 2 },
    { id: 'cat_housing', ws: familyWs, name: 'الإيجار والصيانة المنزلية', type: 'expense', color: '#8854D0', icon: '🏠', order: 3 },
    { id: 'cat_health', ws: familyWs, name: 'الصحة والأدوية والعيادات', type: 'expense', color: '#20BF6B', icon: '💊', order: 4 },
    { id: 'cat_dining', ws: familyWs, name: 'المطاعم والكافيهات', type: 'expense', color: '#E1503F', icon: '🍔', order: 5 },
    { id: 'cat_fuel', ws: familyWs, name: 'الوقود وصيانة السيارة', type: 'expense', color: '#333333', icon: '🚗', order: 6 },
    { id: 'cat_shopping', ws: familyWs, name: 'الترفيه والملابس والتسوق', type: 'expense', color: '#2C6FEE', icon: '🛍️', order: 7 },
    { id: 'cat_education', ws: familyWs, name: 'المدارس والدروس الخصوصية', type: 'expense', color: '#E3A63A', icon: '🎓', order: 8 },
  ];
  for (const c of categories) {
    insertCat.run(c.id, c.ws, c.name, c.type, c.color, c.icon, c.order);
  }

  // 5. Tags
  const insertTag = db.prepare('INSERT INTO tags (id, workspace_id, name, color, icon) VALUES (?, ?, ?, ?, ?)');
  const tags = [
    { id: 'tag_essential', ws: familyWs, name: 'ضروري لا غنى عنه', color: '#E1503F', icon: '📌' },
    { id: 'tag_monthly', ws: familyWs, name: 'التزام شهري ثابت', color: '#2C6FEE', icon: '📅' },
    { id: 'tag_family', ws: familyWs, name: 'مصروفات عائلية', color: '#0E9A73', icon: '👨‍👩‍👧' },
    { id: 'tag_emergency', ws: familyWs, name: 'طوارئ', color: '#E3A63A', icon: '🚨' },
  ];
  for (const t of tags) {
    insertTag.run(t.id, t.ws, t.name, t.color, t.icon);
  }

  // 6. Rich 90-Day Transactions (May, June, July 2026)!
  const insertTx = db.prepare('INSERT INTO transactions (id, workspace_id, account_id, category_id, type, amount, date, note, is_deleted, is_favorite, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');

  const richTxs = [
    // --- July 2026 (Month 1) ---
    { id: 'tx_901', date: daysAgoStr(0), amt: 780, cat: 'cat_bills', acc: 'acc_vodafone', type: 'expense', note: 'سداد فاتورة إنترنت الفايبر المنزلية', fav: 1, by: 'u_ahmed' },
    { id: 'tx_902', date: daysAgoStr(1), amt: 8500, cat: 'cat_housing', acc: 'acc_bank_ahli', type: 'expense', note: 'إيجار الشقة السكنية لشهر يوليو', fav: 1, by: 'u_ahmed' },
    { id: 'tx_903', date: daysAgoStr(2), amt: 38000, cat: 'cat_salary', acc: 'acc_bank_ahli', type: 'income', note: 'الراتب الشهري الرئيسي - شهر يوليو', fav: 1, by: 'u_ahmed' },
    { id: 'tx_904', date: daysAgoStr(3), amt: 3450, cat: 'cat_groceries', acc: 'acc_cash_box', type: 'expense', note: 'مشتريات السوبرماركت واللحوم والخضار', fav: 1, by: 'u_sara' },
    { id: 'tx_905', date: daysAgoStr(4), amt: 1420, cat: 'cat_health', acc: 'acc_credit_card', type: 'expense', note: 'أدوية وفيتامينات شهرياً من صيدلية العزبي', fav: 0, by: 'u_sara' },
    { id: 'tx_906', date: daysAgoStr(5), amt: 14500, cat: 'cat_investments', acc: 'acc_bank_misr', type: 'income', note: 'أرباح وثائق صندوق الاستثمار الرابع', fav: 1, by: 'u_ahmed' },
    { id: 'tx_907', date: daysAgoStr(6), amt: 1250, cat: 'cat_dining', acc: 'acc_cash_box', type: 'expense', note: 'عشاء عائلي في مطعم بالتجمع', fav: 0, by: 'u_ahmed' },
    { id: 'tx_908', date: daysAgoStr(7), amt: 950, cat: 'cat_fuel', acc: 'acc_cash_box', type: 'expense', note: 'تموين بنزين 95 وتغيير زيت السيارة', fav: 0, by: 'u_ahmed' },
    { id: 'tx_909', date: daysAgoStr(8), amt: 5800, cat: 'cat_freelance', acc: 'acc_vodafone', type: 'income', note: 'دفعة مشروع تصميم تطبيق جوال', fav: 0, by: 'u_ahmed' },
    { id: 'tx_910', date: daysAgoStr(9), amt: 2600, cat: 'cat_shopping', acc: 'acc_credit_card', type: 'expense', note: 'ملابس وأحذية جديدة للأولاد', fav: 1, by: 'u_sara' },
    { id: 'tx_911', date: daysAgoStr(12), amt: 6000, cat: 'cat_education', acc: 'acc_bank_ahli', type: 'expense', note: 'قسط النشاط الصيفي للأبناء', fav: 0, by: 'u_ahmed' },
    { id: 'tx_912', date: daysAgoStr(15), amt: 3200, cat: 'cat_groceries', acc: 'acc_cash_box', type: 'expense', note: 'مشتريات منتصف الشهر وكارفور', fav: 0, by: 'u_sara' },
    { id: 'tx_913', date: daysAgoStr(18), amt: 1100, cat: 'cat_bills', acc: 'acc_vodafone', type: 'expense', note: 'فاتورة الكهرباء والغاز', fav: 0, by: 'u_sara' },
    { id: 'tx_914', date: daysAgoStr(22), amt: 7500, cat: 'cat_freelance', acc: 'acc_bank_misr', type: 'income', note: 'مستحقات استشارة برمجة واجهات', fav: 1, by: 'u_ahmed' },
    { id: 'tx_915', date: daysAgoStr(26), amt: 2100, cat: 'cat_health', acc: 'acc_credit_card', type: 'expense', note: 'كشف وفحوصات عيادة العيون', fav: 0, by: 'u_sara' },

    // --- June 2026 (Month 2) ---
    { id: 'tx_916', date: daysAgoStr(31), amt: 38000, cat: 'cat_salary', acc: 'acc_bank_ahli', type: 'income', note: 'الراتب الشهري الرئيسي - شهر يونيو', fav: 1, by: 'u_ahmed' },
    { id: 'tx_917', date: daysAgoStr(32), amt: 8500, cat: 'cat_housing', acc: 'acc_bank_ahli', type: 'expense', note: 'إيجار الشقة السكنية لشهر يونيو', fav: 1, by: 'u_ahmed' },
    { id: 'tx_918', date: daysAgoStr(34), amt: 4100, cat: 'cat_groceries', acc: 'acc_cash_box', type: 'expense', note: 'مشتريات غذائية كبرى أول شهر يونيو', fav: 0, by: 'u_sara' },
    { id: 'tx_919', date: daysAgoStr(37), amt: 12000, cat: 'cat_bonus', acc: 'acc_bank_misr', type: 'income', note: 'مكافأة تميز الأداء الربع سنوية', fav: 1, by: 'u_ahmed' },
    { id: 'tx_920', date: daysAgoStr(40), amt: 1850, cat: 'cat_shopping', acc: 'acc_credit_card', type: 'expense', note: 'مستلزمات منزلية وديكور', fav: 0, by: 'u_sara' },
    { id: 'tx_921', date: daysAgoStr(43), amt: 890, cat: 'cat_fuel', acc: 'acc_cash_box', type: 'expense', note: 'تموين وقود وصيانة دورية', fav: 0, by: 'u_ahmed' },
    { id: 'tx_922', date: daysAgoStr(46), amt: 1650, cat: 'cat_dining', acc: 'acc_credit_card', type: 'expense', note: 'عزومة عائلية في مطعم درة التجمع', fav: 0, by: 'u_ahmed' },
    { id: 'tx_923', date: daysAgoStr(50), amt: 3600, cat: 'cat_groceries', acc: 'acc_cash_box', type: 'expense', note: 'مشتريات منتصف يونيو وكارفور', fav: 0, by: 'u_sara' },
    { id: 'tx_924', date: daysAgoStr(54), amt: 820, cat: 'cat_bills', acc: 'acc_vodafone', type: 'expense', note: 'سداد فواتير المياه والكهرباء', fav: 0, by: 'u_sara' },
    { id: 'tx_925', date: daysAgoStr(58), amt: 6400, cat: 'cat_freelance', acc: 'acc_bank_misr', type: 'income', note: 'مشروع هوية بصرية لشركة عقارية', fav: 0, by: 'u_ahmed' },

    // --- May 2026 (Month 3) ---
    { id: 'tx_926', date: daysAgoStr(62), amt: 38000, cat: 'cat_salary', acc: 'acc_bank_ahli', type: 'income', note: 'الراتب الشهري الرئيسي - شهر مايو', fav: 1, by: 'u_ahmed' },
    { id: 'tx_927', date: daysAgoStr(63), amt: 8500, cat: 'cat_housing', acc: 'acc_bank_ahli', type: 'expense', note: 'إيجار الشقة السكنية لشهر مايو', fav: 1, by: 'u_ahmed' },
    { id: 'tx_928', date: daysAgoStr(65), amt: 3900, cat: 'cat_groceries', acc: 'acc_cash_box', type: 'expense', note: 'مشتريات أول مايو الغذائية', fav: 0, by: 'u_sara' },
    { id: 'tx_929', date: daysAgoStr(69), amt: 13500, cat: 'cat_investments', acc: 'acc_bank_misr', type: 'income', note: 'عائد شهادات بنك مصر الثلاثية', fav: 1, by: 'u_ahmed' },
    { id: 'tx_930', date: daysAgoStr(73), amt: 2400, cat: 'cat_health', acc: 'acc_credit_card', type: 'expense', note: 'علاج ومستلزمات صحية شهرية', fav: 0, by: 'u_sara' },
    { id: 'tx_931', date: daysAgoStr(78), amt: 1100, cat: 'cat_fuel', acc: 'acc_cash_box', type: 'expense', note: 'تموين بنزين وفحص تكييف السيارة', fav: 0, by: 'u_ahmed' },
    { id: 'tx_932', date: daysAgoStr(82), amt: 1400, cat: 'cat_dining', acc: 'acc_cash_box', type: 'expense', note: 'وجبة عشاء مع الأصدقاء', fav: 0, by: 'u_ahmed' },
    { id: 'tx_933', date: daysAgoStr(86), amt: 3100, cat: 'cat_groceries', acc: 'acc_cash_box', type: 'expense', note: 'مشتريات نهاية شهر مايو', fav: 0, by: 'u_sara' },
    { id: 'tx_934', date: daysAgoStr(89), amt: 900, cat: 'cat_bills', acc: 'acc_vodafone', type: 'expense', note: 'فاتورة الإنترنت المنزلي مايو', fav: 0, by: 'u_sara' },
  ];

  for (const t of richTxs) {
    insertTx.run(t.id, familyWs, t.acc, t.cat, t.type, t.amt, t.date, t.note, 0, t.fav, t.by, now);
  }

  // Recalculate account balances
  for (const a of accounts) {
    const incSum = db.prepare("SELECT COALESCE(SUM(amount), 0) as s FROM transactions WHERE account_id = ? AND type = 'income' AND is_deleted = 0").get(a.id).s;
    const expSum = db.prepare("SELECT COALESCE(SUM(amount), 0) as s FROM transactions WHERE account_id = ? AND type = 'expense' AND is_deleted = 0").get(a.id).s;
    const current = a.init + incSum - expSum;
    db.prepare('UPDATE accounts SET current_balance = ? WHERE id = ?').run(current, a.id);
  }

  // 7. Budgets
  const insertBud = db.prepare('INSERT INTO budgets (id, workspace_id, name, category_id, amount, period, start_date, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
  insertBud.run('b_101', familyWs, 'ميزانية السوبرماركت والمؤن', 'cat_groceries', 14000, 'monthly', new Date().toISOString().slice(0, 7) + '-01', 1);
  insertBud.run('b_102', familyWs, 'ميزانية الفواتير والاشتراكات', 'cat_bills', 4000, 'monthly', new Date().toISOString().slice(0, 7) + '-01', 1);
  insertBud.run('b_103', familyWs, 'ميزانية المطاعم والترفيه', 'cat_dining', 4500, 'monthly', new Date().toISOString().slice(0, 7) + '-01', 1);
  insertBud.run('b_104', familyWs, 'ميزانية الوقود والصيانة', 'cat_fuel', 3000, 'monthly', new Date().toISOString().slice(0, 7) + '-01', 1);

  // 8. Audit Log
  const insertAudit = db.prepare('INSERT INTO audit_log (id, actor_id, action, target, meta, created_at) VALUES (?, ?, ?, ?, ?, ?)');
  insertAudit.run('log_201', 'u_admin', 'login', 'مدير المنصة', 'تسجيل دخول السوبر أدمن', daysAgoStr(0));
  insertAudit.run('log_202', 'u_ahmed', 'create_workspace', 'أسرة أحمد محمود العائلية', 'كود: FAM-AHMED', daysAgoStr(90));

  // 9. Settings
  db.prepare(`INSERT INTO settings (id, currency, date_format, timezone, week_start, fiscal_start, theme)
              VALUES ('global', 'EGP', 'YYYY-MM-DD', 'Africa/Cairo', 'sat', '01-01', 'light')`).run();
}

initSchema();

module.exports = { db, hashPassword, verifyPassword };
