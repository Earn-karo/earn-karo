require('dotenv').config();
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const dataDir = path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, 'earn-bro.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 email TEXT NOT NULL UNIQUE COLLATE NOCASE,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'player' CHECK(role IN ('player','admin')),
 balance_paise INTEGER NOT NULL DEFAULT 0 CHECK(balance_paise >= 0),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS activities (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL REFERENCES users(id),
 kind TEXT NOT NULL,
 title TEXT NOT NULL,
 points INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(user_id, kind, title)
);
CREATE TABLE IF NOT EXISTS payment_orders (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL REFERENCES users(id),
 razorpay_order_id TEXT NOT NULL UNIQUE,
 amount_paise INTEGER NOT NULL,
 status TEXT NOT NULL DEFAULT 'created',
 razorpay_payment_id TEXT UNIQUE,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 paid_at TEXT
);
CREATE TABLE IF NOT EXISTS withdrawal_requests (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL REFERENCES users(id),
 amount_paise INTEGER NOT NULL,
 upi_id TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS webhook_events (
 event_id TEXT PRIMARY KEY,
 event_type TEXT NOT NULL,
 received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);
const userColumns = db.prepare("PRAGMA table_info(users)").all();

if (!userColumns.some(col => col.name === 'mobile')) {
  db.exec("ALTER TABLE users ADD COLUMN mobile TEXT");
}

db.exec(`
  CREATE UNIQUE INDEX IF NOT EXISTS users_mobile_unique
  ON users(mobile)
  WHERE mobile IS NOT NULL AND mobile != '';
`);
if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
  const email = process.env.ADMIN_EMAIL.trim().toLowerCase();
  const existing = db.prepare("SELECT id FROM users WHERE role='admin' LIMIT 1").get();
  if (!existing) {
    const hash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);
    db.prepare("INSERT OR IGNORE INTO users(name,email,password_hash,role) VALUES(?,?,?,'admin')")
      .run('Earn Bro Admin', email, hash);
    console.log('Initial admin created from environment settings.');
  }
}

const razorpayReady = !!(process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET &&
 !process.env.RAZORPAY_KEY_ID.includes('replace') && !process.env.RAZORPAY_KEY_SECRET.includes('replace'));
const razorpay = razorpayReady ? new Razorpay({ key_id: process.env.RAZORPAY_KEY_ID, key_secret: process.env.RAZORPAY_KEY_SECRET }) : null;

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use((req,res,next) => {
  if (process.env.NODE_ENV === 'production' && req.headers['x-forwarded-proto'] !== 'https') {
    return res.status(400).send('HTTPS is required in production.');
  }
  next();
});
app.use(express.json({ limit: '20kb', verify: (req,res,buf) => { req.rawBody = Buffer.from(buf); } }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(session({
  name: 'earnbro.sid',
  secret: process.env.SESSION_SECRET || 'development-only-change-this-secret-before-launch',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 1000*60*60*24*7 }
}));
const authLimiter = rateLimit({ windowMs: 15*60*1000, limit: 20, standardHeaders: true, legacyHeaders: false });
app.use('/api/auth', authLimiter);
app.use(express.static(path.join(__dirname, 'public')));

function requireAuth(req,res,next){ if(!req.session.userId) return res.status(401).json({error:'Please log in.'}); next(); }
function requireAdmin(req,res,next){ const user=db.prepare('SELECT role FROM users WHERE id=?').get(req.session.userId); if(!user || user.role!=='admin') return res.status(403).json({error:'Admin access required.'}); next(); }
function getUser(id){return db.prepare('SELECT id,name,email,role,balance_paise,created_at FROM users WHERE id=?').get(id);}
function csrfGuard(req,res,next){
  // SameSite cookies + JSON-only API help mitigate CSRF. For production, add a synchronizer CSRF token
  // for any cookie-authenticated state-changing endpoints and configure trusted origins.
  const origin=req.get('origin');
  const base=process.env.APP_BASE_URL;
  if(origin && base && !origin.startsWith(base)) return res.status(403).json({error:'Origin not allowed.'});
  next();
}
app.use('/api', csrfGuard);

app.get('/api/health',(req,res)=>res.json({ok:true,paymentsConfigured:razorpayReady}));
app.post('/api/auth/signup', async (req,res)=>{
  const name = String(req.body.name || '').trim().slice(0,50);
  const mobile = String(req.body.mobile || '').trim();
  const password = String(req.body.password || '');

  if (name.length < 2 || !/^[6-9]\d{9}$/.test(mobile) || password.length < 10) {
    return res.status(400).json({
      error: 'Name, valid 10-digit mobile number, and password of at least 10 characters are required.'
    });
  }

  try {
    const existing = db.prepare('SELECT id FROM users WHERE mobile = ?').get(mobile);
    if (existing) {
      return res.status(409).json({error:'This mobile number is already registered.'});
    }

    const hash = await bcrypt.hash(password, 12);
    const email = `${mobile}@mobile.earnbro.local`;

    const info = db.prepare(
      'INSERT INTO users(name,email,password_hash,mobile) VALUES(?,?,?,?)'
    ).run(name, email, hash, mobile);

    req.session.regenerate(err=>{
      if (err) return res.status(500).json({error:'Could not create session.'});
      req.session.userId = Number(info.lastInsertRowid);
      res.json({user:getUser(req.session.userId)});
    });
  } catch(e) {
    if (String(e.code) === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({error:'This mobile number is already registered.'});
    }
    res.status(500).json({error:'Could not create account.'});
  }
});
app.post('/api/auth/login', async (req,res)=>{
  const identifier = String(req.body.mobile || req.body.email || '').trim();
  const password = String(req.body.password || '');

  const user = db.prepare(
    'SELECT * FROM users WHERE mobile = ? OR email = ?'
  ).get(identifier, identifier.toLowerCase());

  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({
      error: 'Mobile number or password is incorrect.'
    });
  }

  req.session.regenerate(err=>{
    if (err) {
      return res.status(500).json({error:'Could not start session.'});
    }

    req.session.userId = user.id;
    res.json({user:getUser(user.id)});
  });
});
app.post('/api/auth/logout',requireAuth,(req,res)=>req.session.destroy(()=>{res.clearCookie('earnbro.sid');res.json({ok:true});}));
app.get('/api/me',requireAuth,(req,res)=>res.json({user:getUser(req.session.userId)}));

const games=[
 {id:'ludo',name:'Ludo King',icon:'🎲',description:'Classic ludo fun',points:5},
 {id:'carrom',name:'Carrom',icon:'🎯',description:'Aim, flick and score',points:8},
 {id:'bubble',name:'Bubble Shooter',icon:'🫧',description:'Pop colorful bubbles',points:4},
 {id:'fruit',name:'Fruit Slice',icon:'🍉',description:'Slice the fruit',points:3},
 {id:'pool',name:'8 Ball Pool',icon:'🎱',description:'Practice your shots',points:6},
 {id:'puzzle',name:'Brain Puzzle',icon:'🧩',description:'Train your brain',points:5}
];
const tasks=[
 {id:'daily',name:'Daily check-in',description:'Open your rewards dashboard',points:2},
 {id:'play',name:'Play a game',description:'Launch any game once',points:3},
 {id:'newgame',name:'Try a new game',description:'Launch a different game',points:4},
 {id:'profile',name:'Complete your profile',description:'Keep your account details ready',points:2}
];
app.get('/api/catalog',requireAuth,(req,res)=>{
 const done=db.prepare('SELECT kind,title FROM activities WHERE user_id=?').all(req.session.userId);
 res.json({games,tasks,done,balance_paise:getUser(req.session.userId).balance_paise});
});
app.post('/api/activities',requireAuth,(req,res)=>{
 const {kind,title}=req.body;
 if(!['game','task'].includes(kind)) return res.status(400).json({error:'Invalid activity type.'});
 const item=(kind==='game'?games:tasks).find(x=>x.name===title);
 if(!item) return res.status(400).json({error:'Unknown activity.'});
 try{
  const add=db.transaction(()=>{
   db.prepare('INSERT INTO activities(user_id,kind,title,points) VALUES(?,?,?,?)').run(req.session.userId,kind,item.name,item.points);
   db.prepare('UPDATE users SET balance_paise=balance_paise+? WHERE id=?').run(item.points*100,req.session.userId);
  });
  add();
  res.json({user:getUser(req.session.userId),points:item.points});
 }catch(e){if(String(e.code).startsWith('SQLITE_CONSTRAINT'))return res.status(409).json({error:'This activity has already been claimed.'});res.status(500).json({error:'Could not save activity.'});}
});
app.get('/api/history',requireAuth,(req,res)=>{
 const uid=req.session.userId;
 res.json({
  activities:db.prepare('SELECT kind,title,points,created_at FROM activities WHERE user_id=? ORDER BY id DESC LIMIT 100').all(uid),
  payments:db.prepare('SELECT razorpay_order_id,amount_paise,status,razorpay_payment_id,created_at,paid_at FROM payment_orders WHERE user_id=? ORDER BY id DESC LIMIT 100').all(uid),
  withdrawals:db.prepare('SELECT id,amount_paise,upi_id,status,created_at FROM withdrawal_requests WHERE user_id=? ORDER BY id DESC LIMIT 100').all(uid)
 });
});
app.post('/api/payments/order',requireAuth,async(req,res)=>{
 if(!razorpay) return res.status(503).json({error:'Payment gateway is not configured. Add Razorpay test keys to .env.'});
 const amount=Number(req.body.amount);
 if(!Number.isInteger(amount)||amount<100||amount>1000000) return res.status(400).json({error:'Enter an amount between ₹1 and ₹10,000.'});
 try{
  const order=await razorpay.orders.create({amount:amount*100,currency:'INR',receipt:'eb_'+crypto.randomBytes(8).toString('hex'),notes:{user_id:String(req.session.userId)}});
  db.prepare('INSERT INTO payment_orders(user_id,razorpay_order_id,amount_paise,status) VALUES(?,?,?,?)').run(req.session.userId,order.id,order.amount,'created');
  res.json({keyId:process.env.RAZORPAY_KEY_ID,orderId:order.id,amount:order.amount,currency:order.currency});
 }catch(e){console.error('Razorpay order creation failed:',e.message);res.status(502).json({error:'Could not start payment. Try again later.'});}
});
app.post('/api/payments/verify',requireAuth,(req,res)=>{
 const orderId=String(req.body.razorpay_order_id||''), paymentId=String(req.body.razorpay_payment_id||''), signature=String(req.body.razorpay_signature||'');
 const order=db.prepare('SELECT * FROM payment_orders WHERE razorpay_order_id=? AND user_id=?').get(orderId,req.session.userId);
 if(!order) return res.status(400).json({error:'Order not found for this account.'});
 if(order.status==='paid') return res.json({ok:true,user:getUser(req.session.userId)});
 const expected=crypto.createHmac('sha256',process.env.RAZORPAY_KEY_SECRET||'').update(orderId+'|'+paymentId).digest('hex');
 const a=Buffer.from(expected),b=Buffer.from(signature);
 if(a.length!==b.length || !crypto.timingSafeEqual(a,b)) return res.status(400).json({error:'Payment signature verification failed.'});
 try{
  db.transaction(()=>{
   db.prepare("UPDATE payment_orders SET status='paid',razorpay_payment_id=?,paid_at=CURRENT_TIMESTAMP WHERE razorpay_order_id=? AND status='created'").run(paymentId,orderId);
   // Payment adds to the user's wallet only after server-side signature verification.
   db.prepare('UPDATE users SET balance_paise=balance_paise+? WHERE id=?').run(order.amount_paise,req.session.userId);
  })();
  res.json({ok:true,user:getUser(req.session.userId)});
 }catch(e){res.status(500).json({error:'Could not record payment. Contact support with your order ID.'});}
});
app.post('/api/payments/webhook',(req,res)=>{
 const secret=process.env.RAZORPAY_WEBHOOK_SECRET||'';
 const signature=String(req.get('x-razorpay-signature')||'');
 if(!secret || !req.rawBody) return res.status(400).send('Webhook not configured.');
 const expected=crypto.createHmac('sha256',secret).update(req.rawBody).digest('hex');
 const a=Buffer.from(expected),b=Buffer.from(signature);
 if(a.length!==b.length || !crypto.timingSafeEqual(a,b)) return res.status(400).send('Invalid signature.');
 const eventId=String(req.get('x-razorpay-event-id')||'');
 const event=req.body?.event||'unknown';
 try{
  db.prepare('INSERT INTO webhook_events(event_id,event_type) VALUES(?,?)').run(eventId||crypto.randomUUID(),event);
 }catch(e){if(String(e.code).startsWith('SQLITE_CONSTRAINT'))return res.json({ok:true,duplicate:true});throw e;}
 if(event==='payment.captured'){
  const payment=req.body.payload?.payment?.entity;
  if(payment?.order_id && payment?.id){
   const order=db.prepare("SELECT * FROM payment_orders WHERE razorpay_order_id=? AND status='created'").get(payment.order_id);
   if(order && order.amount_paise===payment.amount){
    db.transaction(()=>{
     db.prepare("UPDATE payment_orders SET status='paid',razorpay_payment_id=?,paid_at=CURRENT_TIMESTAMP WHERE id=?").run(payment.id,order.id);
     db.prepare('UPDATE users SET balance_paise=balance_paise+? WHERE id=?').run(order.amount_paise,order.user_id);
    })();
   }
  }
 }
 res.json({ok:true});
});
app.post('/api/withdrawals',requireAuth,(req,res)=>{
 const amount=Number(req.body.amount), upiId=String(req.body.upiId||'').trim();
 if(!Number.isInteger(amount)||amount<100||amount>10000000) return res.status(400).json({error:'Minimum withdrawal is ₹1 in this starter. Configure your real limits before launch.'});
 if(!/^[\w.\-]{2,256}@[a-zA-Z]{2,64}$/.test(upiId)) return res.status(400).json({error:'Enter a valid-looking UPI ID.'});
 const user=getUser(req.session.userId);
 if(user.balance_paise<amount) return res.status(400).json({error:'Insufficient wallet balance.'});
 // IMPORTANT: requests are only recorded. No payout API is called.
 const tx=db.transaction(()=>{
  db.prepare('UPDATE users SET balance_paise=balance_paise-? WHERE id=?').run(amount,req.session.userId);
  return db.prepare("INSERT INTO withdrawal_requests(user_id,amount_paise,upi_id,status) VALUES(?,?,?,'pending_review')").run(req.session.userId,amount,upiId);
 });
 const info=tx();
 res.json({ok:true,requestId:Number(info.lastInsertRowid),user:getUser(req.session.userId),message:'Withdrawal request queued for admin review; no money has been sent.'});
});
app.get('/api/admin/overview',requireAuth,requireAdmin,(req,res)=>{
 res.json({
  users:db.prepare('SELECT id,name,email,role,balance_paise,created_at FROM users ORDER BY id DESC LIMIT 500').all(),
  withdrawals:db.prepare(`SELECT w.id,w.amount_paise,w.upi_id,w.status,w.created_at,u.email FROM withdrawal_requests w JOIN users u ON u.id=w.user_id ORDER BY w.id DESC LIMIT 500`).all(),
  totals:db.prepare(`SELECT (SELECT COUNT(*) FROM users) users,(SELECT COUNT(*) FROM payment_orders WHERE status='paid') paid_orders,(SELECT COUNT(*) FROM withdrawal_requests WHERE status='pending_review') pending_withdrawals`).get()
 });
});
app.post('/api/admin/withdrawals/:id/review',requireAuth,requireAdmin,(req,res)=>{
 const status=String(req.body.status||'');
 if(!['approved_for_manual_payout','rejected'].includes(status)) return res.status(400).json({error:'Invalid status.'});
 const info=db.prepare("UPDATE withdrawal_requests SET status=? WHERE id=? AND status='pending_review'").run(status,Number(req.params.id));
 if(!info.changes) return res.status(404).json({error:'Pending request not found.'});
 res.json({ok:true});
});
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'index.html')));
app.listen(PORT,()=>console.log(`Earn Bro listening on port ${PORT}`));
