"""客户查询系统 V2.0 正式预览版 — Python 3 standard library server.
Run: python server.py, then visit http://127.0.0.1:8765
Local demo only; use HTTPS/reverse-proxy, access controls and broker approval for production.
"""
import os, io, json, sqlite3, hashlib, secrets, hmac, re, zipfile, xml.etree.ElementTree as ET, time, datetime
from pathlib import Path
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from http.cookies import SimpleCookie
from urllib.parse import urlparse, parse_qs

BASE=Path(__file__).resolve().parent
DB=os.getenv('CHANNEL_DB',str(BASE/'channel.sqlite3'))
HOST=os.getenv('HOST','127.0.0.1'); PORT=int(os.getenv('PORT','8765'))
PRODUCTION=os.getenv('APP_ENV','').lower()=='production'
HTTPS_ONLY=PRODUCTION or os.getenv('HTTPS_ONLY')=='1'
COOKIE_PROTECTION='; Secure' if HTTPS_ONLY else ''
if PRODUCTION:
 if DB!='/data/channel.sqlite3' or not (os.getenv('RAILWAY_VOLUME_MOUNT_PATH')=='/data' or (os.getenv('RENDER')=='true' and os.path.ismount('/data'))):
  raise SystemExit('安全检查：请先给云端服务挂载 /data 持久存储卷，并设置 CHANNEL_DB=/data/channel.sqlite3')

NS='{http://schemas.openxmlformats.org/spreadsheetml/2006/main}'
SESSIONS={}
LIMITS={}
import threading
LIMIT_LOCK=threading.Lock()

def allow(key, limit, window=60):
 with LIMIT_LOCK:
  now=time.monotonic()
  for k in list(LIMITS):
   if not LIMITS[k] or LIMITS[k][-1]<now-600: LIMITS.pop(k,None)
  hits=[t for t in LIMITS.get(key,[]) if t>now-window]
  if len(hits)>=limit:return False
  LIMITS[key]=hits+[now];return True

def audit(c,actor,action,detail):
 c.execute("INSERT INTO audit(at,actor,action,detail) VALUES(?,?,?,?)",(datetime.datetime.now().isoformat(),actor,action,detail))

def normalize_date(value):
 value=str(value or "").strip()
 if not value:return ""
 if re.fullmatch(r"\d+(?:\.\d+)?",value):
  try:return (datetime.datetime(1899,12,30)+datetime.timedelta(days=float(value))).isoformat(sep=" ",timespec="seconds")
  except (ValueError,OverflowError):raise ValueError("Excel 日期无效")
 value=value.replace("/","-")
 try:return datetime.datetime.fromisoformat(value).isoformat(sep=" ",timespec="seconds")
 except ValueError:
  try:return datetime.datetime.strptime(value,"%Y-%m-%d").strftime("%Y-%m-%d")
  except ValueError:raise ValueError("日期格式无效，请使用 YYYY-MM-DD 或 Excel 日期")

COLS=['ClientCode','OpenDate','ReferralCode','渠道名称','净入金','纯入金','是否FTT','第一次交易时间','手机号','更新时间']

from contextlib import contextmanager
@contextmanager
def conn():
 c=sqlite3.connect(DB);c.row_factory=sqlite3.Row;c.execute('PRAGMA journal_mode=WAL')
 try:
  with c:yield c
 finally:c.close()

def pw_hash(p,s=None):
 s=s or secrets.token_hex(16)
 return s+'$'+hashlib.pbkdf2_hmac('sha256',p.encode(),bytes.fromhex(s),240000).hex()

def check_pw(p,h):
 try:s,hh=h.split('$');return hmac.compare_digest(pw_hash(p,s),h)
 except:return False

def init():
 with conn() as c:
  c.executescript('''CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, label TEXT NOT NULL, role TEXT NOT NULL, password_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS clients(client_code TEXT PRIMARY KEY, open_date TEXT, referral_code TEXT, channel TEXT, net_deposit REAL DEFAULT 0, pure_deposit REAL DEFAULT 0, ftt TEXT, first_trade TEXT, masked_phone TEXT, last4 TEXT, updated TEXT, owner_id INTEGER, verified INTEGER NOT NULL DEFAULT 0, note TEXT DEFAULT '', FOREIGN KEY(owner_id) REFERENCES users(id));
CREATE TABLE IF NOT EXISTS imports(id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, filename TEXT, filtered INTEGER, inserted INTEGER, updated INTEGER);
CREATE TABLE IF NOT EXISTS settlements(id INTEGER PRIMARY KEY AUTOINCREMENT, month TEXT NOT NULL, at TEXT NOT NULL, actor TEXT NOT NULL, snapshot TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, actor TEXT, action TEXT, detail TEXT);''')
  c.execute('CREATE INDEX IF NOT EXISTS idx_clients_owner ON clients(owner_id)')
  c.execute('''CREATE TABLE IF NOT EXISTS registrations(id INTEGER PRIMARY KEY, submitter INTEGER NOT NULL, last4 TEXT NOT NULL, claimed_code TEXT NOT NULL DEFAULT '', created TEXT NOT NULL, status TEXT NOT NULL DEFAULT '待核对', linked_code TEXT, evidence TEXT NOT NULL DEFAULT '', reviewed_at TEXT)''')
  if not c.execute('SELECT 1 FROM users LIMIT 1').fetchone():
   if PRODUCTION and len(os.getenv('INITIAL_ADMIN_PASSWORD',''))<12:
    raise SystemExit('首次云端启动前，请在环境变量中添加 INITIAL_ADMIN_PASSWORD（至少12位）')
   for i,(u,label,role) in enumerate([('admin','管理员','admin'),('friend_a','朋友 A','partner'),('friend_b','朋友 B','partner'),('friend_c','朋友 C','partner')]):
    pwd=os.environ['INITIAL_ADMIN_PASSWORD'] if PRODUCTION and u=='admin' else secrets.token_urlsafe(18 if PRODUCTION else 10)
    c.execute('INSERT INTO users(username,label,role,password_hash) VALUES(?,?,?,?)',(u,label,role,pw_hash(pwd)))
    if not PRODUCTION: print(f'初始账号: {u}  密码: {pwd}',flush=True)
   if PRODUCTION: print('已初始化账号。管理员请用 云端环境变量设定的初始密码登录；其他伙伴密码需由管理员在账户管理中设置。',flush=True)
   else: print('请妥善保存密码；不要将这个终端输出转发给渠道朋友。',flush=True)

def read_xlsx(data):
 if len(data)>24*1024*1024:raise ValueError('上传文件超过 24 MB')
 with zipfile.ZipFile(io.BytesIO(data)) as z:
  if sum(x.file_size for x in z.infolist())>120*1024*1024:raise ValueError('文件解压后过大')
  sheet='xl/worksheets/sheet1.xml'
  if sheet not in z.namelist():raise ValueError('找不到 Excel 工作表')
  strings=[]
  if 'xl/sharedStrings.xml' in z.namelist():
   rr=ET.fromstring(z.read('xl/sharedStrings.xml'))
   strings=[''.join(t.text or '' for t in si.iter(NS+'t')) for si in rr.findall(NS+'si')]
  def values(row):
   out={}
   for cell in row.findall(NS+'c'):
    key=re.match('[A-Z]+',cell.get('r',''))
    if not key:continue
    col=key.group();v=cell.find(NS+'v');inline=cell.find(NS+'is');raw=v.text if v is not None and v.text else ''
    if cell.get('t')=='s' and raw:raw=strings[int(raw)]
    elif inline is not None:raw=''.join(t.text or '' for t in inline.iter(NS+'t'))
    out[col]=str(raw or '').strip()
   return out
  root=ET.fromstring(z.read(sheet));r=root.findall('.//'+NS+'sheetData/'+NS+'row')
  if not r:raise ValueError('Excel 无数据')
  headers=values(r[0]); reverse={v:k for k,v in headers.items()}
  missing=[col for col in COLS if col not in reverse]
  if missing:raise ValueError('Excel 缺少字段：'+','.join(missing))
  result=[]
  for row in r[1:]:
   values_row=values(row); record={k:values_row.get(reverse[k],'') for k in COLS}
   if record['ReferralCode'].strip().upper()=='YE3376' and record['ClientCode']:
    result.append(record)
  return result

def parse_month(d):return (d or '')[:7] if re.fullmatch(r'\d{4}-\d{2}.*',d or '') else ''
def price(n):return 700 if n>=30 else 600 if n>=4 else 500 if n>=1 else 0

def user_clients(c,u):
 if u['role']=='admin':return c.execute('SELECT * FROM clients WHERE UPPER(TRIM(referral_code))="YE3376" ORDER BY updated DESC,open_date DESC').fetchall()
 return c.execute('SELECT * FROM clients WHERE UPPER(TRIM(referral_code))="YE3376" AND owner_id=? ORDER BY updated DESC,open_date DESC',(u['id'],)).fetchall()

def monthly_stats(rows,month):
 rows=[r for r in rows if parse_month(r['open_date'])==month]
 verified=sum(int(r['verified'] or 0) for r in rows)
 return {'total':len(rows),'verified':verified,'pending':len(rows)-verified,'rate':price(verified),'reward':verified*price(verified)}

def public_row(r):
 return dict(client_code=r['client_code'],open_date=r['open_date'],phone='****'+r['last4'] if r['last4'] else '',last4=r['last4'],opening_status='已开户' if r['open_date'] else '待确认',verified=bool(r['verified']))

class Handler(BaseHTTPRequestHandler):
 def log_message(self,fmt,*a):pass
 def send(self,status,obj,cookie=None):
  payload=json.dumps(obj,ensure_ascii=False).encode();self.send_response(status)
  self.send_header('X-Frame-Options','DENY');self.send_header('Content-Type','application/json; charset=utf-8');self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('Content-Length',str(len(payload)))
  self.send_header('Referrer-Policy','no-referrer')
  if PRODUCTION:self.send_header('Strict-Transport-Security','max-age=31536000')
  if cookie:self.send_header('Set-Cookie',cookie)
  self.end_headers();self.wfile.write(payload)
 def body(self):
  n=int(self.headers.get('Content-Length','0'))
  if n<0 or n>25*1024*1024:raise ValueError('请求体过大')
  return self.rfile.read(n)
 def auth(self):
  ck=SimpleCookie();ck.load(self.headers.get('Cookie',''))
  sid=ck['nuan_v2_sid'].value if 'nuan_v2_sid' in ck else ''
  sess=SESSIONS.get(sid)
  if not sess:return None,None
  if sess['expires']<time.time():SESSIONS.pop(sid,None);return None,None
  with conn() as c:u=c.execute('SELECT id,username,label,role FROM users WHERE id=?',(sess['uid'],)).fetchone()
  return (dict(u),sess) if u else (None,None)
 def require(self,admin=False,mutate=False):
  u,s=self.auth()
  if not u:self.send(401,{'error':'请先登录'});return None
  if admin and u['role']!='admin':self.send(403,{'error':'没有管理员权限'});return None
  if mutate and self.headers.get('X-CSRF-Token')!=s['csrf']:self.send(403,{'error':'安全校验失败'});return None
  if not allow(('api',u['id']),120):self.send(429,{'error':'操作过于频繁，请稍后再试'});return None
  return u
 def do_GET(self):
  path=urlparse(self.path).path
  if path=='/healthz':
   return self.send(200,{'status':'ok'})
  if path=='/':
   data=(BASE/'index.html').read_bytes();self.send_response(200);self.send_header('X-Frame-Options','DENY');self.send_header('X-Content-Type-Options','nosniff');self.send_header('Referrer-Policy','no-referrer');self.send_header('Content-Security-Policy',"default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");self.send_header('Content-Type','text/html; charset=utf-8');self.send_header('Cache-Control','no-store');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data);return
  if path=='/api/me':
   u,s=self.auth();return self.send(200,{'user':u,'csrf':s['csrf'] if s else None})
  u=self.require()
  if not u:return
  params=parse_qs(urlparse(self.path).query); month=params.get('month',[datetime.date.today().strftime('%Y-%m')])[0]
  if not re.fullmatch(r'\d{4}-(0[1-9]|1[0-2])',month):return self.send(400,{'error':'月份格式无效'})
  with conn() as c:
   if path=='/api/registrations':
    rows=c.execute('SELECT r.*,u.label FROM registrations r JOIN users u ON u.id=r.submitter '+('' if u['role']=='admin' else 'WHERE r.submitter=? ' )+'ORDER BY r.id DESC LIMIT 300',() if u['role']=='admin' else (u['id'],)).fetchall()
    result=[]
    for r in rows:
     item={k:r[k] for k in ('id','last4','claimed_code','created','status','label','reviewed_at')}
     item['official_status']='官方已注册（管理员按材料核对）' if r['status']=='官方已注册' else '暂未取得官方数据'
     if r['linked_code']:
      linked=c.execute('SELECT * FROM clients WHERE client_code=? AND owner_id=? AND UPPER(TRIM(referral_code))=?',(r['linked_code'],r['submitter'],'YE3376')).fetchone()
      if linked:item['official_status']='已确认有效' if linked['verified'] else ('官方报表：已开户' if linked['open_date'] else '官方状态待确认')
     if u['role']=='admin':item['evidence']=r['evidence']
     result.append(item)
    return self.send(200,{'rows':result})
   if path=='/api/overview':
    rows=user_clients(c,u);stats=monthly_stats(rows,month)
    ret={'stats':stats,'month':month}
    if u['role']=='admin':
     part=[]
     for p in c.execute("SELECT id,label FROM users WHERE role='partner' ORDER BY id"):
      s=monthly_stats(user_clients(c,dict(id=p['id'],role='partner')),month)
      part.append({'id':p['id'],'label':p['label'],**s})
     ret['partners']=part;ret['stats']['reward']=sum(p['reward'] for p in part);ret['stats']['rate']=None;ret['invite_code']='YE3376';ret['unassigned']=c.execute('SELECT COUNT(*) FROM clients WHERE owner_id IS NULL').fetchone()[0]
     ret['settlements']=[{**dict(x),'snapshot':json.loads(x['snapshot'])} for x in c.execute('SELECT * FROM settlements WHERE month=? ORDER BY id DESC LIMIT 10',(month,))]
     ret['imports']=[dict(x) for x in c.execute('SELECT at,filename,filtered,inserted,updated FROM imports ORDER BY id DESC LIMIT 5')]
    return self.send(200,ret)
   if path=='/api/clients':
    rows=user_clients(c,u); query=params.get('q',[''])[0].strip()
    if query:
     # Masked export cannot verify a full phone; only last-four search among already assigned records.
     if params.get('type',['tail'])[0]=='code':
      if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',query):return self.send(400,{'error':'客户编号格式无效'})
      rows=[r for r in rows if r['client_code']==query]
     else:
      if not re.fullmatch(r'\d{4}',query):return self.send(400,{'error':'报表手机号已脱敏，请输入手机尾号 4 位查询'})
      rows=[r for r in rows if r['last4']==query]
    else:rows=rows[:300]
    if u['role']=='admin':
     enrich=c.execute('SELECT id,label FROM users').fetchall();names={r['id']:r['label'] for r in enrich}
     data=[{**public_row(r),'owner_id':r['owner_id'],'owner_name':names.get(r['owner_id'],'未分配'),'note':r['note']} for r in rows]
    else:data=[{k:v for k,v in public_row(r).items() if k!='client_code'} for r in rows]
    audit(c,u['username'],'query',f'results={len(rows)}')
    return self.send(200,{'rows':data,'count':len(rows),'masked_only':True})
   if path=='/api/partners' and u['role']=='admin':
    return self.send(200,{'partners':[dict(x) for x in c.execute("SELECT id,label,username FROM users WHERE role='partner'")]})
  return self.send(404,{'error':'接口不存在'})
 def do_POST(self):
  path=urlparse(self.path).path
  try:
   if path=='/api/login':
    if not allow(('login',self.client_address[0]),10,300):return self.send(429,{'error':'登录尝试过多，请 5 分钟后再试'})
    p=json.loads(self.body());username=p.get('username','');password=p.get('password','')
    if not isinstance(username,str) or not isinstance(password,str):raise ValueError('账号和密码格式无效')
    with conn() as c:r=c.execute('SELECT * FROM users WHERE username=?',(username,)).fetchone()
    if not r or not check_pw(password,r['password_hash']):time.sleep(.35);return self.send(401,{'error':'用户名或密码错误'})
    ck=SimpleCookie();ck.load(self.headers.get('Cookie',''))
    if 'nuan_v2_sid' in ck:SESSIONS.pop(ck['nuan_v2_sid'].value,None)
    for key in list(SESSIONS):
     if SESSIONS[key]['expires']<time.time():SESSIONS.pop(key,None)
    with conn() as c:audit(c,username,'login','success')
    sid=secrets.token_urlsafe(32);csrf=secrets.token_urlsafe(32);SESSIONS[sid]={'uid':r['id'],'csrf':csrf,'expires':time.time()+3600*10}
    return self.send(200,{'ok':True},f'nuan_v2_sid={sid}; HttpOnly; SameSite=Strict{COOKIE_PROTECTION}; Path=/; Max-Age=36000')
   u=self.require(admin=path in ('/api/review-registration','/api/upload','/api/assign','/api/verify','/api/change-password','/api/settlement'),mutate=True)
   if not u:return
   if path=='/api/register-client':
    p=json.loads(self.body());tail=p.get('last4','');code=p.get('client_code','')
    if not isinstance(tail,str) or not re.fullmatch(r'\d{4}',tail):raise ValueError('请输入手机尾号四位')
    if not isinstance(code,str) or (code and not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',code)):raise ValueError('客户编号格式无效')
    with conn() as c:
     c.execute('BEGIN IMMEDIATE')
     if c.execute('SELECT 1 FROM registrations WHERE submitter=? AND last4=? AND claimed_code=?',(u['id'],tail,code)).fetchone():raise ValueError('您已提交相同登记，请等待核对')
     cur=c.execute('INSERT INTO registrations(submitter,last4,claimed_code,created) VALUES(?,?,?,?)',(u['id'],tail,code,datetime.datetime.now().isoformat(timespec='seconds')))
     audit(c,u['username'],'register_client',str(cur.lastrowid))
    return self.send(200,{'ok':True})
   if path=='/api/review-registration':
    p=json.loads(self.body());rid=p.get('id');code=p.get('client_code','');note=p.get('evidence','');decision=p.get('decision','link')
    if type(rid) is not int or not isinstance(note,str) or not 5<=len(note.strip())<=500:raise ValueError('请填写 5–500 字核对依据')
    if decision not in ('link','reject','registered'):raise ValueError('审核操作无效')
    if not isinstance(code,str):raise ValueError('客户编号格式无效')
    with conn() as c:
     c.execute('BEGIN IMMEDIATE')
     r=c.execute('SELECT * FROM registrations WHERE id=?',(rid,)).fetchone()
     if not r or r['status'] not in ('待核对','官方已注册'):raise ValueError('登记不存在或已经处理')
     if decision=='link':
      client=c.execute('SELECT * FROM clients WHERE client_code=? AND UPPER(TRIM(referral_code))=?',(code,'YE3376')).fetchone()
      if not client:raise ValueError('尚无该客户的 YE3376 官方导入记录，请保留待核对')
      if client['owner_id'] not in (None,r['submitter']):raise ValueError('客户已归属其他账号，需先核实争议')
      if c.execute('SELECT 1 FROM registrations WHERE linked_code=?',(code,)).fetchone():raise ValueError('该客户已关联登记，请勿重复关联')
      c.execute('UPDATE clients SET owner_id=?,note=? WHERE client_code=?',(r['submitter'],note,code))
     c.execute('UPDATE registrations SET status=?,linked_code=?,evidence=?,reviewed_at=? WHERE id=?',('归属已确认' if decision=='link' else '官方已注册' if decision=='registered' else '未通过',code if decision=='link' else None,note,datetime.datetime.now().isoformat(timespec='seconds'),rid))
     audit(c,u['username'],'review_registration',json.dumps({'id':rid,'decision':decision,'client_code':code,'evidence':note},ensure_ascii=False))
    return self.send(200,{'ok':True})
   if path=='/api/logout':
    ck=SimpleCookie();ck.load(self.headers.get('Cookie',''));sid=ck['nuan_v2_sid'].value if 'nuan_v2_sid' in ck else '';SESSIONS.pop(sid,None)
    return self.send(200,{'ok':True},f'nuan_v2_sid=; HttpOnly; SameSite=Strict{COOKIE_PROTECTION}; Path=/; Max-Age=0')
   if path=='/api/settlement':
    p=json.loads(self.body());month=p.get('month','')
    if not isinstance(month,str) or not re.fullmatch(r'\d{4}-(0[1-9]|1[0-2])',month):raise ValueError('月份格式无效')
    with conn() as c:
     c.execute('BEGIN IMMEDIATE')
     parts=[]
     for partner in c.execute("SELECT id,label FROM users WHERE role='partner' ORDER BY id"):
      rows=user_clients(c,dict(id=partner['id'],role='partner'))
      stats=monthly_stats(rows,month)
      parts.append({'id':partner['id'],'label':partner['label'],**stats,'client_codes':[r['client_code'] for r in rows if r['verified'] and parse_month(r['open_date'])==month]})
     snapshot={'partners':parts,'total':sum(p['reward'] for p in parts),'status':'draft','rule':'500/600/700; thresholds 1/4/30; opening-month'}
     cur=c.execute('INSERT INTO settlements(month,at,actor,snapshot) VALUES(?,?,?,?)',(month,datetime.datetime.now().isoformat(timespec='seconds'),u['username'],json.dumps(snapshot,ensure_ascii=False)))
     audit(c,u['username'],'settlement_draft',str(cur.lastrowid))
    return self.send(200,{'ok':True,'snapshot':snapshot})
   if path=='/api/upload':
    from urllib.parse import unquote
    filename=unquote(self.headers.get('X-Filename','report.xlsx'))[:140]
    if not filename.lower().endswith('.xlsx'):raise ValueError('仅支持 .xlsx 文件')
    records=read_xlsx(self.body());inserted=updated=0
    with conn() as c:
     for r in records:
      code=r['ClientCode'];v=c.execute('SELECT client_code FROM clients WHERE client_code=?',(code,)).fetchone()
      ph=r['手机号'];tail=re.search(r'(\d{4})$',ph);last4=tail.group(1) if tail else '';ph='****'+last4 if last4 else ''
      r['OpenDate']=normalize_date(r['OpenDate']);r['第一次交易时间']=normalize_date(r['第一次交易时间'])
      def val(field):
       try:return float(r[field])
       except:return 0.
      if v:
       c.execute('''UPDATE clients SET open_date=?,referral_code=?,channel=?,net_deposit=?,pure_deposit=?,ftt=?,first_trade=?,masked_phone=?,last4=?,updated=? WHERE client_code=?''',(r['OpenDate'],r['ReferralCode'],r['渠道名称'],val('净入金'),val('纯入金'),r['是否FTT'],r['第一次交易时间'],ph,last4,r['更新时间'],code));updated+=1
      else:
       c.execute('''INSERT INTO clients(client_code,open_date,referral_code,channel,net_deposit,pure_deposit,ftt,first_trade,masked_phone,last4,updated) VALUES(?,?,?,?,?,?,?,?,?,?,?)''',(code,r['OpenDate'],r['ReferralCode'],r['渠道名称'],val('净入金'),val('纯入金'),r['是否FTT'],r['第一次交易时间'],ph,last4,r['更新时间']));inserted+=1
     c.execute('INSERT INTO imports(at,filename,filtered,inserted,updated) VALUES(?,?,?,?,?)',(datetime.datetime.now().isoformat(timespec='seconds'),filename,len(records),inserted,updated))
     c.execute('INSERT INTO audit(at,actor,action,detail) VALUES(?,?,?,?)',(datetime.datetime.now().isoformat(),u['username'],'upload',f'{filename} inserted={inserted} updated={updated}'))
    return self.send(200,{'ok':True,'filtered':len(records),'inserted':inserted,'updated':updated})
   if path in ('/api/assign','/api/verify'):
    p=json.loads(self.body());code=str(p.get('client_code',''))
    with conn() as c:
     if not c.execute('SELECT 1 FROM clients WHERE client_code=?',(code,)).fetchone():raise ValueError('客户不存在')
     old=dict(c.execute('SELECT owner_id,verified,note FROM clients WHERE client_code=?',(code,)).fetchone())
     if path=='/api/assign':
      owner=p.get('owner_id')
      note=str(p.get('note','')).strip()
      if len(note)<5 or len(note)>500:raise ValueError('请填写 5–500 字的归属依据，不能仅凭手机号尾号分配')
      if owner is not None and type(owner) is not int:raise ValueError('归属账号无效')
      if owner is not None:
       t=c.execute('SELECT role FROM users WHERE id=?',(owner,)).fetchone()
       if not t:raise ValueError('渠道不存在')
      c.execute('UPDATE clients SET owner_id=?,note=? WHERE client_code=?',(owner,note,code))
     else:
      if type(p.get('verified')) is not bool:raise ValueError('审核状态须为布尔值')
      c.execute('UPDATE clients SET verified=? WHERE client_code=?',(1 if p['verified'] else 0,code))
     audit(c,u['username'],'change_detail',json.dumps({'client_code':code,'before':old,'after':p},ensure_ascii=False))
     c.execute('INSERT INTO audit(at,actor,action,detail) VALUES(?,?,?,?)',(datetime.datetime.now().isoformat(),u['username'],path,code))
    return self.send(200,{'ok':True})
   if path=='/api/change-own-password':
    if not allow(('password',u['id']),5,300):return self.send(429,{'error':'操作过于频繁，请稍后重试'})
    p=json.loads(self.body());old=p.get('old_password');new=p.get('new_password');confirmation=p.get('confirm_password')
    if not all(isinstance(x,str) for x in (old,new,confirmation)):raise ValueError('密码格式无效')
    if len(new)<12 or len(new)>128:raise ValueError('新密码必须为 12–128 位')
    if new!=confirmation:raise ValueError('两次输入的新密码不一致')
    if secrets.compare_digest(old.encode('utf-8'),new.encode('utf-8')):raise ValueError('新密码不能与当前密码相同')
    with conn() as c:
     current=c.execute('SELECT password_hash FROM users WHERE id=?',(u['id'],)).fetchone()
     if not current or not check_pw(old,current['password_hash']):return self.send(400,{'error':'当前密码不正确'})
     c.execute('UPDATE users SET password_hash=? WHERE id=?',(pw_hash(new),u['id']))
     audit(c,u['username'],'self_password_change','success')
    for sid in list(SESSIONS):
     if SESSIONS.get(sid,{}).get('uid')==u['id']:SESSIONS.pop(sid,None)
    return self.send(200,{'ok':True},f'nuan_v2_sid=; HttpOnly; SameSite=Strict{COOKIE_PROTECTION}; Path=/; Max-Age=0')
   if path=='/api/change-password':
    p=json.loads(self.body());username=p.get('username');password=p.get('password','')
    if not isinstance(password,str) or len(password)<12:raise ValueError('新密码至少 12 位')
    with conn() as c:
     if not c.execute('SELECT 1 FROM users WHERE username=?',(username,)).fetchone():raise ValueError('用户不存在')
     uid=c.execute('SELECT id FROM users WHERE username=?',(username,)).fetchone()[0]
     c.execute('UPDATE users SET password_hash=? WHERE username=?',(pw_hash(password),username))
     audit(c,u['username'],'password_reset',username)
    for key in list(SESSIONS):
     if SESSIONS.get(key,{}).get('uid')==uid:SESSIONS.pop(key,None)
    return self.send(200,{'ok':True})
   return self.send(404,{'error':'接口不存在'})
  except (ValueError,zipfile.BadZipFile,ET.ParseError,KeyError,TypeError,AttributeError,IndexError,json.JSONDecodeError) as e:return self.send(400,{'error':str(e)})
  except Exception as e:print('ERROR',repr(e),flush=True);return self.send(500,{'error':'服务器处理失败'})

if __name__=='__main__':
 import argparse,getpass
 parser=argparse.ArgumentParser();parser.add_argument('--reset-password',choices=['admin','friend_a','friend_b','friend_c']);args=parser.parse_args()
 init()
 if args.reset_password:
  password=getpass.getpass('新密码（至少12位）: ')
  if len(password)<12:raise SystemExit('密码至少12位')
  with conn() as c:
   c.execute('UPDATE users SET password_hash=? WHERE username=?',(pw_hash(password),args.reset_password));audit(c,'local_operator','password_reset',args.reset_password)
  raise SystemExit('密码已更新；请重启服务，使旧登录失效。')
 print(f'打开 http://{HOST}:{PORT}',flush=True)
 try:ThreadingHTTPServer((HOST,PORT),Handler).serve_forever()
 except KeyboardInterrupt:print('\n服务已停止。')
 except OSError as e:raise SystemExit(f'无法启动：端口 {PORT} 可能被占用。请先关闭旧服务。({e})')
