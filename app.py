import os
import re
import time
import uuid
import secrets
from collections import defaultdict
from datetime import datetime, timedelta

import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send, emit, join_room
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY') or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    # HTTPS 환경에서 배포할 때는 SESSION_COOKIE_SECURE=1 환경변수를 설정할 것
    SESSION_COOKIE_SECURE=os.environ.get('SESSION_COOKIE_SECURE') == '1',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)
DATABASE = 'market.db'
socketio = SocketIO(app)

REPORT_THRESHOLD = 3  # 이 횟수 이상 (서로 다른 신고자로부터) 신고되면 자동으로 차단/휴면 처리

USERNAME_RE = re.compile(r'^[A-Za-z0-9_]{3,20}$')
MIN_PASSWORD_LEN = 8
MAX_PASSWORD_LEN = 128
MAX_BIO_LEN = 500
MAX_TITLE_LEN = 100
MAX_DESCRIPTION_LEN = 2000
MAX_PRICE = 100_000_000
MAX_TRANSFER_AMOUNT = 10_000_000
MAX_REPORT_REASON_LEN = 1000
MAX_CHAT_MESSAGE_LEN = 500

LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCK_MINUTES = 5

CHAT_RATE_LIMIT_COUNT = 5
CHAT_RATE_LIMIT_WINDOW_SECONDS = 10
_message_timestamps = defaultdict(list)  # 프로세스 메모리 기반 채팅 rate limit (재시작 시 초기화됨)


def is_rate_limited(user_id):
    now = time.time()
    timestamps = _message_timestamps[user_id]
    while timestamps and now - timestamps[0] > CHAT_RATE_LIMIT_WINDOW_SECONDS:
        timestamps.pop(0)
    if len(timestamps) >= CHAT_RATE_LIMIT_COUNT:
        return True
    timestamps.append(now)
    return False


def safe_check_password(password_hash, candidate):
    try:
        return check_password_hash(password_hash, candidate)
    except (TypeError, ValueError):
        return False


# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 테이블 생성 (최초 실행 시에만) + 기존 DB 마이그레이션 + 관리자 계정 시딩
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                balance INTEGER NOT NULL DEFAULT 100000,
                role TEXT NOT NULL DEFAULT 'user',
                status TEXT NOT NULL DEFAULT 'active',
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT
            )
        """)
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active'
            )
        """)
        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                resolved INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT ''
            )
        """)
        # 1:1 채팅 메시지 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS message (
                id TEXT PRIMARY KEY,
                room TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        # 송금 내역 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transfer (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                amount INTEGER NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        db.commit()

        # 이전 버전 스키마로 이미 생성된 DB를 위한 컬럼 추가 마이그레이션
        for ddl in [
            "ALTER TABLE user ADD COLUMN balance INTEGER NOT NULL DEFAULT 100000",
            "ALTER TABLE user ADD COLUMN role TEXT NOT NULL DEFAULT 'user'",
            "ALTER TABLE user ADD COLUMN status TEXT NOT NULL DEFAULT 'active'",
            "ALTER TABLE user ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE user ADD COLUMN locked_until TEXT",
            "ALTER TABLE product ADD COLUMN status TEXT NOT NULL DEFAULT 'active'",
            "ALTER TABLE report ADD COLUMN resolved INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE report ADD COLUMN created_at TEXT NOT NULL DEFAULT ''",
        ]:
            try:
                cursor.execute(ddl)
                db.commit()
            except sqlite3.OperationalError:
                pass  # 컬럼이 이미 존재함

        # 과거에 평문으로 저장된 비밀번호를 해시로 일괄 마이그레이션
        cursor.execute("SELECT id, password FROM user")
        for row in cursor.fetchall():
            pwd = row['password']
            if not (pwd.startswith('pbkdf2:') or pwd.startswith('scrypt:')):
                cursor.execute(
                    "UPDATE user SET password = ? WHERE id = ?",
                    (generate_password_hash(pwd), row['id'])
                )
        db.commit()

        # 기본 관리자 계정 시딩 (관리자가 하나도 없을 때만)
        cursor.execute("SELECT * FROM user WHERE role = 'admin'")
        if cursor.fetchone() is None:
            cursor.execute(
                "INSERT INTO user (id, username, password, bio, balance, role, status) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), 'admin', generate_password_hash('admin1234!'), None, 0, 'admin', 'active')
            )
            db.commit()

    # DB 파일 접근 권한 최소화 (소유자만 읽기/쓰기 가능)
    try:
        os.chmod(DATABASE, 0o600)
    except OSError:
        pass

# 모든 템플릿에서 nav_user(현재 로그인한 사용자)와 csrf_token()을 사용할 수 있도록 주입
@app.context_processor
def inject_template_globals():
    nav_user = None
    if 'user_id' in session:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
        nav_user = cursor.fetchone()

    def csrf_token():
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_hex(16)
        return session['csrf_token']

    return dict(nav_user=nav_user, csrf_token=csrf_token)

# CSRF 보호: 모든 POST 요청에 대해 세션에 저장된 토큰과 폼의 토큰이 일치하는지 확인
@app.before_request
def csrf_protect():
    if request.method != 'POST' or request.path.startswith('/socket.io'):
        return
    token = session.get('csrf_token')
    form_token = request.form.get('csrf_token', '')
    if not token or not secrets.compare_digest(token, form_token):
        flash('요청이 유효하지 않습니다. 다시 시도해주세요.')
        return redirect(request.referrer or url_for('index'))

def is_admin_user():
    if 'user_id' not in session:
        return False
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT role FROM user WHERE id = ?", (session['user_id'],))
    row = cursor.fetchone()
    return bool(row and row['role'] == 'admin')

def private_room_name(user_id_a, user_id_b):
    return 'priv_' + '_'.join(sorted([user_id_a, user_id_b]))

def apply_report_threshold(db, target_id):
    """서로 다른 신고자 수가 임계치를 넘으면 대상 유저를 휴면 처리하거나 상품을 차단한다."""
    cursor = db.cursor()
    cursor.execute("SELECT COUNT(DISTINCT reporter_id) AS cnt FROM report WHERE target_id = ?", (target_id,))
    count = cursor.fetchone()['cnt']
    if count < REPORT_THRESHOLD:
        return
    cursor.execute("SELECT * FROM user WHERE id = ?", (target_id,))
    if cursor.fetchone():
        cursor.execute("UPDATE user SET status = 'suspended' WHERE id = ?", (target_id,))
        db.commit()
        return
    cursor.execute("SELECT * FROM product WHERE id = ?", (target_id,))
    if cursor.fetchone():
        cursor.execute("UPDATE product SET status = 'blocked' WHERE id = ?", (target_id,))
        db.commit()

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not USERNAME_RE.match(username):
            flash('사용자명은 영문자/숫자/밑줄(_)만 사용해 3~20자로 입력해주세요.')
            return redirect(url_for('register'))
        if not (MIN_PASSWORD_LEN <= len(password) <= MAX_PASSWORD_LEN):
            flash(f'비밀번호는 {MIN_PASSWORD_LEN}자 이상 {MAX_PASSWORD_LEN}자 이하로 입력해주세요.')
            return redirect(url_for('register'))
        db = get_db()
        cursor = db.cursor()
        # 중복 사용자 체크
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
        user_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                       (user_id, username, generate_password_hash(password)))
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()
        now = datetime.utcnow()

        if user and user['locked_until']:
            locked_until = datetime.fromisoformat(user['locked_until'])
            if now < locked_until:
                remaining = int((locked_until - now).total_seconds()) + 1
                flash(f'로그인 시도 횟수를 초과했습니다. {remaining}초 후 다시 시도해주세요.')
                return redirect(url_for('login'))

        if user and safe_check_password(user['password'], password):
            cursor.execute("UPDATE user SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user['id'],))
            db.commit()
            if user['status'] != 'active':
                flash('휴면 처리된 계정입니다. 관리자에게 문의하세요.')
                return redirect(url_for('login'))
            session.clear()  # 세션 고정(session fixation) 공격 방지
            session['user_id'] = user['id']
            session.permanent = True
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            if user:
                new_count = (user['failed_attempts'] or 0) + 1
                locked_until = None
                if new_count >= LOGIN_MAX_ATTEMPTS:
                    locked_until = (now + timedelta(minutes=LOGIN_LOCK_MINUTES)).isoformat()
                cursor.execute(
                    "UPDATE user SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                    (new_count, locked_until, user['id'])
                )
                db.commit()
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
    return render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.clear()
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보, 상품 검색/목록, 내 상품 목록 표시
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    if current_user is None:
        session.clear()
        return redirect(url_for('login'))

    query = request.args.get('q', '').strip()[:100]
    if query:
        like = f"%{query}%"
        cursor.execute(
            "SELECT * FROM product WHERE status = 'active' AND (title LIKE ? OR description LIKE ?) "
            "ORDER BY rowid DESC",
            (like, like)
        )
    else:
        cursor.execute("SELECT * FROM product WHERE status = 'active' ORDER BY rowid DESC")
    all_products = cursor.fetchall()

    # 내가 등록한 상품 (상태 무관하게 모두 보여줌)
    cursor.execute("SELECT * FROM product WHERE seller_id = ? ORDER BY rowid DESC", (session['user_id'],))
    my_products = cursor.fetchall()

    return render_template('dashboard.html', products=all_products, my_products=my_products,
                           user=current_user, query=query)

# 프로필 페이지: 소개글 및 비밀번호 업데이트
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'update_bio':
            bio = request.form.get('bio', '')[:MAX_BIO_LEN]
            cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
            db.commit()
            flash('프로필이 업데이트되었습니다.')
        elif action == 'change_password':
            current_password = request.form.get('current_password', '')
            new_password = request.form.get('new_password', '')
            confirm_password = request.form.get('confirm_password', '')
            cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
            current_user_row = cursor.fetchone()
            if not safe_check_password(current_user_row['password'], current_password):
                flash('현재 비밀번호가 일치하지 않습니다.')
            elif not (MIN_PASSWORD_LEN <= len(new_password) <= MAX_PASSWORD_LEN):
                flash(f'새 비밀번호는 {MIN_PASSWORD_LEN}자 이상 {MAX_PASSWORD_LEN}자 이하로 입력해주세요.')
            elif new_password != confirm_password:
                flash('새 비밀번호가 일치하지 않습니다.')
            else:
                cursor.execute(
                    "UPDATE user SET password = ? WHERE id = ?",
                    (generate_password_hash(new_password), session['user_id'])
                )
                db.commit()
                flash('비밀번호가 변경되었습니다.')
        return redirect(url_for('profile'))
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    return render_template('profile.html', user=current_user)

# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        price_raw = request.form.get('price', '').strip()
        if not title or not description:
            flash('제목과 설명을 입력해주세요.')
            return redirect(url_for('new_product'))
        if len(title) > MAX_TITLE_LEN or len(description) > MAX_DESCRIPTION_LEN:
            flash(f'제목은 {MAX_TITLE_LEN}자, 설명은 {MAX_DESCRIPTION_LEN}자를 넘을 수 없습니다.')
            return redirect(url_for('new_product'))
        if not price_raw.isdigit() or not (0 < int(price_raw) <= MAX_PRICE):
            flash(f'가격은 0보다 크고 {MAX_PRICE} 이하인 숫자로 입력해주세요.')
            return redirect(url_for('new_product'))
        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
            (product_id, title, description, price_raw, session['user_id'])
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')

# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    current_user_id = session.get('user_id')
    is_owner = current_user_id == product['seller_id']

    if product['status'] != 'active' and not is_owner and not is_admin_user():
        flash('삭제되었거나 차단된 상품입니다.')
        return redirect(url_for('dashboard'))

    # 판매자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller, is_owner=is_owner)

# 상품 수정 (소유자만 가능)
@app.route('/product/<product_id>/edit', methods=['GET', 'POST'])
def edit_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    if product['seller_id'] != session['user_id']:
        flash('본인이 등록한 상품만 수정할 수 있습니다.')
        return redirect(url_for('view_product', product_id=product_id))

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        price_raw = request.form.get('price', '').strip()
        if (not title or not description or len(title) > MAX_TITLE_LEN
                or len(description) > MAX_DESCRIPTION_LEN
                or not price_raw.isdigit() or not (0 < int(price_raw) <= MAX_PRICE)):
            flash('입력값을 확인해주세요.')
            return redirect(url_for('edit_product', product_id=product_id))
        cursor.execute(
            "UPDATE product SET title = ?, description = ?, price = ? WHERE id = ?",
            (title, description, price_raw, product_id)
        )
        db.commit()
        flash('상품 정보가 수정되었습니다.')
        return redirect(url_for('view_product', product_id=product_id))
    return render_template('edit_product.html', product=product)

# 상품 삭제 (소유자만 가능)
@app.route('/product/<product_id>/delete', methods=['POST'])
def delete_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    if product['seller_id'] != session['user_id']:
        flash('본인이 등록한 상품만 삭제할 수 있습니다.')
        return redirect(url_for('view_product', product_id=product_id))
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('dashboard'))

# 유저 간 송금 (민감 작업이므로 비밀번호 재인증 필요)
@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    if request.method == 'POST':
        receiver_username = request.form.get('receiver_username', '').strip()
        amount_raw = request.form.get('amount', '').strip()
        password_confirm = request.form.get('password', '')

        if not safe_check_password(current_user['password'], password_confirm):
            flash('비밀번호가 일치하지 않습니다.')
            return redirect(url_for('transfer'))
        if not amount_raw.isdigit() or not (0 < int(amount_raw) <= MAX_TRANSFER_AMOUNT):
            flash(f'송금액은 0보다 크고 {MAX_TRANSFER_AMOUNT} 이하인 숫자로 입력해주세요.')
            return redirect(url_for('transfer'))
        amount = int(amount_raw)

        cursor.execute("SELECT * FROM user WHERE username = ?", (receiver_username,))
        receiver = cursor.fetchone()
        if not receiver:
            flash('존재하지 않는 사용자입니다.')
            return redirect(url_for('transfer'))
        if receiver['id'] == current_user['id']:
            flash('본인에게는 송금할 수 없습니다.')
            return redirect(url_for('transfer'))
        if current_user['balance'] < amount:
            flash('잔액이 부족합니다.')
            return redirect(url_for('transfer'))

        cursor.execute("UPDATE user SET balance = balance - ? WHERE id = ?", (amount, current_user['id']))
        cursor.execute("UPDATE user SET balance = balance + ? WHERE id = ?", (amount, receiver['id']))
        transfer_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO transfer (id, sender_id, receiver_id, amount, created_at) VALUES (?, ?, ?, ?, ?)",
            (transfer_id, current_user['id'], receiver['id'], amount, datetime.utcnow().isoformat())
        )
        db.commit()
        flash(f"{receiver['username']}님에게 {amount}원을 송금했습니다.")
        return redirect(url_for('transfer'))

    cursor.execute(
        "SELECT t.*, su.username AS sender_name, ru.username AS receiver_name FROM transfer t "
        "JOIN user su ON t.sender_id = su.id JOIN user ru ON t.receiver_id = ru.id "
        "WHERE t.sender_id = ? OR t.receiver_id = ? ORDER BY t.created_at DESC",
        (current_user['id'], current_user['id'])
    )
    history = cursor.fetchall()
    return render_template('transfer.html', user=current_user, history=history)

# 1:1 채팅 상대 목록
@app.route('/chat')
def chat_list():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id != ? ORDER BY username", (session['user_id'],))
    users = cursor.fetchall()
    return render_template('chat_list.html', users=users)

# 1:1 채팅방
@app.route('/chat/<username>')
def chat_room(username):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
    other = cursor.fetchone()
    if not other:
        flash('사용자를 찾을 수 없습니다.')
        return redirect(url_for('chat_list'))
    if other['id'] == session['user_id']:
        flash('본인과는 채팅할 수 없습니다.')
        return redirect(url_for('chat_list'))

    room = private_room_name(session['user_id'], other['id'])
    cursor.execute(
        "SELECT m.*, u.username AS sender_name FROM message m JOIN user u ON m.sender_id = u.id "
        "WHERE m.room = ? ORDER BY m.created_at",
        (room,)
    )
    history = cursor.fetchall()
    return render_template('chat_room.html', other=other, room=room, history=history)

# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        target_id = request.form.get('target_id', '').strip()
        reason = request.form.get('reason', '').strip()
        if not target_id or not reason:
            flash('신고 대상과 사유를 입력해주세요.')
            return redirect(url_for('report'))
        if len(target_id) > 100 or len(reason) > MAX_REPORT_REASON_LEN:
            flash('입력값이 너무 깁니다.')
            return redirect(url_for('report'))

        db = get_db()
        cursor = db.cursor()

        # 신고 대상이 실제로 존재하는 유저 또는 상품인지 확인 (데이터 무결성)
        cursor.execute("SELECT 1 FROM user WHERE id = ? UNION SELECT 1 FROM product WHERE id = ?",
                       (target_id, target_id))
        if not cursor.fetchone():
            flash('존재하지 않는 신고 대상입니다.')
            return redirect(url_for('report'))

        # 동일 사용자의 동일 대상 반복 신고 방지 (신고 남용 방지)
        cursor.execute(
            "SELECT 1 FROM report WHERE reporter_id = ? AND target_id = ?",
            (session['user_id'], target_id)
        )
        if cursor.fetchone():
            flash('이미 신고한 대상입니다.')
            return redirect(url_for('report'))

        report_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason, created_at) VALUES (?, ?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, reason, datetime.utcnow().isoformat())
        )
        db.commit()
        apply_report_threshold(db, target_id)
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('report.html')

# 관리자 대시보드
@app.route('/admin')
def admin_dashboard():
    if not is_admin_user():
        flash('관리자만 접근할 수 있습니다.')
        return redirect(url_for('dashboard'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user ORDER BY rowid")
    users = cursor.fetchall()
    cursor.execute("SELECT * FROM product ORDER BY rowid DESC")
    products = cursor.fetchall()
    cursor.execute(
        "SELECT r.*, "
        "(SELECT username FROM user WHERE id = r.reporter_id) AS reporter_name "
        "FROM report r ORDER BY r.rowid DESC"
    )
    reports = cursor.fetchall()
    return render_template('admin_dashboard.html', users=users, products=products, reports=reports)

# 관리자: 유저 활성/휴면 상태 토글
@app.route('/admin/user/<user_id>/status', methods=['POST'])
def admin_toggle_user_status(user_id):
    if not is_admin_user():
        flash('관리자만 접근할 수 있습니다.')
        return redirect(url_for('dashboard'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
    target = cursor.fetchone()
    if not target:
        flash('사용자를 찾을 수 없습니다.')
        return redirect(url_for('admin_dashboard'))
    new_status = 'suspended' if target['status'] == 'active' else 'active'
    cursor.execute(
        "UPDATE user SET status = ?, failed_attempts = 0, locked_until = NULL WHERE id = ?",
        (new_status, user_id)
    )
    db.commit()
    flash(f"{target['username']}님의 상태를 {new_status}(으)로 변경했습니다.")
    return redirect(url_for('admin_dashboard'))

# 관리자: 상품 강제 삭제
@app.route('/admin/product/<product_id>/delete', methods=['POST'])
def admin_delete_product(product_id):
    if not is_admin_user():
        flash('관리자만 접근할 수 있습니다.')
        return redirect(url_for('dashboard'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash('상품을 삭제했습니다.')
    return redirect(url_for('admin_dashboard'))

# 관리자: 신고 처리 완료 표시
@app.route('/admin/report/<report_id>/resolve', methods=['POST'])
def admin_resolve_report(report_id):
    if not is_admin_user():
        flash('관리자만 접근할 수 있습니다.')
        return redirect(url_for('dashboard'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE report SET resolved = 1 WHERE id = ?", (report_id,))
    db.commit()
    flash('신고를 처리 완료로 표시했습니다.')
    return redirect(url_for('admin_dashboard'))

# 소켓 연결 시 로그인 여부 확인 (미인증 연결 거부)
@socketio.on('connect')
def handle_connect():
    if 'user_id' not in session:
        return False

# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트 (서버 세션에서 발신자 확인)
@socketio.on('send_message')
def handle_send_message_event(data):
    if 'user_id' not in session:
        return
    if is_rate_limited(session['user_id']):
        return
    message = (data.get('message') or '').strip()[:MAX_CHAT_MESSAGE_LEN]
    if not message:
        return
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT username FROM user WHERE id = ?", (session['user_id'],))
    sender = cursor.fetchone()
    if not sender:
        return
    send({
        'message_id': str(uuid.uuid4()),
        'username': sender['username'],
        'message': message
    }, broadcast=True)

# 1:1 채팅방 입장: 본인이 참여자인 방만 join 허용
@socketio.on('join_private_room')
def handle_join_private_room(data):
    if 'user_id' not in session:
        return
    room = data.get('room', '')
    if not room.startswith('priv_'):
        return
    participant_ids = room[len('priv_'):].split('_')
    if session['user_id'] not in participant_ids:
        return
    join_room(room)

# 1:1 채팅 메시지 전송: DB에 저장 후 해당 방에만 전달
@socketio.on('send_private_message')
def handle_send_private_message(data):
    if 'user_id' not in session:
        return
    if is_rate_limited(session['user_id']):
        return
    room = data.get('room', '')
    message = (data.get('message') or '').strip()[:MAX_CHAT_MESSAGE_LEN]
    if not room.startswith('priv_') or not message:
        return
    participant_ids = room[len('priv_'):].split('_')
    if session['user_id'] not in participant_ids:
        return

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT username FROM user WHERE id = ?", (session['user_id'],))
    sender = cursor.fetchone()
    message_id = str(uuid.uuid4())
    created_at = datetime.utcnow().isoformat()
    cursor.execute(
        "INSERT INTO message (id, room, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?)",
        (message_id, room, session['user_id'], message, created_at)
    )
    db.commit()
    emit('private_message', {
        'message_id': message_id,
        'username': sender['username'],
        'message': message,
        'created_at': created_at
    }, room=room)

# 보안 헤더 설정 (Clickjacking/MIME sniffing/외부 리소스 로드 방지)
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://cdnjs.cloudflare.com 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self' ws: wss:; "
        "frame-ancestors 'none'; "
        "object-src 'none'"
    )
    return response

# 오류 처리: 내부 정보(스택 트레이스 등)를 노출하지 않고 일반 메시지만 표시
@app.errorhandler(404)
def handle_not_found(e):
    return render_template('error.html', message='페이지를 찾을 수 없습니다.'), 404

@app.errorhandler(500)
def handle_server_error(e):
    return render_template('error.html', message='서버에서 오류가 발생했습니다. 잠시 후 다시 시도해주세요.'), 500

if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    debug_mode = os.environ.get('FLASK_DEBUG') == '1'
    # 개발용 Werkzeug 서버 사용 경고 확인. 운영 배포 시에는 gunicorn/eventlet 등
    # 프로덕션급 WSGI 서버 뒤에서 HTTPS로 서비스할 것.
    socketio.run(app, debug=debug_mode, allow_unsafe_werkzeug=True)
