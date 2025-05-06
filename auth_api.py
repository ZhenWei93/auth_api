import uuid
import re
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import os
import logging
from logging import Formatter
from logging.handlers import RotatingFileHandler
import json
from datetime import datetime

# 設置日誌格式
log_formatter = Formatter(
    '{"time": "%(asctime)s", "level": "%(levelname)s", "request_id": "%(request_id)s", "path": "%(path)s", "method": "%(method)s", "message": %(message)s}',
    datefmt="%Y-%m-%d %H:%M:%S"
)

# 設置日誌處理器（本地檔案和 stdout）
logger = logging.getLogger('auth_api')
log_level = os.getenv('LOG_LEVEL', 'DEBUG').upper()
logger.setLevel(getattr(logging, log_level, logging.DEBUG))

# 本地檔案日誌（可選，僅本地使用）
if not os.getenv('RAILWAY_ENVIRONMENT'):
    file_handler = RotatingFileHandler(
        os.path.join(os.path.abspath(os.path.dirname(__file__)), 'auth_api.log'),
        maxBytes=10_000_000,  # 10MB
        backupCount=5
    )
    file_handler.setFormatter(log_formatter)
    logger.addHandler(file_handler)

# stdout 日誌（Railway 使用）
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(log_formatter)
logger.addHandler(stream_handler)

# 建立 Flask 應用
app = Flask(__name__)

# 設定資料庫位置：從環境變數 DATABASE_URL 讀取，若無則使用 SQLite 本地資料庫
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', f'sqlite:///{os.path.join(BASE_DIR, "auth.db")}')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 初始化 SQLAlchemy
db = SQLAlchemy(app)

# 設定日誌等級為 DEBUG，可輸出詳細的除錯資訊
logging.basicConfig(level=logging.DEBUG)

# 定義身份選項
VALID_IDENTITIES = {'baby', 'child', 'teenager', 'elderly', 'pregnant', 'general'}

# 定義 User 模型（資料表），代表使用者資料
class User(db.Model):
    id = db.Column(db.String(10), primary_key=True, nullable=False)  # 身分證
    username = db.Column(db.String(80), unique=True, nullable=False)  # 使用者名稱
    password = db.Column(db.String(120), nullable=False)  # 明文密碼
    identity = db.Column(db.String(10), nullable=False)  # identity 欄位

# 定義 SearchHistory 模型（資料表），代表查詢歷史
class SearchHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # 自增主鍵，移除 autoincrement=True
    user_id = db.Column(db.String(10), db.ForeignKey('user.id'), nullable=False)  # 外鍵，關聯到 user 表
    query_text = db.Column(db.String(255), nullable=False)  # 查詢內容
    query_time = db.Column(db.DateTime, nullable=False)  # 查詢時間
    user = db.relationship('User', backref=db.backref('search_history', lazy=True))

## 建立資料表（先刪除舊表）
# with app.app_context():
    # db.drop_all()  # 刪除舊表
    # db.create_all()  # 重新創建表

# 身分證號碼驗證
def validate_id(id):
    if not id:
        return False
    pattern = r'^[A-Z][12][0-9]{8}$'
    return bool(re.match(pattern, id))

# 身份驗證
def validate_identity(identity):
    return identity in VALID_IDENTITIES

# 查詢內容驗證
def validate_query_text(query_text):
    if not query_text or len(query_text) > 255:
        return False
    return True

# 日誌上下文過濾器
class RequestContextFilter(logging.Filter):
    def filter(self, record):
        from flask import has_request_context
        if has_request_context():
            record.request_id = getattr(request, 'request_id', 'none')
            record.path = request.path
            record.method = request.method
        else:
            record.request_id = 'none'
            record.path = 'none'
            record.method = 'none'
        return True

logger.addFilter(RequestContextFilter())

# 為每個請求生成 request_id
@app.before_request
def add_request_id():
    request.request_id = str(uuid.uuid4())

# 驗證 token（簡單檢查）
def authenticate_request():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        logger.warning("Missing token")
        return None, jsonify({'error': 'Missing token'}), 401
    
    # 目前使用 dummy-token，未來可改進為 JWT 或其他認證方式
    if token != 'dummy-token':
        logger.warning(f"Invalid token: {token}")
        return None, jsonify({'error': 'Invalid token'}), 401
    
    # 從查詢參數或請求體獲取 user_id
    user_id = request.args.get('user_id')  # 優先從查詢參數獲取
    if not user_id:
        data = request.get_json(silent=True)
        user_id = data.get('user_id') if data else None
    if not user_id:
        logger.warning("Missing user_id in request")
        return None, jsonify({'error': 'Missing user_id'}), 400
    
    if not validate_id(user_id):
        logger.warning(f"Invalid user_id format: {user_id}")
        return None, jsonify({'error': 'Invalid user_id format'}), 400

    user = User.query.filter_by(id=user_id).first()
    if not user:
        logger.warning(f"User not found for user_id: {user_id}")
        return None, jsonify({'error': 'User not found'}), 404
    
    return user, None

# 使用者註冊 API：接收 POST 請求
@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        logger.debug(f"Received register request: {json.dumps({k: v for k, v in data.items() if k != 'password'})}")

        if not data or 'id' not in data or 'username' not in data or 'password' not in data or 'identity' not in data:
            logger.warning("Missing id, username, password, or identity")
            return jsonify({'error': 'Missing id, username, password, or identity'}), 400

        id = data['id']
        username = data['username']
        password = data['password']
        identity = data['identity']

        if not validate_id(id):
            logger.warning(f"Invalid id format: {id}")
            return jsonify({'error': 'Invalid id format: must be 10 characters, start with uppercase letter, second character 1 or 2, followed by 8 digits'}), 400

        if not validate_identity(identity):
            logger.warning(f"Invalid identity: {identity}")
            return jsonify({'error': f"Invalid identity: must be one of {', '.join(VALID_IDENTITIES)}"}), 400

        if User.query.filter_by(id=id).first():
            logger.warning(f"ID number already exists: {id}")
            return jsonify({'error': 'ID number already exists'}), 400
        if User.query.filter_by(username=username).first():
            logger.warning(f"Username already exists: {username}")
            return jsonify({'error': 'Username already exists'}), 400

        new_user = User(id=id, username=username, password=password, identity=identity)
        db.session.add(new_user)
        db.session.commit()

        logger.info(f"User registered successfully: id={id}, username={username}, identity={identity}")
        return jsonify({'message': 'User registered successfully', 'id': id, 'username': username, 'identity': identity}), 201
        
    except Exception as e:
        logger.error(f"Register failed: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

# 使用者登入 API：接收 POST 請求
@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        logger.debug(f"Received login request: {json.dumps({k: v for k, v in data.items() if k != 'password'})}")

        if not data or 'id' not in data or 'password' not in data:
            logger.warning("Missing id or password")
            return jsonify({'error': 'Missing id or password'}), 400

        id = data['id']
        password = data['password']

        if not validate_id(id):
            logger.warning(f"Invalid id format: {id}")
            return jsonify({'error': 'Invalid id format: must be 10 characters, start with uppercase letter, second character 1 or 2, followed by 8 digits'}), 400

        user = User.query.filter_by(id=id).first()
        if user and user.password == password:
            logger.info(f"Login successful: id={id}, username={user.username}, identity={user.identity}")
            return jsonify({
                'message': 'Login successful',
                'token': 'dummy-token',
                'id': id,
                'username': user.username,
                'identity': user.identity
            }), 200
        
        logger.warning(f"Login failed: invalid credentials for id={id}")
        return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        logger.error(f"Login failed: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# 健康檢查 API：供外部監控確認系統是否正常
@app.route('/health', methods=['GET'])
def health():
    logger.debug("Health check requested")
    return jsonify({'status': 'healthy'}), 200

# 查看所有使用者資料的 API
@app.route('/api/users', methods=['GET'])
def get_users():
    try:
        logger.debug("Fetching all users")
        users = User.query.all()
        user_list = [{
            'id': user.id,
            'username': user.username,
            'password': user.password,
            'identity': user.identity
        } for user in users]
        logger.info(f"Retrieved {len(user_list)} users")
        return jsonify(user_list), 200
    except Exception as e:
        logger.error(f"Failed to fetch users: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# 新增查詢歷史 API
@app.route('/api/search-history', methods=['POST'])
def add_search_history():
    try:
        user, error_response = authenticate_request()
        if error_response:
            return error_response

        data = request.get_json()
        if not data or 'query_text' not in data:
            logger.warning("Missing query_text")
            return jsonify({'error': 'Missing query_text'}), 400

        query_text = data['query_text']
        user_id = user.id  # 使用已認證的使用者 ID

        # 驗證查詢內容
        if not validate_query_text(query_text):
            logger.warning(f"Invalid query_text: {query_text}")
            return jsonify({'error': 'Invalid query_text: must be non-empty and less than 255 characters'}), 400

        # 儲存查詢歷史，設置 query_time 為當前時間
        query_time = datetime.utcnow().replace(second=0, microsecond=0)  # 去掉秒數和毫秒
        new_history = SearchHistory(user_id=user_id, query_text=query_text, query_time=query_time)
        db.session.add(new_history)
        db.session.commit()

        logger.info(f"Search history added for user_id={user_id}, query_text={query_text}")
        return jsonify({'message': 'Search history added successfully', 'id': new_history.id}), 201

    except Exception as e:
        logger.error(f"Add search history failed: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

# 獲取查詢歷史 API
@app.route('/api/search-history', methods=['GET'])
def get_search_history():
    try:
        user, error_response = authenticate_request()
        if error_response:
            return error_response

        user_id = request.args.get('user_id')  # 從查詢參數獲取 user_id
        if not user_id or not validate_id(user_id):
            logger.warning(f"Invalid or missing user_id: {user_id}")
            return jsonify({'error': 'Invalid or missing user_id'}), 400

        logger.debug(f"Fetching search history for user_id={user_id}")
        history = SearchHistory.query.filter_by(user_id=user_id).order_by(SearchHistory.id.desc()).all()
        history_list = [{
            'id': record.id,
            'query_text': record.query_text,
            'query_time': record.query_time.isoformat()[:16]  # 截取到分鐘，格式如 2025-05-05 17:22
        } for record in history]

        logger.info(f"Retrieved {len(history_list)} search history records for user_id={user_id}")
        return jsonify(history_list), 200

    except Exception as e:
        logger.error(f"Get search history failed: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500
    
# 主程式進入點
if __name__ == '__main__':
    with app.app_context():
        try:
            db.create_all()
            logger.info("Database initialized")
        except Exception as e:
            logger.error(f"Database init error: {str(e)}")

    port = int(os.getenv('PORT', 8080))

    from waitress import serve
    serve(app, host='0.0.0.0', port=port, threads=4)