import uuid
import re
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import os
import logging
from logging import Formatter
from logging.handlers import RotatingFileHandler
import json

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
# VALID_IDENTITIES = {'幼兒', '孩童', '青少年', '年長者', '孕婦', '一般成人'}
VALID_IDENTITIES = {'baby', 'child', 'teenager', 'elderly', 'pregnant', 'general'}

# 定義 User 模型（資料表），代表使用者資料
class User(db.Model):
    id = db.Column(db.String(10), primary_key=True, nullable=False)  # 身分證
    age = db.Column(db.Integer, nullable=False)  # 年齡
    username = db.Column(db.String(80), unique=True, nullable=False)  # 使用者名稱
    password = db.Column(db.String(120), nullable=False)  # 明文密碼
    identity = db.Column(db.String(10), nullable=False)  # 新增 identity 欄位

# 建立資料表
with app.app_context():
    db.create_all()

# 身分證號碼驗證
def validate_id(id):
    if not id:
        return False
    # 檢查格式：第一碼大寫字母，第二碼1或2，其餘8碼數字
    pattern = r'^[A-Z][12][0-9]{8}$'
    return bool(re.match(pattern, id))

# 年齡驗證
def validate_age(age):
    try:
        age = int(age)
        return 0 <= age <= 150  # 合理年齡範圍
    except (ValueError, TypeError):
        return False

# 身份驗證
def validate_identity(identity):
    return identity in VALID_IDENTITIES

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

# 使用者註冊 API：接收 POST 請求
@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        logger.debug(f"Received register request: {json.dumps({k: v for k, v in data.items() if k != 'password'})}")

        # 檢查必要欄位
        if not data or 'id' not in data or 'username' not in data or 'password' not in data or 'age' not in data or 'identity' not in data:
            logger.warning("Missing id, username, password, or age, or identity")
            return jsonify({'error': 'Missing id, username, password, age, or identity '}), 400

        id = data['id']
        username = data['username']
        password = data['password']
        age = data['age']
        identity = data['identity']

        # 驗證身分證號碼
        if not validate_id(id):
            logger.warning(f"Invalid id format: {id}")
            return jsonify({'error': 'Invalid id format: must be 10 characters, start with uppercase letter, second character 1 or 2, followed by 8 digits'}), 400

        # 驗證年齡
        if not validate_age(age):
            logger.warning(f"Invalid age: {age}")
            return jsonify({'error': 'Invalid age: must be a number between 0 and 150'}), 400

        # 驗證身份
        if not validate_identity(identity):
            logger.warning(f"Invalid identity: {identity}")
            return jsonify({'error': f"Invalid identity: must be one of {', '.join(VALID_IDENTITIES)}"}), 400

        # 檢查身分證號碼或使用者名稱是否已存在
        if User.query.filter_by(id=id).first():
            logger.warning(f"ID number already exists: {id}")
            return jsonify({'error': 'ID number already exists'}), 400
        if User.query.filter_by(username=username).first():
            logger.warning(f"Username already exists: {username}")
            return jsonify({'error': 'Username already exists'}), 400

        # 儲存使用者資料（包括身份）
        new_user = User(id=id, age=int(age), username=username, password=password, identity=identity)
        db.session.add(new_user)
        db.session.commit()

        logger.info(f"User registered successfully: id={id}, username={username}, age={age}, identity={identity}")
        return jsonify({'message': 'User registered successfully', 'id': id, 'identity': identity}), 201
        
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

        # 檢查必要欄位
        if not data or 'id' not in data or 'password' not in data:
            logger.warning("Missing id or password")
            return jsonify({'error': 'Missing id or password'}), 400

        id = data['id']
        password = data['password']

        # 驗證身分證號碼
        if not validate_id(id):
            logger.warning(f"Invalid id format: {id}")
            return jsonify({'error': 'Invalid id format: must be 10 characters, start with uppercase letter, second character 1 or 2, followed by 8 digits'}), 400

        user = User.query.filter_by(id=id).first()
        if user and user.password == password:
            logger.info(f"Login successful: id={id}, username={user.username}, age={user.age}, identity={user.identity}")
            return jsonify({
                'message': 'Login successful',
                'token': 'dummy-token',
                'id': id,
                'username': user.username,
                'age': user.age,
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

# 新增查看所有使用者資料的 API
@app.route('/api/users', methods=['GET'])
def get_users():
    try:
        logger.debug("Fetching all users")
        users = User.query.all()
        user_list = [{
            'id': user.id,
            'age': user.age,
            'username': user.username,
            'password': user.password,
            'identity': user.identity
        } for user in users]
        logger.info(f"Retrieved {len(user_list)} users")
        return jsonify(user_list), 200
    except Exception as e:
        logger.error(f"Failed to fetch users: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# 主程式進入點
if __name__ == '__main__':
    with app.app_context():  # 在應用程式上下文中執行初始化
        try:
            db.create_all()  # 建立所有資料表（若尚未建立）
            logger.info("Database initialized")
        except Exception as e:
            logger.error(f"Database init error: {str(e)}")

    # 從環境變數讀取埠號，預設為 8080
    port = int(os.getenv('PORT', 8080))

    # 使用 Waitress 作為 WSGI server 來部署 Flask 應用（適用於正式環境）
    from waitress import serve
    serve(app, host='0.0.0.0', port=port, threads=4)