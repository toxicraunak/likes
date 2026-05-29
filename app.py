from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError
import logging
import warnings
from urllib3.exceptions import InsecureRequestWarning
import os
import threading
import time
from datetime import datetime, timedelta
import sys
import base64

sys.path.append("/")
from protobuf import my_pb2, output_pb2

warnings.simplefilter('ignore', InsecureRequestWarning)

app = Flask(__name__)
app.logger.setLevel(logging.INFO)

# ================= RAILWAY CONFIG =================
# Railway provides PORT env var
PORT = int(os.environ.get("PORT", 5000))

# Railway persistent storage path (if mounted)
# Default to current directory for local dev
STORAGE_PATH = os.environ.get("RAILWAY_VOLUME_MOUNT_PATH", ".")

# Update file paths for Railway
ACCOUNTS_FILE = os.path.join(STORAGE_PATH, "accounts.txt")
TOKEN_FILE_IND = os.path.join(STORAGE_PATH, "token_ind.json")
TOKEN_FILE_BR = os.path.join(STORAGE_PATH, "token_br.json")
TOKEN_FILE_BD = os.path.join(STORAGE_PATH, "token_bd.json")

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'
TOKEN_REFRESH_INTERVAL_HOURS = 2
MAX_WORKERS = 10

# Global flag to track scheduler
scheduler_started = False

# ================= JWT UTILITIES =================

def decode_jwt_payload(token):
    """Decode JWT payload to check expiry"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
        
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception as e:
        return None

def is_token_expired(token):
    """Check if JWT token is expired"""
    try:
        payload = decode_jwt_payload(token)
        if not payload:
            return True
        
        exp = payload.get('exp')
        if not exp:
            iat = payload.get('iat')
            ttl = payload.get('ttl', 7200)
            if iat:
                exp = iat + ttl
            else:
                return True
        
        current_time = int(time.time())
        return current_time >= exp
    except:
        return True

def get_token_remaining_time(token):
    """Get remaining seconds for token"""
    try:
        payload = decode_jwt_payload(token)
        if not payload:
            return 0
        
        exp = payload.get('exp')
        if not exp:
            iat = payload.get('iat')
            ttl = payload.get('ttl', 7200)
            if iat:
                exp = iat + ttl
            else:
                return 0
        
        remaining = exp - int(time.time())
        return max(0, remaining)
    except:
        return 0

# ================= JWT GENERATION =================

def get_oauth_token(password, uid):
    """Get OAuth token from Garena"""
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    
    headers = {
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    
    try:
        r = requests.post(url, headers=headers, data=data, timeout=30)
        j = r.json()
        
        token = (
            j.get("access_token")
            or j.get("token")
            or j.get("session_key")
            or j.get("jwt")
            or (j.get("data") or {}).get("token")
        )
        
        if token:
            j["access_token"] = token
            
        return {
            "access_token": j.get("access_token"),
            "open_id": j.get("open_id"),
            "uid": j.get("uid"),
            "raw": j
        }
    except Exception as e:
        app.logger.error(f"OAuth failed for UID {uid}: {e}")
        return None

def encrypt_aes(key, iv, plaintext):
    """AES-128-CBC Encryption"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_message)

def parse_major_login_response(response_content):
    """Parse MajorLogin protobuf response to dict"""
    response_dict = {}
    try:
        lines = response_content.split("\n")
        for line in lines:
            if ":" in line:
                key, value = line.split(":", 1)
                response_dict[key.strip()] = value.strip().strip('"')
    except:
        pass
    return response_dict

def generate_jwt_token(uid, password):
    """Main JWT Generation Flow"""
    token_data = get_oauth_token(password, uid)
    if not token_data or not token_data.get("access_token"):
        return None
    
    access_token = token_data["access_token"]
    open_id = token_data.get("open_id", "")
    
    # Build GameData protobuf
    game_data = my_pb2.GameData()
    game_data.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    game_data.game_name = "free fire"
    game_data.game_version = 1
    game_data.version_code = "1.108.3"
    game_data.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
    game_data.device_type = "Handheld"
    game_data.network_provider = "Verizon Wireless"
    game_data.connection_type = "WIFI"
    game_data.screen_width = 1280
    game_data.screen_height = 960
    game_data.dpi = "240"
    game_data.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
    game_data.total_ram = 5951
    game_data.gpu_name = "Adreno (TM) 640"
    game_data.gpu_version = "OpenGL ES 3.0"
    game_data.user_id = f"Google|{uid}-{int(time.time())}"
    game_data.ip_address = "172.190.111.97"
    game_data.language = "en"
    game_data.open_id = open_id
    game_data.access_token = access_token
    game_data.platform_type = 4
    game_data.device_form_factor = "Handheld"
    game_data.device_model = "Asus ASUS_I005DA"
    game_data.field_60 = 32968
    game_data.field_61 = 29815
    game_data.field_62 = 2479
    game_data.field_63 = 914
    game_data.field_64 = 31213
    game_data.field_65 = 32968
    game_data.field_66 = 31213
    game_data.field_67 = 32968
    game_data.field_70 = 4
    game_data.field_73 = 2
    game_data.library_path = "/data/app/com.dts.freefireth-QPvBnTUhYWE-7DMZSOGdmA==/lib/arm"
    game_data.field_76 = 1
    game_data.apk_info = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-QPvBnTUhYWE-7DMZSOGdmA==/base.apk"
    game_data.field_78 = 6
    game_data.field_79 = 1
    game_data.os_architecture = "32"
    game_data.build_number = "2019117877"
    game_data.field_85 = 1
    game_data.graphics_backend = "OpenGLES2"
    game_data.max_texture_units = 16383
    game_data.rendering_api = 4
    game_data.encoded_field_89 = "\u0017T\u0011\u0017\u0002\b\u000eUMQ\bEZ\u0003@ZK;Z\u0002\u000eV\ri[QVi\u0003\ro\t\u0007e"
    game_data.field_92 = 9204
    game_data.marketplace = "3rd_party"
    game_data.encryption_key = "KqsHT2B4It60T/65PGR5PXwFxQkVjGNi+IMCK3CFBCBfrNpSUA1dZnjaT3HcYchlIFFL1ZJOg0cnulKCPGD3C3h1eFQ="
    game_data.total_storage = 111107
    game_data.field_97 = 1
    game_data.field_98 = 1
    game_data.field_99 = "4"
    game_data.field_100 = "4"
    
    serialized = game_data.SerializeToString()
    encrypted = encrypt_aes(AES_KEY, AES_IV, serialized)
    
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'X-GA': "v1 1",
        'X-Unity-Version': "2018.4.11f1",
        'ReleaseVersion': "OB53"
    }
    
    try:
        response = requests.post(url, data=encrypted, headers=headers, verify=False, timeout=30)
        
        if response.status_code == 200:
            parsed = output_pb2.Garena_420()
            parsed.ParseFromString(response.content)
            result = parse_major_login_response(str(parsed))
            
            jwt_token = result.get("token")
            region = result.get("region", "BD")
            
            if jwt_token:
                return {
                    "uid": str(uid),
                    "token": jwt_token,
                    "region": region,
                    "api": result.get("api", "N/A"),
                    "status": "live",
                    "generated_at": int(time.time())
                }
        return None
    except Exception as e:
        app.logger.error(f"MajorLogin failed for {uid}: {e}")
        return None

# ================= TOKEN MANAGEMENT =================

def load_accounts():
    """Load uid:password from accounts.txt"""
    accounts = []
    if not os.path.exists(ACCOUNTS_FILE):
        return accounts
    
    with open(ACCOUNTS_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                uid, pwd = line.split(":", 1)
                accounts.append({"uid": uid.strip(), "password": pwd.strip()})
    return accounts

def load_tokens_with_validation(server_name):
    """Load tokens and check expiry"""
    filepath = None
    if server_name == "IND":
        filepath = TOKEN_FILE_IND
    elif server_name in ["BR", "US", "SAC", "NA"]:
        filepath = TOKEN_FILE_BR
    else:
        filepath = TOKEN_FILE_BD
    
    if not os.path.exists(filepath):
        return None, 0, 0
    
    try:
        with open(filepath, "r") as f:
            tokens = json.load(f)
        
        if not isinstance(tokens, list):
            return None, 0, 0
        
        valid_tokens = []
        expired_count = 0
        
        for token_entry in tokens:
            token = token_entry.get("token", "")
            if not token:
                continue
            
            if is_token_expired(token):
                expired_count += 1
            else:
                remaining = get_token_remaining_time(token)
                token_entry["expires_in"] = remaining
                valid_tokens.append(token_entry)
        
        return valid_tokens, expired_count, len(tokens)
        
    except Exception as e:
        app.logger.error(f"Failed to load tokens: {e}")
        return None, 0, 0

def save_tokens(filepath, tokens):
    """Save tokens to file with proper error handling"""
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else '.', exist_ok=True)
        
        with open(filepath, "w") as f:
            json.dump(tokens, f, indent=2)
        return True
    except Exception as e:
        app.logger.error(f"Failed to save tokens to {filepath}: {e}")
        return False

def refresh_expired_tokens(server_name):
    """Refresh only expired tokens for a specific server"""
    app.logger.info(f"Refreshing expired tokens for {server_name}...")
    
    accounts = load_accounts()
    if not accounts:
        app.logger.error("No accounts found")
        return False
    
    # Determine filepath
    filepath = None
    if server_name == "IND":
        filepath = TOKEN_FILE_IND
    elif server_name in ["BR", "US", "SAC", "NA"]:
        filepath = TOKEN_FILE_BR
    else:
        filepath = TOKEN_FILE_BD
    
    # Load current tokens
    current_tokens = []
    if os.path.exists(filepath):
        try:
            with open(filepath, "r") as f:
                current_tokens = json.load(f)
        except:
            current_tokens = []
    
    # Find which need refresh
    uid_to_account = {acc["uid"]: acc for acc in accounts}
    tokens_to_refresh = []
    
    for token_entry in current_tokens:
        uid = token_entry.get("uid")
        token = token_entry.get("token", "")
        
        if not token or is_token_expired(token):
            if uid in uid_to_account:
                tokens_to_refresh.append(uid_to_account[uid])
    
    # Add new accounts
    existing_uids = {t.get("uid") for t in current_tokens}
    for acc in accounts:
        if acc["uid"] not in existing_uids:
            tokens_to_refresh.append(acc)
    
    if not tokens_to_refresh:
        app.logger.info("No tokens need refresh")
        return True
    
    # Refresh
    results = []
    threads = []
    
    def worker(acc):
        result = generate_jwt_token(acc['uid'], acc['password'])
        if result:
            results.append(result)
        time.sleep(0.3)
    
    for acc in tokens_to_refresh:
        t = threading.Thread(target=worker, args=(acc,))
        threads.append(t)
    
    for i in range(0, len(threads), MAX_WORKERS):
        batch = threads[i:i+MAX_WORKERS]
        for t in batch:
            t.start()
        for t in batch:
            t.join()
    
    if results:
        # Merge with existing valid
        valid_existing = [t for t in current_tokens if not is_token_expired(t.get("token", ""))]
        uid_map = {t["uid"]: t for t in valid_existing}
        
        for new_token in results:
            uid_map[new_token["uid"]] = new_token
        
        merged = list(uid_map.values())
        return save_tokens(filepath, merged)
    
    return False

def refresh_all_tokens():
    """Force refresh all tokens"""
    app.logger.info("Starting full token refresh...")
    accounts = load_accounts()
    
    if not accounts:
        return
    
    results = []
    threads = []
    
    def worker(acc):
        result = generate_jwt_token(acc['uid'], acc['password'])
        if result:
            results.append(result)
        time.sleep(0.5)
    
    for acc in accounts:
        t = threading.Thread(target=worker, args=(acc,))
        threads.append(t)
    
    for i in range(0, len(threads), MAX_WORKERS):
        batch = threads[i:i+MAX_WORKERS]
        for t in batch:
            t.start()
        for t in batch:
            t.join()
    
    if results:
        # Group by region
        region_files = {
            "IND": TOKEN_FILE_IND,
            "BR": TOKEN_FILE_BR,
            "BD": TOKEN_FILE_BD
        }
        
        region_data = {}
        for item in results:
            region = item.get("region", "BD").upper()
            if region in ["BR", "US", "SAC", "NA"]:
                region = "BR"
            
            if region not in region_data:
                region_data[region] = []
            region_data[region].append(item)
        
        for region, data in region_data.items():
            if region in region_files:
                filepath = region_files[region]
                
                # Load existing
                existing = []
                if os.path.exists(filepath):
                    try:
                        with open(filepath, "r") as f:
                            existing = json.load(f)
                    except:
                        existing = []
                
                # Merge
                uid_map = {item["uid"]: item for item in existing}
                for new_item in data:
                    uid_map[new_item["uid"]] = new_item
                
                merged = list(uid_map.values())
                save_tokens(filepath, merged)

def scheduled_refresh():
    """Background scheduler"""
    while True:
        next_run = datetime.now() + timedelta(hours=TOKEN_REFRESH_INTERVAL_HOURS)
        app.logger.info(f"Next refresh at: {next_run}")
        refresh_all_tokens()
        time.sleep(TOKEN_REFRESH_INTERVAL_HOURS * 3600)

def start_scheduler():
    """Start background thread only once"""
    global scheduler_started
    if not scheduler_started:
        t = threading.Thread(target=scheduled_refresh, daemon=True)
        t.start()
        scheduler_started = True
        app.logger.info("Token scheduler started")

# ================= LIKE API =================

def encrypt_for_like(plaintext):
    try:
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        padded = pad(plaintext, AES.block_size)
        encrypted = cipher.encrypt(padded)
        return binascii.hexlify(encrypted).decode('utf-8')
    except Exception as e:
        return None

def create_like_protobuf(uid, region):
    try:
        msg = like_pb2.like()
        msg.uid = int(uid)
        msg.region = region
        return msg.SerializeToString()
    except Exception as e:
        return None

def create_uid_protobuf(uid):
    try:
        msg = uid_generator_pb2.uid_generator()
        msg.saturn_ = int(uid)
        msg.garena = 1
        return msg.SerializeToString()
    except Exception as e:
        return None

def decode_player_info(binary_data):
    if not binary_data or len(binary_data) < 5:
        return None
    
    try:
        info = like_count_pb2.Info()
        info.ParseFromString(binary_data)
        if info.AccountInfo.UID != 0:
            return info
    except:
        pass
    
    try:
        basic = like_count_pb2.BasicInfo()
        basic.ParseFromString(binary_data)
        if basic.UID != 0:
            info = like_count_pb2.Info()
            info.AccountInfo.UID = basic.UID
            info.AccountInfo.PlayerNickname = basic.PlayerNickname
            info.AccountInfo.Likes = basic.Likes
            return info
    except:
        pass
    
    return None

def get_player_info(encrypted_uid, server_name, token):
    try:
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif server_name in ["BR", "US", "SAC", "NA"]:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
        
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB53"
        }
        
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=15)
        
        if response.status_code == 401:
            return None, "EXPIRED"
        
        if response.status_code != 200:
            return None, f"HTTP_{response.status_code}"
        
        result = decode_player_info(response.content)
        return result, "OK"
        
    except Exception as e:
        return None, "ERROR"

async def send_like_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB53"
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers, timeout=10) as resp:
                return resp.status
    except:
        return None

async def send_multiple_likes(uid, server_name, url, tokens):
    try:
        proto_data = create_like_protobuf(uid, server_name)
        if not proto_data:
            return None
        
        encrypted = encrypt_for_like(proto_data)
        if not encrypted:
            return None
        
        tasks = []
        for i in range(100):
            token = tokens[i % len(tokens)]["token"]
            tasks.append(send_like_request(encrypted, token, url))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
        
    except:
        return None

# ================= FLASK ROUTES =================

@app.route('/')
def home():
    """Railway health check"""
    return jsonify({
        "status": "running",
        "service": "Free Fire Like API",
        "timestamp": datetime.now().isoformat()
    })

@app.route('/health')
def health():
    """Railway health check endpoint"""
    return jsonify({"status": "healthy"}), 200

@app.route('/generate_token', methods=['GET'])
def api_generate_token():
    uid = request.args.get('uid')
    password = request.args.get('password')
    
    if not uid or not password:
        return jsonify({"error": "Missing uid or password"}), 400
    
    result = generate_jwt_token(uid, password)
    if result:
        payload = decode_jwt_payload(result['token'])
        if payload and payload.get('exp'):
            result['expires_at'] = datetime.fromtimestamp(payload['exp']).isoformat()
            result['expires_in_seconds'] = payload['exp'] - int(time.time())
        return jsonify({"status": "success", "data": result})
    return jsonify({"status": "error", "message": "Failed"}), 500

@app.route('/refresh_all_tokens', methods=['GET'])
def api_refresh_all():
    def run():
        refresh_all_tokens()
    
    threading.Thread(target=run).start()
    return jsonify({"status": "started", "message": "Full refresh in progress"})

@app.route('/refresh_expired', methods=['GET'])
def api_refresh_expired():
    server_name = request.args.get("server_name", "IND").upper()
    
    def run():
        refresh_expired_tokens(server_name)
    
    threading.Thread(target=run).start()
    return jsonify({
        "status": "started", 
        "server": server_name,
        "message": "Refreshing expired tokens"
    })

@app.route('/token_status', methods=['GET'])
def api_token_status():
    server_name = request.args.get("server_name", "IND").upper()
    
    valid_tokens, expired_count, total_count = load_tokens_with_validation(server_name)
    
    if valid_tokens is None:
        return jsonify({"error": "Token file not found"}), 404
    
    expiring_soon = []
    for t in valid_tokens[:5]:
        remaining = get_token_remaining_time(t.get("token", ""))
        expiring_soon.append({
            "uid": t.get("uid"),
            "region": t.get("region"),
            "expires_in_minutes": round(remaining / 60, 1)
        })
    
    return jsonify({
        "server": server_name,
        "total_tokens": total_count,
        "valid_tokens": len(valid_tokens),
        "expired_tokens": expired_count,
        "sample_tokens": expiring_soon
    })

@app.route('/status', methods=['GET'])
def api_status():
    files = {
        "IND": TOKEN_FILE_IND,
        "BR": TOKEN_FILE_BR,
        "BD": TOKEN_FILE_BD
    }
    
    status = {}
    for region, filepath in files.items():
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                    sample_expiry = None
                    if data and len(data) > 0:
                        remaining = get_token_remaining_time(data[0].get("token", ""))
                        sample_expiry = f"{remaining // 60} minutes"
                    
                    status[region] = {
                        "exists": True, 
                        "count": len(data),
                        "sample_expires_in": sample_expiry
                    }
            except Exception as e:
                status[region] = {"exists": True, "error": str(e)}
        else:
            status[region] = {"exists": False}
    
    return jsonify({
        "status": "running",
        "storage_path": STORAGE_PATH,
        "auto_refresh_hours": TOKEN_REFRESH_INTERVAL_HOURS,
        "token_files": status
    })

@app.route('/like', methods=['GET'])
def handle_like():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    
    if not uid or not server_name:
        return jsonify({"error": "Missing uid or server_name"}), 400
    
    try:
        # Load tokens with validation
        valid_tokens, expired_count, total_count = load_tokens_with_validation(server_name)
        
        # If no valid tokens, try to refresh
        if not valid_tokens or len(valid_tokens) == 0:
            app.logger.warning(f"No valid tokens for {server_name}, attempting refresh...")
            refresh_success = refresh_expired_tokens(server_name)
            
            if refresh_success:
                valid_tokens, _, _ = load_tokens_with_validation(server_name)
            
            if not valid_tokens or len(valid_tokens) == 0:
                return jsonify({
                    "error": "No valid tokens available",
                    "message": "Token refresh attempted but failed",
                    "expired_count": expired_count,
                    "total_count": total_count
                }), 500
        
        # Get first valid token
        check_token = valid_tokens[0]["token"]
        
        # Encrypt target UID
        uid_proto = create_uid_protobuf(uid)
        if not uid_proto:
            return jsonify({"error": "UID protobuf failed"}), 500
        
        encrypted_uid = encrypt_for_like(uid_proto)
        if not encrypted_uid:
            return jsonify({"error": "Encryption failed"}), 500
        
        # Get before likes
        before_info, status = get_player_info(encrypted_uid, server_name, check_token)
        
        # If token expired during request, refresh and retry
        if status == "EXPIRED":
            app.logger.warning("Token expired during request, refreshing...")
            refresh_expired_tokens(server_name)
            valid_tokens, _, _ = load_tokens_with_validation(server_name)
            
            if not valid_tokens:
                return jsonify({"error": "Token expired and refresh failed"}), 500
            
            check_token = valid_tokens[0]["token"]
            before_info, status = get_player_info(encrypted_uid, server_name, check_token)
        
        if before_info is None:
            return jsonify({
                "error": "Failed to retrieve player info",
                "token_status": status,
                "valid_tokens_available": len(valid_tokens)
            }), 500
        
        # Extract data
        before_likes = int(before_info.AccountInfo.Likes)
        player_name = str(before_info.AccountInfo.PlayerNickname)
        player_uid = int(before_info.AccountInfo.UID)
        
        app.logger.info(f"Before: {player_name} has {before_likes} likes")
        
        # Select like URL
        if server_name == "IND":
            like_url = "https://client.ind.freefiremobile.com/LikeProfile"
        elif server_name in ["BR", "US", "SAC", "NA"]:
            like_url = "https://client.us.freefiremobile.com/LikeProfile"
        else:
            like_url = "https://clientbp.ggblueshark.com/LikeProfile"
        
        # Send likes
        asyncio.run(send_multiple_likes(uid, server_name, like_url, valid_tokens))
        
        # Wait for server update
        time.sleep(2)
        
        # Get after likes
        after_info, _ = get_player_info(encrypted_uid, server_name, check_token)
        
        if after_info is None:
            return jsonify({"error": "Failed to get final player info"}), 500
        
        after_likes = int(after_info.AccountInfo.Likes)
        likes_given = after_likes - before_likes
        
        return jsonify({
            "PlayerNickname": player_name,
            "UID": player_uid,
            "LikesbeforeCommand": before_likes,
            "LikesafterCommand": after_likes,
            "LikesGivenByAPI": likes_given,
            "status": 1 if likes_given > 0 else 2,
            "tokens_used": len(valid_tokens)
        })
        
    except Exception as e:
        app.logger.error(f"Like handler error: {e}")
        return jsonify({"error": str(e)}), 500

# ================= MAIN =================

if __name__ == '__main__':
    # Create accounts file if not exists
    if not os.path.exists(ACCOUNTS_FILE):
        with open(ACCOUNTS_FILE, 'w') as f:
            f.write("# Format: uid:password\\n")
            f.write("# Example: 123456789:mypassword\\n")
        app.logger.info(f"Created {ACCOUNTS_FILE}")
    
    # Start scheduler
    start_scheduler()
    
    # Run app - Railway provides PORT env var
    app.run(host='0.0.0.0', port=PORT, debug=False, use_reloader=False, threaded=True)
