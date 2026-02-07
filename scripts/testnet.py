import os
import sys
import asyncio
import random
import json
import time
from typing import List, Tuple, Optional
from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_defunct
import aiohttp
from aiohttp_socks import ProxyConnector
from colorama import init, Fore, Style
from datetime import datetime, timezone

init(autoreset=True)

BORDER_WIDTH = 80

KONNEX_AI_BASE = "https://konnex-ai.xyz/api/v1"
KONNEX_HUB_BASE = "https://hub.konnex.world/api"

WEBSITE_ID = "7857ae2c-2ebf-4871-a775-349bcdc416ce"
ORGANIZATION_ID = "dbe51e03-92cc-4a5a-8d57-61c10753246b"
LOYALTY_RULE_ID = "5da522d1-5532-4850-a77d-2308d96288b1"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Content-Type": "application/json",
    "Origin": "https://testnet.konnex.world",
    "Referer": "https://testnet.konnex.world/",
    "Sec-Ch-Ua": '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "cross-site",
}

HUB_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
    "Accept": "*/*",
    "Accept-Language": "vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Content-Type": "application/json",
    "Origin": "https://hub.konnex.world",
    "Referer": "https://hub.konnex.world/points",
    "Sec-Ch-Ua": '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
}

CONFIG = {
    "DELAY_BETWEEN_ACCOUNTS": 3,
    "DELAY_BETWEEN_TASKS": 2,
    "RETRY_ATTEMPTS": 3,
    "RETRY_DELAY": 5,
    "THREADS": 5,
    "BYPASS_SSL": True,
    "TIMEOUT": 60,
    "STATUS_CHECK_INTERVAL": 3,
    "MAX_STATUS_CHECKS": 40,
}

LANG = {
    'vi': {
        'title': 'KONNEX TESTNET - ROBOT TRAINING TASKS',
        'info': 'Thông tin',
        'found': 'Tìm thấy',
        'wallets': 'ví',
        'processing_wallets': '⚙ ĐANG XỬ LÝ {count} VÍ',
        'getting_tasks': 'Đang lấy danh sách nhiệm vụ...',
        'tasks_success': 'Đã lấy {count} nhiệm vụ!',
        'selecting_task': 'Đang chọn nhiệm vụ ngẫu nhiên...',
        'task_selected': 'Đã chọn nhiệm vụ',
        'sending_request': 'Đang gửi yêu cầu...',
        'request_sent': 'Đã gửi yêu cầu thành công!',
        'checking_status': 'Đang kiểm tra trạng thái...',
        'status_queued': 'Trạng thái: Đang xếp hàng',
        'status_processing': 'Trạng thái: Đang xử lý',
        'status_done': 'Trạng thái: Hoàn thành',
        'submitting_feedback': 'Đang gửi đánh giá...',
        'feedback_success': 'Đã gửi đánh giá thành công!',
        'getting_csrf': 'Đang lấy CSRF token...',
        'csrf_success': 'Đã lấy CSRF token thành công!',
        'signing_message': 'Đang ký thông điệp...',
        'sign_success': 'Đã ký tin nhắn thành công!',
        'logging_in': 'Đang đăng nhập Hub...',
        'login_success': 'Đăng nhập Hub thành công!',
        'getting_user_id': 'Đang lấy User ID...',
        'user_id_success': 'Đã lấy User ID thành công!',
        'completing_loyalty': 'Đang hoàn thành nhiệm vụ loyalty...',
        'loyalty_success': 'Nhiệm vụ loyalty hoàn thành!',
        'success': '✅ Hoàn thành nhiệm vụ cho ví {address}',
        'points_earned': 'Điểm',
        'failure': '❌ Thất bại: {error}',
        'address': 'Địa chỉ ví',
        'pausing': 'Tạm dừng',
        'seconds': 'giây',
        'completed': '✅ HOÀN THÀNH: {successful}/{total} VÍ THÀNH CÔNG',
        'error': 'Lỗi',
        'pvkey_not_found': '❌ Không tìm thấy tệp pvkey.txt',
        'pvkey_empty': '❌ Không tìm thấy khóa riêng hợp lệ',
        'pvkey_error': '❌ Không thể đọc pvkey.txt',
        'invalid_key': 'không hợp lệ, đã bỏ qua',
        'warning_line': 'Cảnh báo: Dòng',
        'found_proxies': 'Tìm thấy {count} proxy trong proxies.txt',
        'found_wallets': 'Thông tin: Tìm thấy {count} ví',
        'no_proxies': 'Không tìm thấy proxy trong proxies.txt',
        'using_proxy': '🔄 Sử dụng Proxy - [{proxy}] với IP công khai - [{public_ip}]',
        'no_proxy': 'Không có proxy',
        'unknown': 'Không xác định',
        'invalid_proxy': '⚠ Proxy không hợp lệ hoặc không hoạt động: {proxy}',
        'ip_check_failed': '⚠ Không thể kiểm tra IP công khai: {error}',
        'task_header': 'NHIỆM VỤ HUẤN LUYỆN ROBOT',
        'task_name': 'Nhiệm vụ',
        'task_description': 'Mô tả',
        'request_id': 'ID Yêu cầu',
        'video_url': 'Video URL',
        'score_given': 'Điểm đánh giá',
        'status_timeout': '⚠ Hết thời gian chờ kiểm tra trạng thái',
        'already_completed': 'Đã hoàn thành trước đó',
        'total_earned': 'Tổng điểm kiếm được',
    },
    'en': {
        'title': 'KONNEX TESTNET - ROBOT TRAINING TASKS',
        'info': 'Information',
        'found': 'Found',
        'wallets': 'wallets',
        'processing_wallets': '⚙ PROCESSING {count} WALLETS',
        'getting_tasks': 'Getting tasks list...',
        'tasks_success': 'Got {count} tasks!',
        'selecting_task': 'Selecting random task...',
        'task_selected': 'Task selected',
        'sending_request': 'Sending request...',
        'request_sent': 'Request sent successfully!',
        'checking_status': 'Checking status...',
        'status_queued': 'Status: Queued',
        'status_processing': 'Status: Processing',
        'status_done': 'Status: Done',
        'submitting_feedback': 'Submitting feedback...',
        'feedback_success': 'Feedback submitted successfully!',
        'getting_csrf': 'Getting CSRF token...',
        'csrf_success': 'Got CSRF token successfully!',
        'signing_message': 'Signing message...',
        'sign_success': 'Signed message successfully!',
        'logging_in': 'Logging in to Hub...',
        'login_success': 'Hub login successful!',
        'getting_user_id': 'Getting User ID...',
        'user_id_success': 'Got User ID successfully!',
        'completing_loyalty': 'Completing loyalty task...',
        'loyalty_success': 'Loyalty task completed!',
        'success': '✅ Task completed for wallet {address}',
        'points_earned': 'Points',
        'failure': '❌ Failed: {error}',
        'address': 'Wallet address',
        'pausing': 'Pausing',
        'seconds': 'seconds',
        'completed': '✅ COMPLETED: {successful}/{total} WALLETS SUCCESSFUL',
        'error': 'Error',
        'pvkey_not_found': '❌ pvkey.txt file not found',
        'pvkey_empty': '❌ No valid private keys found',
        'pvkey_error': '❌ Failed to read pvkey.txt',
        'invalid_key': 'is invalid, skipped',
        'warning_line': 'Warning: Line',
        'found_proxies': 'Found {count} proxies in proxies.txt',
        'found_wallets': 'Info: Found {count} wallets',
        'no_proxies': 'No proxies found in proxies.txt',
        'using_proxy': '🔄 Using Proxy - [{proxy}] with Public IP - [{public_ip}]',
        'no_proxy': 'No proxy',
        'unknown': 'Unknown',
        'invalid_proxy': '⚠ Invalid or unresponsive proxy: {proxy}',
        'ip_check_failed': '⚠ Failed to check public IP: {error}',
        'task_header': 'ROBOT TRAINING TASKS',
        'task_name': 'Task',
        'task_description': 'Description',
        'request_id': 'Request ID',
        'video_url': 'Video URL',
        'score_given': 'Score given',
        'status_timeout': '⚠ Status check timeout',
        'already_completed': 'Already completed',
        'total_earned': 'Total Points Earned',
    }
}

def print_border(text: str, color=Fore.CYAN, width=BORDER_WIDTH, language: str = 'en'):
    text = text.strip()
    if len(text) > width - 4:
        text = text[:width - 7] + "..."
    padded_text = f" {text} ".center(width - 2)
    print(f"{color}┌{'─' * (width - 2)}┐{Style.RESET_ALL}")
    print(f"{color}│{padded_text}│{Style.RESET_ALL}")
    print(f"{color}└{'─' * (width - 2)}┘{Style.RESET_ALL}")

def print_separator(color=Fore.MAGENTA, language: str = 'en'):
    print(f"{color}{'═' * BORDER_WIDTH}{Style.RESET_ALL}")

def print_message(message: str, color=Fore.YELLOW, language: str = 'en'):
    print(f"{color}  {message}{Style.RESET_ALL}")

def print_wallets_summary(count: int, language: str = 'en'):
    print_border(
        LANG[language]['processing_wallets'].format(count=count),
        Fore.MAGENTA, language=language
    )
    print()

def is_valid_private_key(key: str) -> bool:
    key = key.strip()
    if not key.startswith('0x'):
        key = '0x' + key
    try:
        bytes.fromhex(key.replace('0x', ''))
        return len(key) == 66
    except ValueError:
        return False

def load_private_keys(file_path: str = "pvkey.txt", language: str = 'en') -> List[Tuple[int, str]]:
    if not os.path.exists(file_path):
        print(f"{Fore.RED}  {LANG[language]['pvkey_not_found']}{Style.RESET_ALL}")
        return []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        private_keys = []
        for idx, line in enumerate(lines, 1):
            key = line.strip()
            if not key or key.startswith('#'):
                continue
            
            if not key.startswith('0x'):
                key = '0x' + key
            
            if is_valid_private_key(key):
                private_keys.append((idx, key))
            else:
                print(f"{Fore.YELLOW}  {LANG[language]['warning_line']} {idx}: {LANG[language]['invalid_key']}{Style.RESET_ALL}")
        
        if not private_keys:
            print(f"{Fore.RED}  {LANG[language]['pvkey_empty']}{Style.RESET_ALL}")
        
        return private_keys
    
    except Exception as e:
        print(f"{Fore.RED}  {LANG[language]['pvkey_error']}: {str(e)}{Style.RESET_ALL}")
        return []

def load_proxies(file_path: str = "proxies.txt", language: str = 'en') -> List[str]:
    if not os.path.exists(file_path):
        print(f"{Fore.YELLOW}  ℹ {LANG[language]['no_proxies']}{Style.RESET_ALL}")
        return []
    
    proxies = []
    with open(file_path, 'r') as f:
        for line in f:
            proxy = line.strip()
            if proxy and not proxy.startswith('#'):
                proxies.append(proxy)
    
    if proxies:
        print(f"{Fore.YELLOW}  ℹ {LANG[language]['found_proxies'].format(count=len(proxies))}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}  ℹ {LANG[language]['no_proxies']}{Style.RESET_ALL}")
    
    return proxies

def parse_proxy(proxy: str) -> Tuple[Optional[str], str]:
    """
    Parse proxy string and return (proxy_type, proxy_url)
    Supports: http://, https://, socks4://, socks5://
    """
    proxy = proxy.strip()
    
    if proxy.startswith('socks5://'):
        return ('socks5', proxy)
    elif proxy.startswith('socks4://'):
        return ('socks4', proxy)
    elif proxy.startswith('https://'):
        return ('https', proxy)
    elif proxy.startswith('http://'):
        return ('http', proxy)
    else:
        return ('http', f'http://{proxy}')

async def check_proxy_ip(proxy: str, language: str = 'en') -> str:
    """Check the public IP of a proxy"""
    try:
        proxy_type, proxy_url = parse_proxy(proxy)
        
        if proxy_type in ['socks4', 'socks5']:
            connector = ProxyConnector.from_url(proxy_url)
        else:
            connector = None
        
        timeout = aiohttp.ClientTimeout(total=10)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            if proxy_type in ['http', 'https'] and connector is None:
                proxy_dict = proxy_url
            else:
                proxy_dict = None
            
            async with session.get('https://api.ipify.org?format=json', proxy=proxy_dict, ssl=False) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get('ip', LANG[language]['unknown'])
    except Exception as e:
        return LANG[language]['unknown']
    
    return LANG[language]['unknown']

async def get_tasks(session: aiohttp.ClientSession, language: str = 'en') -> List[dict]:
    """Get list of available tasks from Konnex AI"""
    try:
        async with session.get(
            f"{KONNEX_AI_BASE}/list_tasks",
            headers=HEADERS,
            ssl=not CONFIG['BYPASS_SSL']
        ) as response:
            if response.status == 200:
                tasks = await response.json()
                return tasks
            else:
                print(f"{Fore.RED}  ✖ Failed to get tasks: HTTP {response.status}{Style.RESET_ALL}")
                return []
    except Exception as e:
        print(f"{Fore.RED}  ✖ Error getting tasks: {str(e)}{Style.RESET_ALL}")
        return []

async def send_task_request(session: aiohttp.ClientSession, task_name: str, language: str = 'en') -> Optional[str]:
    """Send request to process a task"""
    try:
        payload = {"task": task_name}
        
        async with session.post(
            f"{KONNEX_AI_BASE}/send_request",
            json=payload,
            headers=HEADERS,
            ssl=not CONFIG['BYPASS_SSL']
        ) as response:
            if response.status == 200:
                data = await response.json()
                request_id = data.get('id')
                error = data.get('error')
                
                if error:
                    print(f"{Fore.RED}  ✖ Error from API: {error}{Style.RESET_ALL}")
                    return None
                
                return request_id
            else:
                print(f"{Fore.RED}  ✖ Failed to send request: HTTP {response.status}{Style.RESET_ALL}")
                return None
    except Exception as e:
        print(f"{Fore.RED}  ✖ Error sending request: {str(e)}{Style.RESET_ALL}")
        return None

async def check_request_status(session: aiohttp.ClientSession, request_id: str, language: str = 'en') -> Optional[dict]:
    """Check status of a request"""
    try:
        async with session.get(
            f"{KONNEX_AI_BASE}/request_status",
            params={"id": request_id},
            headers=HEADERS,
            ssl=not CONFIG['BYPASS_SSL']
        ) as response:
            if response.status == 200:
                data = await response.json()
                return data
            else:
                print(f"{Fore.RED}  ✖ Failed to check status: HTTP {response.status}{Style.RESET_ALL}")
                return None
    except Exception as e:
        print(f"{Fore.RED}  ✖ Error checking status: {str(e)}{Style.RESET_ALL}")
        return None

async def submit_feedback(session: aiohttp.ClientSession, request_id: str, wallet_address: str, score: int = 8, language: str = 'en') -> bool:
    """Submit feedback for completed task"""
    try:
        payload = {
            "score": score,
            "wallet": wallet_address.lower()
        }
        
        async with session.post(
            f"{KONNEX_AI_BASE}/request_feedback",
            params={"request_id": request_id},
            json=payload,
            headers=HEADERS,
            ssl=not CONFIG['BYPASS_SSL']
        ) as response:
            if response.status == 200:
                data = await response.json()
                return True
            else:
                text = await response.text()
                print(f"{Fore.RED}  ✖ Failed to submit feedback: HTTP {response.status} - {text[:100]}{Style.RESET_ALL}")
                return False
    except Exception as e:
        print(f"{Fore.RED}  ✖ Error submitting feedback: {str(e)}{Style.RESET_ALL}")
        return False

async def login_to_hub(session: aiohttp.ClientSession, private_key: str, language: str = 'en') -> bool:
    """Login to Konnex Hub"""
    try:
        w3 = Web3()
        account = Account.from_key(private_key)
        address = account.address
        
        # Step 1: Get CSRF token
        print(f"{Fore.CYAN}  > {LANG[language]['getting_csrf']}{Style.RESET_ALL}")
        
        async with session.get(
            f"{KONNEX_HUB_BASE}/auth/csrf",
            headers=HUB_HEADERS,
            ssl=not CONFIG['BYPASS_SSL']
        ) as response:
            if response.status != 200:
                print(f"{Fore.RED}  ✖ Failed to get CSRF: HTTP {response.status}{Style.RESET_ALL}")
                return False
            
            csrf_data = await response.json()
            csrf_token = csrf_data.get('csrfToken')
            
            if not csrf_token:
                print(f"{Fore.RED}  ✖ No CSRF token in response{Style.RESET_ALL}")
                return False
            
            print(f"{Fore.GREEN}  ✓ {LANG[language]['csrf_success']}{Style.RESET_ALL}")
        
        # Step 2: Sign message
        print(f"{Fore.CYAN}  > {LANG[language]['signing_message']}{Style.RESET_ALL}")

        current_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        
        message_dict = {
            "domain": "hub.konnex.world",
            "address": address,
            "statement": "Sign in to the app. Powered by Snag Solutions.",
            "uri": "https://hub.konnex.world",
            "version": "1",
            "chainId": 31612,
            "nonce": csrf_token,
            "issuedAt": current_time
        }
                
        message_text = f"{message_dict['domain']} wants you to sign in with your Ethereum account:\n{message_dict['address']}\n\n{message_dict['statement']}\n\nURI: {message_dict['uri']}\nVersion: {message_dict['version']}\nChain ID: {message_dict['chainId']}\nNonce: {message_dict['nonce']}\nIssued At: {message_dict['issuedAt']}"
                
        w3 = Web3()
        message = encode_defunct(text=message_text)
        signed_message = w3.eth.account.sign_message(message, private_key=private_key)
        signature = signed_message.signature.hex()
        if not signature.startswith('0x'):
           signature = '0x' + signature
                    
        print(f"{Fore.GREEN}  ✓ {LANG[language]['sign_success']}{Style.RESET_ALL}")
        
        # Step 3: Login with credentials
        print(f"{Fore.CYAN}  > {LANG[language]['logging_in']}{Style.RESET_ALL}")
        
        login_data = {
            "message": json.dumps(message_dict),
            "accessToken": signature,
            "signature": signature,
            "walletConnectorName": "MetaMask",
            "walletAddress": address,
            "redirect": "false",
            "callbackUrl": "/protected",
            "chainType": "evm",
            "walletProvider": "undefined",
            "csrfToken": csrf_token,
            "json": "true"
        }
        
        form_data = aiohttp.FormData()
        for key, value in login_data.items():
            form_data.add_field(key, str(value))
        
        headers_login = HUB_HEADERS.copy()
        headers_login['Content-Type'] = 'application/x-www-form-urlencoded'
        
        async with session.post(
            f"{KONNEX_HUB_BASE}/auth/callback/credentials",
            data=form_data,
            headers=headers_login,
            ssl=not CONFIG['BYPASS_SSL']
        ) as response:
            if response.status != 200:
                response_text = await response.text()
                print(f"{Fore.RED}  ✖ Login failed: HTTP {response.status}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}  ℹ Response: {response_text[:200]}{Style.RESET_ALL}")
                return False
            
            print(f"{Fore.GREEN}  ✓ {LANG[language]['login_success']}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}  - {LANG[language]['address']}: {address}{Style.RESET_ALL}")
            print()
            
            return True
    
    except Exception as e:
        print(f"{Fore.RED}  ✖ Login error: {str(e)}{Style.RESET_ALL}")
        return False

async def complete_loyalty_task(session: aiohttp.ClientSession, language: str = 'en') -> bool:
    """Complete the loyalty task on Hub"""
    try:
        print(f"{Fore.CYAN}  > {LANG[language]['completing_loyalty']}{Style.RESET_ALL}")
        
        async with session.post(
            f"{KONNEX_HUB_BASE}/loyalty/rules/{LOYALTY_RULE_ID}/complete",
            json={},
            headers=HUB_HEADERS,
            ssl=not CONFIG['BYPASS_SSL']
        ) as response:
            if response.status == 200:
                print(f"{Fore.GREEN}  ✓ {LANG[language]['loyalty_success']} (+50 {LANG[language]['points_earned']}){Style.RESET_ALL}")
                return True
            else:
                text = await response.text()
                if "already" in text.lower() or "completed" in text.lower():
                    print(f"{Fore.YELLOW}  ℹ {LANG[language]['already_completed']}{Style.RESET_ALL}")
                    return True
                else:
                    print(f"{Fore.YELLOW}  ⚠ Loyalty task: HTTP {response.status} - {text[:100]}{Style.RESET_ALL}")
                    return False
    except Exception as e:
        print(f"{Fore.RED}  ✖ Loyalty task error: {str(e)}{Style.RESET_ALL}")
        return False

async def train_robot(private_key: str, profile_num: int, proxy: Optional[str] = None, language: str = 'en'):
    """Main function to train robot and complete tasks"""
    for attempt in range(CONFIG['RETRY_ATTEMPTS']):
        try:
            connector = None
            if proxy:
                proxy_type, proxy_url = parse_proxy(proxy)
                if proxy_type in ['socks4', 'socks5']:
                    connector = ProxyConnector.from_url(proxy_url)
            
            timeout = aiohttp.ClientTimeout(total=CONFIG['TIMEOUT'])
            
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                print(f"{Fore.MAGENTA}{'─' * BORDER_WIDTH}{Style.RESET_ALL}")
                print()
                
                if proxy:
                    public_ip = await check_proxy_ip(proxy, language)
                    if public_ip != LANG[language]['unknown']:
                        proxy_display = proxy.split('@')[0] if '@' in proxy else proxy[:30]
                        print(f"{Fore.CYAN}  {LANG[language]['using_proxy'].format(proxy=proxy_display, public_ip=public_ip)}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.YELLOW}  {LANG[language]['invalid_proxy'].format(proxy=proxy[:30])}{Style.RESET_ALL}")
                
                w3 = Web3()
                account = Account.from_key(private_key)
                address = account.address
                
                print(f"{Fore.CYAN}  > {LANG[language]['getting_tasks']}{Style.RESET_ALL}")
                
                tasks = await get_tasks(session, language)
                
                if not tasks:
                    print(f"{Fore.RED}  ✖ No tasks available{Style.RESET_ALL}")
                    return False
                
                print(f"{Fore.GREEN}  ✓ {LANG[language]['tasks_success'].format(count=len(tasks))}{Style.RESET_ALL}")
                print()
                
                print(f"{Fore.CYAN}  > {LANG[language]['selecting_task']}{Style.RESET_ALL}")
                
                selected_task = random.choice(tasks)
                task_name = selected_task.get('name', '')
                task_description = selected_task.get('description', '')
                
                print(f"{Fore.GREEN}  ✓ {LANG[language]['task_selected']}: {task_description}{Style.RESET_ALL}")
                print()
                
                print(f"{Fore.CYAN}┌─ {LANG[language]['task_header']} ─────────────────────────────────────────────{Style.RESET_ALL}")
                print(f"{Fore.CYAN}│ > {LANG[language]['sending_request']}{Style.RESET_ALL}")
                
                request_id = await send_task_request(session, task_name, language)
                
                if not request_id:
                    print(f"{Fore.RED}│ ✖ Failed to send request{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}└──────────────────────────────────────────────────────────────{Style.RESET_ALL}")
                    return False
                
                print(f"{Fore.GREEN}│ ✓ {LANG[language]['request_sent']}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}│ - {LANG[language]['request_id']}: {request_id}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}│ - {LANG[language]['task_name']}: {task_description}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}│{Style.RESET_ALL}")
                
                print(f"{Fore.CYAN}│ > {LANG[language]['checking_status']}{Style.RESET_ALL}")
                
                status_data = None
                for check in range(CONFIG['MAX_STATUS_CHECKS']):
                    await asyncio.sleep(CONFIG['STATUS_CHECK_INTERVAL'])
                    
                    status_data = await check_request_status(session, request_id, language)
                    
                    if not status_data:
                        continue
                    
                    status = status_data.get('status', '')
                    
                    if status == 'queued':
                        print(f"{Fore.YELLOW}│ ⏳ {LANG[language]['status_queued']} ({check + 1}/{CONFIG['MAX_STATUS_CHECKS']}){Style.RESET_ALL}")
                    elif status == 'processing':
                        print(f"{Fore.YELLOW}│ ⚙ {LANG[language]['status_processing']} ({check + 1}/{CONFIG['MAX_STATUS_CHECKS']}){Style.RESET_ALL}")
                    elif status == 'done':
                        print(f"{Fore.GREEN}│ ✓ {LANG[language]['status_done']}{Style.RESET_ALL}")
                        break
                    else:
                        print(f"{Fore.YELLOW}│ ⚠ Unknown status: {status}{Style.RESET_ALL}")
                
                if not status_data or status_data.get('status') != 'done':
                    print(f"{Fore.YELLOW}│ {LANG[language]['status_timeout']}{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}└──────────────────────────────────────────────────────────────{Style.RESET_ALL}")
                    return False
                
                task_description_full = status_data.get('task', task_description)
                video_url = status_data.get('video_url', 'N/A')
                
                print(f"{Fore.YELLOW}│ - {LANG[language]['task_description']}: {task_description_full}{Style.RESET_ALL}")
                if video_url != 'N/A':
                    print(f"{Fore.YELLOW}│ - {LANG[language]['video_url']}: {video_url}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}│{Style.RESET_ALL}")
                
                print(f"{Fore.CYAN}│ > {LANG[language]['submitting_feedback']}{Style.RESET_ALL}")
                
                score = random.randint(7, 10)
                
                feedback_success = await submit_feedback(session, request_id, address, score, language)
                
                if not feedback_success:
                    print(f"{Fore.RED}│ ✖ Failed to submit feedback{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}└──────────────────────────────────────────────────────────────{Style.RESET_ALL}")
                    return False
                
                print(f"{Fore.GREEN}│ ✓ {LANG[language]['feedback_success']}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}│ - {LANG[language]['score_given']}: {score}/10{Style.RESET_ALL}")
                
                print(f"{Fore.CYAN}└──────────────────────────────────────────────────────────────{Style.RESET_ALL}")
                print()
                
                hub_login_success = await login_to_hub(session, private_key, language)
                
                if hub_login_success:
                    await complete_loyalty_task(session, language)
                else:
                    print(f"{Fore.YELLOW}  ⚠ Skipping loyalty task due to login failure{Style.RESET_ALL}")
                
                print()
                print(f"{Fore.GREEN}  ✅ {LANG[language]['success'].format(address=address[:6]+'...'+address[-4:])}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}  - {LANG[language]['total_earned']}: 50 {LANG[language]['points_earned']}{Style.RESET_ALL}")
                print()
                
                return True
        
        except Exception as e:
            if attempt < CONFIG['RETRY_ATTEMPTS'] - 1:
                delay = CONFIG['RETRY_DELAY']
                print(f"{Fore.RED}  ✖ {LANG[language]['failure'].format(error=str(e))}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}  ℹ {LANG[language]['pausing']} {delay:.2f} {LANG[language]['seconds']}{Style.RESET_ALL}")
                await asyncio.sleep(delay)
                continue
            print(f"{Fore.RED}  ✖ {LANG[language]['failure'].format(error=str(e))}{Style.RESET_ALL}")
            return False
    
    return False

async def run_testnet(language: str = 'vi'):
    print()
    print_border(LANG[language]['title'], Fore.CYAN, language=language)
    print()

    proxies = load_proxies(language=language)
    print()

    private_keys = load_private_keys(language=language)
    print(f"{Fore.YELLOW}  ℹ {LANG[language]['found_wallets'].format(count=len(private_keys))}{Style.RESET_ALL}")
    print()

    if not private_keys:
        return

    print_separator(language=language)
    random.shuffle(private_keys)
    print_wallets_summary(len(private_keys), language)

    total_interactions = 0
    successful_interactions = 0

    async def process_wallet(index, profile_num, private_key):
        nonlocal successful_interactions, total_interactions
        proxy = proxies[index % len(proxies)] if proxies else None
        
        async with semaphore:
            success = await train_robot(private_key, profile_num, proxy, language)
            total_interactions += 1
            if success:
                successful_interactions += 1
            if index < len(private_keys) - 1:
                print_message(f"{LANG[language]['pausing']} {CONFIG['DELAY_BETWEEN_ACCOUNTS']:.2f} {LANG[language]['seconds']}", Fore.YELLOW, language)
                await asyncio.sleep(CONFIG['DELAY_BETWEEN_ACCOUNTS'])

    semaphore = asyncio.Semaphore(CONFIG['THREADS'])
    tasks = [process_wallet(i, profile_num, key) for i, (profile_num, key) in enumerate(private_keys)]
    await asyncio.gather(*tasks, return_exceptions=True)

    print()
    print_border(
        LANG[language]['completed'].format(successful=successful_interactions, total=total_interactions),
        Fore.GREEN, language=language
    )
    print()

if __name__ == "__main__":
    asyncio.run(run_testnet('vi'))
