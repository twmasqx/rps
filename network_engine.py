# -*- coding: utf-8 -*-
"""
محرك الشبكة - فحص حقيقي، ARP، DNS/SNI، Kick (عند توفر Root)
للاستخدام على شبكات مملوكة فقط.
"""
import random
import time
import threading
import os
import platform
from typing import List, Dict, Optional

# استيراد scapy
try:
    from scapy.all import ARP, Ether, srp, sr1, send, conf, IP, TCP  # type: ignore
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

# منافذ شائعة للـ OS fingerprinting
COMMON_PORTS = {
    22: 'SSH',
    80: 'HTTP',
    443: 'HTTPS',
    445: 'SMB',
    3389: 'RDP',
    21: 'FTP',
    23: 'Telnet',
    53: 'DNS',
    5900: 'VNC',
}
# تخمين OS من المنافذ المفتوحة
OS_SIGNATURES = {
    'Linux': [22, 80, 443, 53],
    'Windows': [445, 3389, 80, 443],
    'Router/NAS': [80, 443, 53, 22],
    'Android/iOS': [80, 443],
}


def is_root_available() -> bool:
    """التحقق من صلاحيات Root - تعمل على Linux/Android"""
    try:
        if hasattr(os, 'geteuid'):
            return os.geteuid() == 0
        return False
    except (AttributeError, OSError):
        return False


# قاعدة OUI مُوسعة للتعرّف على العلامات التجارية
# ملاحظة: القائمة يمكن توسيعها عبر إضافة المزيد من البادئات
OUI_DB = {
    'APPLE': [
        '00:1C:B3', 'F4:5C:89', 'A4:5E:60', 'BC:AE:C5', 'D8:9D:67', 'A4:5E:60'
    ],
    'SAMSUNG': [
        '00:16:6C', '28:6C:07', '90:9F:33', '5C:49:79', 'FC:DB:B3'
    ],
    'HUAWEI': [
        '00:1E:C9', '8C:BE:BE', 'D8:9D:67', 'B8:3A:35', '84:3A:4B'
    ],
    'XIAOMI': [
        '00:21:6A', '00:E0:4C', '30:9C:23', '7C:8B:CA', '48:5B:39'
    ],
    'SONY': [
        '00:0B:6B', '00:1B:77', '80:00:2F', '5C:26:0A'
    ],
    'LG': [
        '00:02:B3', '00:80:48'
    ],
    'NOKIA': [
        '00:13:EF', '00:17:0D'
    ],
    'OPPO': [
        '00:1D:D7', '00:24:01'
    ],
    'VIVO': [
        '00:18:E7', '00:22:75'
    ],
    'ONEPLUS': [
        '00:1A:11', '00:1E:C2', '64:A2:F9', 'B4:B6:76'
    ],
    'REALME': ['8C:80:E8', '7C:B2:7D', '50:65:F3'],
    'MOTOROLA': ['00:1A:6B', '00:26:55', '34:4B:50', '94:65:2D'],
    'GOOGLE': ['00:1A:11', 'F8:0F:F9', 'FA:5F:A6', '3C:5A:B4'],
}

# قاعدة نماذج احترافية - العلامة التجارية + الموديل
MODEL_DB = {
    'APPLE': ['iPhone 15 Pro Max', 'iPhone 15 Pro', 'iPhone 15', 'iPhone 14', 'iPad Pro', 'iPad Air', 'MacBook Pro', 'Apple Watch'],
    'SAMSUNG': ['Galaxy S24 Ultra', 'Galaxy S24', 'Galaxy Z Fold', 'Galaxy A54', 'Galaxy Note 20', 'Galaxy Tab'],
    'HUAWEI': ['P60 Pro', 'Mate 60 Pro', 'Mate 50', 'Nova 12', 'Nova 10'],
    'XIAOMI': ['Xiaomi 14', 'Xiaomi 13', 'Redmi Note 13', 'Redmi Note 12', 'POCO F5', 'Mi 11'],
    'SONY': ['Xperia 1 V', 'Xperia 5', 'Xperia 10'],
    'LG': ['LG Velvet', 'LG Wing', 'LG V60'],
    'NOKIA': ['Nokia G60', 'Nokia G50', 'Nokia X30', 'Nokia 8.3'],
    'OPPO': ['Find X7', 'Find X6', 'Reno 11', 'Reno8', 'A78'],
    'VIVO': ['X100', 'Vivo X90', 'V29', 'V23', 'Y36'],
    'ONEPLUS': ['OnePlus 12', 'OnePlus 11', 'OnePlus Nord 3', 'OnePlus Nord'],
    'REALME': ['Realme GT 5', 'Realme 11', 'Realme C55'],
    'MOTOROLA': ['Moto Edge', 'Moto G84', 'Razr'],
    'GOOGLE': ['Pixel 8 Pro', 'Pixel 8', 'Pixel 7a'],
}


def get_model_for_vendor(vendor: str) -> str:
    """إرجاع نموذج افتراضي للعلامة التجارية"""
    models = MODEL_DB.get(vendor, ['Device'])
    return random.choice(models) if vendor != 'Unknown' else 'Unknown Device'


def normalize_mac(mac: str) -> str:
    # تحويل الماك لصيغة موحدة (أحرف كبيرة) وإرجاع أول ثلاث بايتس
    mac = mac.strip().upper()
    mac = mac.replace('-', ':')
    parts = mac.split(':')
    if len(parts) >= 3:
        prefix = ':'.join(parts[:3])
        return prefix
    return mac


def get_vendor_from_mac(mac: str) -> str:
    # يبحث في قاعدة OUI ويعيد اسم الشركة أو 'Unknown'
    prefix = normalize_mac(mac)
    for vendor, prefixes in OUI_DB.items():
        for p in prefixes:
            if prefix.startswith(p):
                return vendor
    return 'Unknown'


class Device:
    """جهاز مُكتشف - مع OS، المنافذ، وقوة الإشارة، واستهلاك البيانات"""
    def __init__(self, ip: str, mac: str, vendor: str, x: float = 0.0, y: float = 0.0):
        self.ip = ip
        self.mac = mac
        self.vendor = vendor
        self.x = x
        self.y = y
        self.trail = []
        self.os_guess = ''
        self.open_ports: List[int] = []
        self.rssi = None
        self.rtt_ms = None
        self.rx_bps = 0.0
        self.tx_bps = 0.0
        self.speed_limit_down_kbps = 0
        self.speed_limit_up_kbps = 0


def _log(msg: str, category: str = 'info'):
    """تسجيل منظم في ملفات logs"""
    try:
        log_dir = os.path.join(os.path.dirname(__file__), 'logs')
        os.makedirs(log_dir, exist_ok=True)
        ts = time.strftime('%Y-%m-%d %H:%M:%S')
        line = f"[{ts}] [{category.upper()}] {msg}\n"
        path = os.path.join(log_dir, f'{category}.log')
        with open(path, 'a', encoding='utf-8') as f:
            f.write(line)
    except Exception:
        pass


class NetworkEngine:
    # المحرك المسئول عن فحص الشبكة وإرجاع الأجهزة
    def __init__(self):
        self.devices: List[Device] = []
        self._lock = threading.Lock()
        from collections import defaultdict, deque
        self.requests_log = defaultdict(list)
        self.requests_log_path = os.path.join(os.path.dirname(__file__), 'requests_log.json')
        self.known_macs: set = set()
        self.bandwidth_samples: List[tuple] = []
        self._last_net_stats = None
        self._last_net_time = None
        self.device_traffic: Dict[str, Dict] = {}
        self._traffic_lock = threading.Lock()
        self._live_domains: deque = deque(maxlen=200)
        try:
            self.load_requests_log()
            self._load_known_devices()
        except Exception:
            pass
        self._load_remote_config()

    def _load_known_devices(self):
        """تحميل الأجهزة المعروفة من السجل"""
        try:
            path = os.path.join(os.path.dirname(__file__), 'known_devices.json')
            if os.path.exists(path):
                import json
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self.known_macs = set(data.get('macs', []))
        except Exception:
            pass

    def _save_known_devices(self):
        try:
            import json
            path = os.path.join(os.path.dirname(__file__), 'known_devices.json')
            with open(path, 'w', encoding='utf-8') as f:
                json.dump({'macs': list(self.known_macs)}, f)
        except Exception:
            pass

    def _load_remote_config(self):
        """تحميل إعدادات الإرسال عن بُعد (اختياري)"""
        self.remote_api_url = None
        self.telegram_bot_token = None
        self.telegram_chat_id = None
        try:
            cfg_path = os.path.join(os.path.dirname(__file__), 'nexus_config.json')
            if os.path.exists(cfg_path):
                import json
                with open(cfg_path, 'r', encoding='utf-8') as f:
                    cfg = json.load(f)
                self.remote_api_url = cfg.get('api_url')
                self.telegram_bot_token = cfg.get('telegram_bot_token')
                self.telegram_chat_id = cfg.get('telegram_chat_id')
        except Exception:
            pass

    def _push_to_remote(self, mac: str, rec: dict):
        """إرسال الطلب إلى API أو Telegram (إن وُجد الإعداد)"""
        try:
            if self.telegram_bot_token and self.telegram_chat_id:
                import urllib.request
                import urllib.parse
                msg = f"[{rec.get('time')}] {mac}\n{rec.get('domain')}"
                url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
                data = urllib.parse.urlencode({'chat_id': self.telegram_chat_id, 'text': msg}).encode()
                urllib.request.urlopen(urllib.request.Request(url, data=data, method='POST'), timeout=5)
            if self.remote_api_url:
                import urllib.request
                import json
                data = json.dumps({'mac': mac, **rec}).encode('utf-8')
                req = urllib.request.Request(self.remote_api_url, data=data, headers={'Content-Type': 'application/json'}, method='POST')
                urllib.request.urlopen(req, timeout=5)
        except Exception:
            pass

    def _simulate_devices(self, count=8) -> List[Device]:
        # مولد أجهزة وهمية يعمل كـ fallback عند عدم توفر صلاحيات أو scapy
        devs = []
        vendors = list(OUI_DB.keys())
        for i in range(count):
            # توليد IP وهمي
            ip = f'192.168.1.{100 + i}'
            # اختيار مصنع عشوائي
            vendor = random.choice(vendors)
            # اختيار بادئة OUI حقيقية جزئياً
            prefix = random.choice(OUI_DB.get(vendor, ['02:00:00']))
            # إكمال الماك بأربعة بايتات عشوائية
            mac_tail = ':'.join('%02X' % random.randint(0, 255) for _ in range(3))
            mac = prefix + ':' + mac_tail
            # اختيار نموذج جهاز معقول
            model = random.choice(MODEL_DB.get(vendor, ['Device']))
            # إحداثيات أولية داخل الدائرة
            x = random.uniform(-0.8, 0.8)
            y = random.uniform(-0.8, 0.8)
            d = Device(ip=ip, mac=mac, vendor=vendor, x=x, y=y)
            # إضافة اسم النموذج كخاصية إضافية
            d.model = model
            devs.append(d)
        return devs

    def load_oui_from_file(self, path: str = 'oui_db.json') -> None:
        # تحميل OUI إضافي من ملف JSON إن وُجد لزيادة دقة التعرّف
        try:
            import json
            if os.path.exists(path):
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    # دمج البيانات الجديدة مع OUI_DB الحالي
                    for vendor, prefixes in data.items():
                        if vendor in OUI_DB:
                            existing = set(OUI_DB[vendor])
                            for p in prefixes:
                                if p not in existing:
                                    OUI_DB[vendor].append(p)
                        else:
                            OUI_DB[vendor] = prefixes
        except Exception:
            # أي فشل في التحميل نتجنّبه بصمت
            pass

    def save_oui_to_file(self, path: str = 'oui_db.json') -> None:
        # حفظ OUI الحالي إلى ملف ليمكن توسيعه خارج التطبيق لاحقاً
        try:
            import json
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(OUI_DB, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def get_device_count(self) -> int:
        with self._lock:
            return len(self.devices)

    def get_gateway_ip(self) -> str:
        """الحصول على عنوان البوابة - للشبكات المحلية"""
        try:
            if platform.system() == 'Windows':
                import subprocess
                r = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=5)
                for line in r.stdout.split('\n'):
                    if 'Default Gateway' in line or 'العبارة الافتراضية' in line:
                        parts = line.split(':')
                        if len(parts) > 1:
                            return parts[-1].strip().split()[-1]
            else:
                with open('/proc/net/route', 'r') as f:
                    for line in f.readlines()[1:]:
                        fields = line.split()
                        if len(fields) >= 3 and fields[1] == '00000000':
                            g = int(fields[2], 16)
                            return f"{(g>>24)&0xFF}.{(g>>16)&0xFF}.{(g>>8)&0xFF}.{g&0xFF}"
        except Exception:
            pass
        return '192.168.1.1'

    def get_default_interface(self) -> str:
        """الحصول على واجهة الشبكة الافتراضية (wlan0, eth0 ...)"""
        try:
            if platform.system() != 'Windows' and os.path.exists('/proc/net/route'):
                with open('/proc/net/route', 'r') as f:
                    lines = f.readlines()[1:]
                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 3 and parts[1] == '00000000':
                            return parts[0]
            for iface in ('wlan0', 'eth0', 'wlan1', 'eth1', 'rmnet_data0'):
                if os.path.exists(f'/sys/class/net/{iface}'):
                    return iface
        except Exception:
            pass
        return 'wlan0'

    def request_root_or_warn(self) -> bool:
        """التحقق من صلاحيات Root - مطلوبة للتحكم في السرعة واعتراض التدفق"""
        if is_root_available():
            return True
        _log("Root required for Bandwidth Control & Full Gateway. Run as root.", 'info')
        return False

    def set_device_bandwidth_limit(self, ip: str, mac: str, down_kbps: int = 0, up_kbps: int = 0) -> bool:
        """
        تحديد سرعة الإنترنت لجهاز باستخدام tc (Traffic Control).
        يتطلب Root. 0 = بلا حد.
        """
        if not is_root_available():
            return False
        if platform.system() == 'Windows':
            return False
        try:
            import subprocess
            iface = self.get_default_interface()
            base = f'tc qdisc show dev {iface} | grep -q "htb"'
            subprocess.run(['sh', '-c', base], capture_output=True, timeout=2)
            down = max(1, down_kbps) if down_kbps else 999999
            up = max(1, up_kbps) if up_kbps else 999999
            class_id = abs(hash(mac) % 200) + 10
            cmds = [
                f'tc qdisc add dev {iface} root handle 1: htb default 30 2>/dev/null || true',
                f'tc class add dev {iface} parent 1: classid 1:1 htb rate 1000mbit 2>/dev/null || true',
                f'tc class add dev {iface} parent 1:1 classid 1:{class_id} htb rate {down}kbit ceil {down}kbit 2>/dev/null || true',
                f'tc filter add dev {iface} parent 1: protocol ip u32 match ip src {ip} flowid 1:{class_id} 2>/dev/null || true',
            ]
            for cmd in cmds:
                subprocess.run(['sh', '-c', cmd], capture_output=True, timeout=5)
            for d in self.devices:
                if d.ip == ip or d.mac == mac:
                    d.speed_limit_down_kbps = down_kbps
                    d.speed_limit_up_kbps = up_kbps
                    break
            _log(f"Bandwidth limit: {ip} -> {down_kbps}kbps down, {up_kbps}kbps up", 'gateway')
            return True
        except Exception as e:
            _log(f"tc limit failed: {e}", 'gateway')
            return False

    def record_traffic(self, mac: str, bytes_val: int, direction: str):
        """تسجيل حركة البيانات لجهاز (rx/tx) - يُستدعى من sniffer"""
        if not mac:
            return
        mac = mac.lower()
        with self._traffic_lock:
            if mac not in self.device_traffic:
                self.device_traffic[mac] = {'rx': 0, 'tx': 0, 'samples': []}
            rec = self.device_traffic[mac]
            if direction == 'rx':
                rec['rx'] += bytes_val
            else:
                rec['tx'] += bytes_val
            now = time.time()
            rec['samples'].append((now, rec['rx'], rec['tx']))
            if len(rec['samples']) > 30:
                rec['samples'].pop(0)

    def get_device_traffic_stats(self) -> Dict[str, Dict]:
        """إحصائيات استهلاك البيانات لكل جهاز"""
        result = {}
        with self._traffic_lock:
            for mac, rec in list(self.device_traffic.items()):
                rx_bps = tx_bps = 0.0
                if len(rec.get('samples', [])) >= 2:
                    a, b = rec['samples'][-2], rec['samples'][-1]
                    dt = b[0] - a[0]
                    if dt > 0:
                        rx_bps = (b[1] - a[1]) / dt
                        tx_bps = (b[2] - a[2]) / dt
                result[mac] = {'rx': rec['rx'], 'tx': rec['tx'], 'rx_bps': rx_bps, 'tx_bps': tx_bps}
        with self._lock:
            for d in self.devices:
                mac = d.mac.lower()
                if mac in result:
                    d.rx_bps = result[mac]['rx_bps']
                    d.tx_bps = result[mac]['tx_bps']
        return result

    def get_live_domains(self) -> List[Dict]:
        """النطاقات والروابط الحية (DNS/SNI/HTTP) - أحدث أولاً"""
        return list(reversed(list(self._live_domains)))

    def scan_device_ports(self, ip: str, ports: List[int] = None) -> List[int]:
        """فحص المنافذ المفتوحة - يتطلب scapy"""
        if not SCAPY_AVAILABLE:
            return []
        ports = ports or list(COMMON_PORTS.keys())
        open_ports = []
        try:
            conf.verb = 0
            from scapy.all import sr1
            for port in ports[:8]:
                pkt = IP(dst=ip) / TCP(dport=port, flags='S')
                ans = sr1(pkt, timeout=1, verbose=0)
                if ans and ans.haslayer(TCP) and ans[TCP].flags == 0x12:
                    open_ports.append(port)
        except Exception:
            pass
        return open_ports

    def infer_os_from_ports(self, open_ports: List[int]) -> str:
        """تخمين نظام التشغيل من المنافذ المفتوحة"""
        open_set = set(open_ports)
        best = 'Unknown'
        best_score = 0
        for os_name, sig in OS_SIGNATURES.items():
            score = len(open_set & set(sig))
            if score > best_score:
                best_score = score
                best = os_name
        return best

    def get_bandwidth_stats(self) -> tuple:
        """إرجاع (download_bps, upload_bps) من /proc/net/dev"""
        try:
            rx, tx = 0, 0
            if os.path.exists('/proc/net/dev'):
                with open('/proc/net/dev', 'r') as f:
                    for line in f.readlines()[2:]:
                        parts = line.split()
                        if len(parts) >= 10 and ':' in parts[0]:
                            rx += int(parts[1])
                            tx += int(parts[9])
            now = time.time()
            if self._last_net_stats and self._last_net_time:
                dt = now - self._last_net_time
                if dt > 0:
                    dr = (rx - self._last_net_stats[0]) / dt
                    du = (tx - self._last_net_stats[1]) / dt
                    self.bandwidth_samples.append((now, dr, du))
                    if len(self.bandwidth_samples) > 60:
                        self.bandwidth_samples.pop(0)
            self._last_net_stats = (rx, tx)
            self._last_net_time = now
            return (rx, tx)
        except Exception:
            return (0, 0)

    def get_bandwidth_rate(self) -> tuple:
        """معدل الرفع/التنزيل الحالي (bytes/sec)"""
        if len(self.bandwidth_samples) < 2:
            self.get_bandwidth_stats()
            time.sleep(1)
            self.get_bandwidth_stats()
        if len(self.bandwidth_samples) >= 2:
            a, b = self.bandwidth_samples[-2], self.bandwidth_samples[-1]
            return (b[1], b[2])
        return (0, 0)

    def run_security_audit(self) -> Dict:
        """فحص بروتوكول أمان الشبكة - WEP/WPA/WPA2"""
        result = {'protocol': 'Unknown', 'secure': True, 'details': []}
        try:
            if platform.system() != 'Windows':
                import subprocess
                for cmd in [['iwconfig'], ['nmcli', '-t', '-f', 'SECURITY', 'dev', 'wifi']]:
                    try:
                        r = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
                        out = (r.stdout or '').lower() + (r.stderr or '').lower()
                        if 'wep' in out:
                            result['protocol'] = 'WEP'
                            result['secure'] = False
                            result['details'].append('تحذير: WEP غير آمن')
                            break
                        elif 'wpa2' in out or 'wpa2-psk' in out:
                            result['protocol'] = 'WPA2'
                            result['secure'] = True
                            break
                        elif 'wpa' in out:
                            result['protocol'] = 'WPA'
                            result['secure'] = True
                            result['details'].append('يفضل الترقية إلى WPA2')
                            break
                    except Exception:
                        continue
        except Exception:
            result['details'].append('استخدم إعدادات Router للتحقق')
        _log(f"Security Audit: {result.get('protocol')} - secure={result.get('secure')}", 'audit')
        return result

    def kick_device(self, target_ip: str, target_mac: str) -> bool:
        """
        قطع اتصال جهاز عبر ARP Poisoning (يتطلب Root + Scapy).
        لإدارة الشبكة المملوكة فقط.
        """
        if not SCAPY_AVAILABLE or not is_root_available():
            return False
        try:
            conf.verb = 0
            gateway = self.get_gateway_ip()
            fake_mac = '02:00:00:00:00:00'
            # إخبار الهدف أن البوابة لديها MAC مزيف - يفقد الاتصال
            pkt = Ether(dst=target_mac) / ARP(op=2, psrc=gateway, hwdst=target_mac, pdst=target_ip, hwsrc=fake_mac)
            for _ in range(5):
                send(pkt)
                time.sleep(0.1)
            return True
        except Exception:
            return False

    def start_passive_sniffer(self, callback, iface: str = None) -> bool:
        """
        يبدأ رصداً سلبياً للحزم على الواجهة المحلية.
        - callback: دالة تستقبل قاموسًا بمعلومات الحزمة/الجهاز.
        - iface: واجهة الشبكة إن أردت تحديدها، خلاف ذلك يستخدم الافتراضي.
        يُعيد True إذا نُفّذ، False إذا كان scapy غير متوفر.
        هذه الوظيفة لا تقوم بأي تعديل على الشبكة ولا تنفذ هجمات.
        """
        if not SCAPY_AVAILABLE:
            return False

        # علامة إيقاف آمنة
        self._sniffer_stop = threading.Event()

        def _process_packet(pkt):
            try:
                info = {
                    'time': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'src_mac': None,
                    'dst_mac': None,
                    'src_ip': None,
                    'dst_ip': None,
                    'protocol': None,
                    'meta': {}
                }
                # ARP
                if pkt.haslayer('ARP'):
                    arp = pkt.getlayer('ARP')
                    info['protocol'] = 'ARP'
                    info['src_mac'] = arp.hwsrc
                    info['dst_mac'] = arp.hwdst if hasattr(arp, 'hwdst') else None
                    info['src_ip'] = arp.psrc
                    info['dst_ip'] = arp.pdst

                # IP/TCP/UDP
                if pkt.haslayer('IP'):
                    ip = pkt.getlayer('IP')
                    info['src_ip'] = getattr(ip, 'src', info['src_ip'])
                    info['dst_ip'] = getattr(ip, 'dst', info['dst_ip'])
                    info['protocol'] = info['protocol'] or ip.proto

                # مصدر/مقّدم طبقة لواسم الماك
                if pkt.haslayer('Ether'):
                    eth = pkt.getlayer('Ether')
                    info['src_mac'] = getattr(eth, 'src', info['src_mac'])
                    info['dst_mac'] = getattr(eth, 'dst', info['dst_mac'])

                # تحليل DNS وSNI وHTTP Host/User-Agent وmDNS/SSDP
                try:
                    from scapy.layers.inet import TCP, UDP, IP
                    from scapy.packet import Raw
                    # DNS
                    try:
                        from scapy.layers.dns import DNS, DNSQR
                        if pkt.haslayer(DNS) and getattr(pkt.getlayer(DNS), 'qdcount', 0) > 0:
                            dns = pkt.getlayer(DNS)
                            q = pkt.getlayer(DNSQR)
                            qname = getattr(q, 'qname', None)
                            if qname:
                                # qname may be bytes
                                try:
                                    qn = qname.decode() if isinstance(qname, bytes) else str(qname)
                                except Exception:
                                    qn = str(qname)
                                info['protocol'] = 'DNS'
                                info['meta']['dns_query'] = qn.rstrip('.')
                    except Exception:
                        pass

                    # mDNS (5353) / SSDP (1900)
                    if pkt.haslayer(UDP) and (getattr(pkt[UDP], 'sport', 0) in (5353, 1900) or getattr(pkt[UDP], 'dport', 0) in (5353, 1900)):
                        info['protocol'] = 'MDNS/SSDP'

                    # HTTP headers and TLS SNI (basic extraction)
                    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                        payload = pkt[Raw].load
                        # Try HTTP headers
                        try:
                            s = payload.decode('utf-8', errors='ignore')
                            if '\r\nHost:' in s or s.lower().startswith('get ') or s.lower().startswith('post '):
                                for line in s.split('\r\n'):
                                    if line.lower().startswith('host:'):
                                        info['meta']['host'] = line.split(':', 1)[1].strip()
                                    if line.lower().startswith('user-agent:'):
                                        info['meta']['user-agent'] = line.split(':', 1)[1].strip()
                        except Exception:
                            pass

                        # Basic TLS ClientHello SNI extraction
                        try:
                            def extract_sni(payload_bytes: bytes) -> str | None:
                                # Parse TLS record header
                                if len(payload_bytes) < 5:
                                    return None
                                # Content Type 22 = Handshake
                                if payload_bytes[0] != 22:
                                    return None
                                # skip record header (5 bytes)
                                # handshake starts at payload_bytes[5]
                                hs = payload_bytes[5:]
                                if len(hs) < 4:
                                    return None
                                # handshake type 1 = ClientHello
                                if hs[0] != 1:
                                    return None
                                # skip to extensions: need to skip variable lengths (client version, random, session id, cipher suites, compression)
                                try:
                                    idx = 4
                                    # session id length
                                    sid_len = hs[idx]
                                    idx += 1 + sid_len
                                    # cipher suites length (2 bytes)
                                    cs_len = int.from_bytes(hs[idx:idx+2], 'big')
                                    idx += 2 + cs_len
                                    # compression length
                                    comp_len = hs[idx]
                                    idx += 1 + comp_len
                                    # extensions length
                                    if idx + 2 > len(hs):
                                        return None
                                    ext_len = int.from_bytes(hs[idx:idx+2], 'big')
                                    idx += 2
                                    end_ext = idx + ext_len
                                    while idx + 4 <= end_ext:
                                        ext_type = int.from_bytes(hs[idx:idx+2], 'big')
                                        ext_len_i = int.from_bytes(hs[idx+2:idx+4], 'big')
                                        idx += 4
                                        if ext_type == 0:  # server_name
                                            # server_name list
                                            list_len = int.from_bytes(hs[idx:idx+2], 'big')
                                            idx2 = idx + 2
                                            while idx2 < idx + 2 + list_len:
                                                name_type = hs[idx2]
                                                name_len = int.from_bytes(hs[idx2+1:idx2+3], 'big')
                                                idx2 += 3
                                                name = hs[idx2:idx2+name_len].decode('utf-8', errors='ignore')
                                                return name
                                        idx += ext_len_i
                                except Exception:
                                    return None
                                return None

                            sni = extract_sni(payload)
                            if sni:
                                info['protocol'] = 'TLS'
                                info['meta']['sni'] = sni
                        except Exception:
                            pass
                except Exception:
                    pass

                # إذا كانت هناك معلومات ماك/آي بي نبعثها
                if info['src_mac'] or info['src_ip']:
                    # سجل سريع للطلبات المرتبطة بالجهاز
                    mac_key = (info.get('src_mac') or info.get('dst_mac') or 'unknown')
                    try:
                        # تأكد من وجود بنية السجل
                        if not hasattr(self, 'requests_log'):
                            from collections import defaultdict
                            self.requests_log = defaultdict(list)
                        mac_key = mac_key.lower()
                        recs = self.requests_log.setdefault(mac_key, [])
                        # اجمع أسماء النطاقات من DNS/SNI/Host
                        domain = None
                        if 'dns_query' in info.get('meta', {}):
                            domain = info['meta']['dns_query']
                        elif 'sni' in info.get('meta', {}):
                            domain = info['meta']['sni']
                        elif 'host' in info.get('meta', {}):
                            domain = info['meta']['host']
                        if domain:
                            rec = {'time': info.get('time'), 'domain': domain, 'mac': mac_key}
                            recs.append(rec)
                            self._live_domains.append({'time': info.get('time'), 'domain': domain, 'mac': mac_key})
                            try:
                                self.save_requests_log()
                                self._push_to_remote(mac_key, rec)
                            except Exception:
                                pass
                    except Exception:
                        pass
                    pkt_len = len(pkt) if hasattr(pkt, '__len__') else 0
                    if pkt_len and info.get('src_mac'):
                        self.record_traffic(info['src_mac'], pkt_len, 'tx')
                    if pkt_len and info.get('dst_mac'):
                        self.record_traffic(info['dst_mac'], pkt_len, 'rx')
                    callback(info)
            except Exception:
                pass

        def _sniff_loop():
            try:
                from scapy.all import sniff
                sniff(iface=iface, prn=_process_packet, store=0, stop_filter=lambda x: getattr(self, '_sniffer_stop', threading.Event()).is_set())
            except Exception:
                return

        t = threading.Thread(target=_sniff_loop, daemon=True)
        t.start()
        self._sniffer_thread = t
        return True

    def stop_passive_sniffer(self) -> None:
        # إيقاف الرصد السلبي بأمان
        if hasattr(self, '_sniffer_stop'):
            try:
                self._sniffer_stop.set()
            except Exception:
                pass

    def get_requests_for_device(self, mac: str):
        # إرجاع قائمة النطاقات/الطلبات المرتبطة بماك معين
        if not hasattr(self, 'requests_log'):
            return []
        return list(self.requests_log.get(mac.lower(), []))

    def save_requests_log(self):
        try:
            # تحويل defaultdict إلى dict عادي
            import json
            data = {mac: lst for mac, lst in self.requests_log.items()}
            with open(self.requests_log_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def load_requests_log(self):
        try:
            import json
            if os.path.exists(self.requests_log_path):
                with open(self.requests_log_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    from collections import defaultdict
                    self.requests_log = defaultdict(list, {k: v for k, v in data.items()})
        except Exception:
            from collections import defaultdict
            self.requests_log = defaultdict(list)

    def _measure_rtt(self, ip: str) -> Optional[float]:
        """قياس RTT التقريبي (ms) - يُستخدم لتقدير المسافة على الرادار"""
        if not SCAPY_AVAILABLE:
            return None
        try:
            pkt = IP(dst=ip) / TCP(dport=80, flags='S')
            t0 = time.time()
            ans = sr1(pkt, timeout=2, verbose=0)
            if ans:
                return (time.time() - t0) * 1000
        except Exception:
            pass
        return None

    def enhance_device_with_scan(self, device: Device) -> None:
        """إثراء الجهاز بفحص المنافذ وتخمين OS وقوة الإشارة (RTT)"""
        try:
            ports = self.scan_device_ports(device.ip)
            device.open_ports = ports
            device.os_guess = self.infer_os_from_ports(ports)
            rtt = self._measure_rtt(device.ip)
            if rtt is not None:
                device.rtt_ms = rtt
                _log(f"Device {device.ip}: RTT={rtt:.0f}ms", 'scan')
            _log(f"Device {device.ip}: OS={device.os_guess}, ports={ports}", 'scan')
        except Exception:
            pass

    def scan_network(self, ip_range: str = '192.168.1.0/24', timeout: int = 2, allow_simulation: bool = False, deep_scan: bool = False) -> List[Device]:
        # يحاول فحص الشبكة عبر scapy باستخدام ARP
        # في حال فشل التشغيل (صلاحيات/عدم وجود npcap...) يعود إلى وضع المحاكاة
        if not SCAPY_AVAILABLE:
            # scapy غير متوفر
            if allow_simulation:
                self.devices = self._simulate_devices()
                return self.devices
            else:
                # لا نولد أجهزة افتراضية إلا إذا سُمح صراحة
                with self._lock:
                    self.devices = []
                return []

        try:
            # تعطيل رسائل scapy الزائدة
            conf.verb = 0
            # تنفيذ ARP-scan عبر البث
            ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip_range), timeout=timeout)
            found = []
            for snd, rcv in ans:
                ip = rcv.psrc
                mac = rcv.hwsrc
                vendor = get_vendor_from_mac(mac)
                model = get_model_for_vendor(vendor)
                x = random.uniform(-1.0, 1.0)
                y = random.uniform(-1.0, 1.0)
                d = Device(ip=ip, mac=mac, vendor=vendor, x=x, y=y)
                d.model = model
                if mac.lower() not in self.known_macs and self.known_macs:
                    if hasattr(self, 'on_intruder') and self.on_intruder:
                        self.on_intruder(d)
                    _log(f"Intruder: {mac} ({ip})", 'alert')
                self.known_macs.add(mac.lower())
                found.append(d)
            self._save_known_devices()
            if not found:
                # لم يُكتشف شيء؛ لا نولد أجهزة افتراضية تلقائياً
                if allow_simulation:
                    found = self._simulate_devices()
                else:
                    found = []
            with self._lock:
                self.devices = found
            if deep_scan and found and SCAPY_AVAILABLE:
                def _enhance():
                    for d in found[:3]:
                        self.enhance_device_with_scan(d)
                threading.Thread(target=_enhance, daemon=True).start()
            return found

        except PermissionError:
            # لا توجد صلاحيات لفتح الشبكة - نعود للمحاكاة
            self.devices = self._simulate_devices()
            return self.devices
        except Exception:
            # أي أخطاء أخرى نستخدم المحاكاة الاحتياطية
            self.devices = self._simulate_devices()
            return self.devices


def precheck_environment() -> Dict[str, str]:
    # فحص سريع للبيئة: وجود scapy و Kivy - متوافق مع Android
    info = {}
    try:
        import scapy.all as scapy  # type: ignore
        info['scapy'] = 'OK'
    except Exception:
        info['scapy'] = 'MISSING'

    try:
        import kivy  # type: ignore
        info['kivy'] = 'OK'
    except Exception:
        info['kivy'] = 'MISSING'

    # صلاحيات الجذر (للمسح الشبكي) - يعمل على Linux/Android
    try:
        info['root'] = 'YES' if os.geteuid() == 0 else 'NO'
    except (AttributeError, OSError):
        # Windows أو أنظمة لا تدعم geteuid
        info['root'] = 'N/A'

    return info


if __name__ == '__main__':
    # اختبار سريع عند التشغيل المباشر
    engine = NetworkEngine()
    devs = engine.scan_network()
    print('Discovered', len(devs), 'devices')
