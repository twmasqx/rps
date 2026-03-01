# -*- coding: utf-8 -*-
"""
واجهة المستخدم الاحترافية - Nexus Vision
KivyMD مع ثيم داكن وتصميم Cybersecurity
متجاوبة مع شاشات الجوال - بدون أكواد ويندوز
"""
from kivy.lang import Builder
from kivy.clock import Clock
from kivy.graphics import Color, Ellipse, Line, Rectangle, Triangle
from kivy.metrics import dp
import math
import threading
import time
import os
import json
from typing import List

# KivyMD
from kivymd.app import MDApp
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.floatlayout import MDFloatLayout
from kivymd.uix.list import MDList, OneLineAvatarListItem, TwoLineAvatarListItem, ThreeLineAvatarListItem
from kivymd.uix.list import IconLeftWidget, IconRightWidget
from kivymd.uix.button import MDRaisedButton, MDFillRoundFlatButton, MDIconButton
from kivymd.uix.progressbar import MDProgressBar
from kivymd.uix.card import MDCard
try:
    from kivymd.uix.slider import MDSlider
except ImportError:
    from kivy.uix.slider import Slider as MDSlider
from kivymd.uix.dialog import MDDialog
from kivymd.uix.snackbar import Snackbar
from kivymd.uix.scrollview import MDScrollView
from kivymd.uix.toolbar import MDTopAppBar
from kivymd.uix.label import MDLabel

from network_engine import Device, get_vendor_from_mac, is_root_available, NetworkEngine


def _angle_diff(a, b):
    d = (a - b + 180) % 360 - 180
    return abs(d)


# رموز العلامات التجارية للعرض الاحترافي
VENDOR_ICONS = {
    'APPLE': '🍎',
    'SAMSUNG': '📱',
    'HUAWEI': '📶',
    'XIAOMI': '📲',
    'SONY': '🎮',
    'OPPO': '📞',
    'VIVO': '🔊',
    'ONEPLUS': '➕',
    'GOOGLE': '🔵',
    'MOTOROLA': '🦋',
    'NOKIA': '📵',
    'REALME': '⚡',
}
COLORS = {
    'bg_dark': (0.05, 0.06, 0.08, 1),
    'card_bg': (0.08, 0.1, 0.12, 1),
    'accent': (0, 0.85, 0.65, 1),      # سيان تقني
    'accent_dim': (0, 0.6, 0.5, 0.5),
    'danger': (0.9, 0.2, 0.2, 1),
    'text': (0.9, 0.92, 0.95, 1),
    'text_dim': (0.6, 0.65, 0.7, 1),
}


class BandwidthGraph(MDBoxLayout):
    """رسم بياني لاستهلاك الرفع/التنزيل"""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.down_samples = []
        self.up_samples = []
        self.size_hint = (1, None)
        self.height = dp(80)

    def update_samples(self, down_bps: float, up_bps: float):
        self.down_samples.append(down_bps / 1024)
        self.up_samples.append(up_bps / 1024)
        if len(self.down_samples) > 40:
            self.down_samples.pop(0)
            self.up_samples.pop(0)
        self.canvas.ask_update()

    def _draw(self):
        self.canvas.clear()
        down = getattr(self, 'down_samples', None)
        if down is None or not down or self.width < 10 or self.height < 10:
            return
        with self.canvas:
            Color(*COLORS['card_bg'])
            Rectangle(pos=self.pos, size=self.size)
            h = self.height - 4
            up = getattr(self, 'up_samples', [])
            max_val = max(max(self.down_samples, default=0), max(up, default=0), 1)
            pts_d = []
            pts_u = []
            n = len(self.down_samples)
            for i, (d, u) in enumerate(zip(self.down_samples, self.up_samples)):
                x = self.x + self.width * (i / max(n - 1, 1))
                pts_d.extend([x, self.y + 4 + (d / max_val) * h * 0.4])
                pts_u.extend([x, self.y + 4 + h * 0.5 + (u / max_val) * h * 0.4])
            if pts_d:
                Color(0, 1, 0.7, 0.8)
                Line(points=pts_d, width=2)
            if pts_u:
                Color(1, 0.6, 0, 0.8)
                Line(points=pts_u, width=2)

    def on_pos(self, *a):
        self._draw()

    def on_size(self, *a):
        self._draw()


class RadarWidget(MDBoxLayout):
    """رادار مرئي متجاوب - يتوسط الشاشة"""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.angle = 0.0
        self.devices: List[Device] = []
        self.spin_speed = 1.6
        self._device_clicked_callback = None
        self.size_hint = (1, None)
        self.height = dp(280)
        Clock.schedule_interval(self._on_tick, 1 / 30.)

    def set_device_clicked_callback(self, callback):
        self._device_clicked_callback = callback

    def _on_tick(self, dt):
        self.angle = (self.angle + self.spin_speed) % 360.0
        for d in self.devices:
            d.trail.append((d.x, d.y))
            if len(d.trail) > 8:
                d.trail.pop(0)
            t = time.time() + (hash(d.mac) % 10)
            d.x += math.sin(t * 0.6) * 0.0008
            d.y += math.cos(t * 0.6) * 0.0008
        self._draw()

    def set_devices(self, devices: List[Device]):
        self.devices = list(devices) if devices else []
        for i, d in enumerate(self.devices):
            rtt = getattr(d, 'rtt_ms', None)
            rssi = getattr(d, 'rssi', None)
            angle = (hash(d.mac) % 360) * math.pi / 180
            if rtt is not None:
                radius = min(0.95, 0.2 + (rtt / 120) * 0.75)
            elif rssi is not None:
                radius = max(0.2, 0.95 - (rssi + 90) / 80)
            else:
                radius = 0.5 + (hash(d.mac) % 40) / 100
            d.x = radius * math.cos(angle)
            d.y = radius * math.sin(angle)

    def on_touch_down(self, touch):
        if not self.collide_point(*touch.pos):
            return super().on_touch_down(touch)
        cx = self.center_x
        cy = self.center_y
        radius = min(self.width, self.height) / 2 - 15
        px, py = touch.pos
        closest = None
        closest_dist = 1e9
        for d in self.devices:
            dx = cx + d.x * radius - px
            dy = cy + d.y * radius - py
            dist = (dx * dx + dy * dy) ** 0.5
            if dist < closest_dist:
                closest_dist = dist
                closest = d
        if closest and closest_dist <= 28 and self._device_clicked_callback:
            try:
                self._device_clicked_callback(getattr(closest, 'mac', ''))
            except Exception:
                pass
            return True
        return super().on_touch_down(touch)

    def _draw(self):
        self.canvas.clear()
        with self.canvas:
            Color(*COLORS['card_bg'])
            Rectangle(pos=self.pos, size=self.size)
            cx = self.center_x
            cy = self.center_y
            radius = min(self.width, self.height) / 2 - 15

            Color(*COLORS['accent_dim'])
            for r in range(1, 5):
                Line(circle=(cx, cy, radius * r / 5), width=1)

            angle_rad = math.radians(-self.angle)
            sweep_angle = math.radians(30)
            x1 = cx + radius * math.cos(angle_rad)
            y1 = cy + radius * math.sin(angle_rad)
            x2 = cx + radius * math.cos(angle_rad + sweep_angle)
            y2 = cy + radius * math.sin(angle_rad + sweep_angle)
            Color(*COLORS['accent'])
            Triangle(points=[cx, cy, x1, y1, x2, y2])

            for d in self.devices:
                px = cx + d.x * radius
                py = cy + d.y * radius
                dx, dy = px - cx, py - cy
                dist = math.hypot(dx, dy)
                if dist > radius:
                    nx, ny = dx / dist, dy / dist
                    px, py = cx + nx * radius * 0.98, cy + ny * radius * 0.98
                    edge_alpha = max(0, 0.86 - (dist - radius) * 0.01)
                else:
                    edge_alpha = 1.0

                if d.trail:
                    trail_pts = [cx + d.trail[0][0] * radius, cy + d.trail[0][1] * radius]
                    for tx, ty in d.trail[1:]:
                        trail_pts.extend([cx + tx * radius, cy + ty * radius])
                    Color(0, 1, 0.7, 0.5)
                    Line(points=trail_pts, width=2)

                dev_angle = (math.degrees(math.atan2(d.y, d.x)) + 360) % 360
                if _angle_diff(self.angle, dev_angle) < 6.0:
                    Color(0, 0.86, 1.0, 0.63)
                    Ellipse(pos=(px - 20, py - 20), size=(40, 40))

                rx = getattr(d, 'rx_bps', 0) + getattr(d, 'tx_bps', 0)
                high_usage = rx > 50 * 1024
                if high_usage:
                    Color(1, 0.4, 0, 0.9)
                    Ellipse(pos=(px - 14, py - 14), size=(28, 28))
                if d.vendor == 'APPLE':
                    Color(1, 1, 1, edge_alpha)
                else:
                    Color(0.39, 1, 0.47, edge_alpha)
                Ellipse(pos=(px - 8, py - 8), size=(16, 16))

    def on_pos(self, *args):
        self._draw()

    def on_size(self, *args):
        self._draw()


class ScannerThread:
    """خيط مسح منفصل - لا يوقف الواجهة"""
    def __init__(self, engine, interval=3.0, on_devices=None, on_log=None, on_scan_start=None, on_scan_end=None, deep_scan=False):
        self.engine = engine
        self.interval = interval
        self._running = True
        self._thread = None
        self.on_devices = on_devices
        self.on_log = on_log
        self.on_scan_start = on_scan_start
        self.on_scan_end = on_scan_end
        self.deep_scan = deep_scan

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        while self._running:
            try:
                if self.on_scan_start:
                    Clock.schedule_once(lambda dt: self.on_scan_start(), 0)
                devs = self.engine.scan_network(allow_simulation=False, deep_scan=self.deep_scan)
                for d in devs:
                    name = getattr(d, 'model', '') or d.vendor
                    if self.on_log:
                        Clock.schedule_once(lambda dt, m=f"[{time.strftime('%H:%M:%S')}] Target: {name} ({d.mac})": self.on_log(m), 0)
                if self.on_devices:
                    Clock.schedule_once(lambda dt, d=devs: self.on_devices(d), 0)
            except Exception as e:
                if self.on_log:
                    Clock.schedule_once(lambda dt, m=f"[{time.strftime('%H:%M:%S')}] Error: {e}": self.on_log(m), 0)
            if self.on_scan_end:
                Clock.schedule_once(lambda dt: self.on_scan_end(), 0)
            time.sleep(self.interval)

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)


class DeviceListItem(MDBoxLayout):
    """عنصر قائمة - جهاز + سرعة مباشرة + شريط تحديد الحد"""
    def __init__(self, device: Device, engine: NetworkEngine = None, on_click=None, on_speed_change=None, **kwargs):
        super().__init__(orientation='vertical', **kwargs)
        self.device = device
        self.engine = engine
        self.on_click_cb = on_click
        self.on_speed_change = on_speed_change
        self.size_hint_y = None
        self.height = dp(100)
        self.spacing = dp(4)
        self.padding = [dp(8), dp(4)]

        row = MDBoxLayout(orientation='horizontal', size_hint_y=None, height=dp(48))
        icon = VENDOR_ICONS.get(device.vendor, '📱')
        model = getattr(device, 'model', '') or device.vendor
        rx = getattr(device, 'rx_bps', 0) / 1024
        tx = getattr(device, 'tx_bps', 0) / 1024
        speed_txt = f"↓{rx:.0f} ↑{tx:.0f} KB/s"
        self.speed_label = MDLabel(
            text=f"{icon} {device.vendor} • {model}  [{speed_txt}]",
            halign='left',
            theme_text_color='Custom',
            text_color=COLORS['text'],
            size_hint_x=0.7,
        )
        self.speed_label.bind(on_touch_down=lambda w, t: self._handle_click(t))
        row.add_widget(self.speed_label)
        limit = getattr(device, 'speed_limit_down_kbps', 0)
        self.slider = MDSlider(min=0, max=1000, value=limit, size_hint_x=0.3)
        self.slider.bind(value=self._on_slider_change)
        row.add_widget(self.slider)
        self.add_widget(row)

        limit_lbl = MDLabel(
            text=f"IP: {device.ip}  |  Limit: {limit}kbps" + (" (unlimited)" if limit == 0 else ""),
            halign='left',
            font_style='Caption',
            theme_text_color='Custom',
            text_color=COLORS['text_dim'],
            size_hint_y=None,
            height=dp(20),
        )
        self.limit_label = limit_lbl
        self.add_widget(limit_lbl)

    def _handle_click(self, touch):
        if self.collide_point(*touch.pos) and touch.button == 'left':
            if self.on_click_cb and self.device:
                self.on_click_cb(self.device.mac)
            return True
        return False

    def _on_slider_change(self, instance, value):
        limit = int(value)
        self.limit_label.text = f"IP: {self.device.ip}  |  Limit: {limit}kbps" + (" (unlimited)" if limit == 0 else "")
        if self.engine and limit >= 0:
            def _apply():
                self.engine.set_device_bandwidth_limit(self.device.ip, self.device.mac, limit, limit)
            threading.Thread(target=_apply, daemon=True).start()
        if self.on_speed_change:
            self.on_speed_change(self.device.mac, limit)

    def update_speed_display(self, rx_bps, tx_bps):
        rx, tx = rx_bps / 1024, tx_bps / 1024
        icon = VENDOR_ICONS.get(self.device.vendor, '📱')
        model = getattr(self.device, 'model', '') or self.device.vendor
        self.speed_label.text = f"{icon} {self.device.vendor} • {model}  [↓{rx:.0f} ↑{tx:.0f} KB/s]"


class NexusVisionApp(MDApp):
    """التطبيق الرئيسي - واجهة احترافية"""
    def __init__(self, engine=None, **kwargs):
        super().__init__(**kwargs)
        self.engine = engine or __import__('network_engine').NetworkEngine()
        self.scanner = None
        self._sniffer_running = False
        self._monitor_dialog = None
        self._monitor_log_refresh = None
        self._device_list_items = {}
        self.theme_cls.theme_style = "Dark"
        self.theme_cls.primary_palette = "Cyan"
        self.theme_cls.accent_palette = "Teal"

    def build(self):
        root = MDBoxLayout(orientation='vertical', md_bg_color=COLORS['bg_dark'])

        # شريط علوي
        self.top_bar = MDTopAppBar(
            title="Nexus Vision",
            md_bg_color=COLORS['card_bg'],
            specific_text_color=COLORS['text'],
            left_action_items=[["arrow-left", lambda x: self._back_action()],
                              ["home", lambda x: self._home_action()]],
            right_action_items=[["refresh", lambda x: self._on_scan()]],
            elevation=0,
        )
        root.add_widget(self.top_bar)

        # لوحة تحكم Gateway - عدادات سرعة
        self.dashboard_card = MDCard(
            size_hint=(1, None),
            height=dp(72),
            md_bg_color=COLORS['card_bg'],
            elevation=0,
            radius=[dp(8)],
            padding=dp(8),
        )
        dash = MDBoxLayout(orientation='horizontal', spacing=dp(12))
        self.total_down_lbl = MDLabel(text="↓ 0 KB/s", font_style='H6', theme_text_color='Custom', text_color=(0, 1, 0.7, 1))
        self.total_up_lbl = MDLabel(text="↑ 0 KB/s", font_style='H6', theme_text_color='Custom', text_color=(1, 0.6, 0, 1))
        dash.add_widget(MDLabel(text="[color=00d9a5]Gateway[/color]", markup=True, size_hint_x=None, width=dp(60)))
        dash.add_widget(self.total_down_lbl)
        dash.add_widget(self.total_up_lbl)
        self.dashboard_card.add_widget(dash)
        root.add_widget(self.dashboard_card)

        # حالة Root + عداد الأجهزة
        root_status = "✓ Root" if is_root_available() else "○ No Root"
        self.count_label = MDLabel(
            text=f"[color=00d9a5]Devices: 0[/color]  |  [color=888888]{root_status}[/color]",
            markup=True,
            halign="center",
            font_style="H6",
            size_hint_y=None,
            height=dp(36),
        )
        root.add_widget(self.count_label)

        # رسم استهلاك البيانات
        self.bandwidth_graph = BandwidthGraph()
        root.add_widget(self.bandwidth_graph)

        # شريط التقدم
        self.progress = MDProgressBar(
            value=0,
            color=COLORS['accent'],
            size_hint_y=None,
            height=dp(4),
        )
        root.add_widget(self.progress)

        # بطاقة الرادار
        radar_card = MDCard(
            size_hint=(1, None),
            height=dp(300),
            md_bg_color=COLORS['card_bg'],
            elevation=0,
            radius=[dp(12)],
            padding=dp(8),
        )
        self.radar = RadarWidget()
        self.radar.set_device_clicked_callback(self._on_device_clicked)
        radar_card.add_widget(self.radar)
        root.add_widget(radar_card)

        # أزرار الإجراءات
        btn_row = MDBoxLayout(size_hint_y=None, height=dp(56), spacing=dp(8), padding=dp(8))
        for text, icon, action in [
            ("Scan", "radar", self._on_scan),
            ("Intercept", "crosshairs-gps", self._intercept_action),
            ("Kick", "lan-connect", self._kick_action),
        ]:
            btn = MDRaisedButton(
                text=text,
                icon=icon,
                md_bg_color=COLORS['accent'],
                on_release=action,
                size_hint_x=1,
            )
            btn_row.add_widget(btn)
        root.add_widget(btn_row)

        # قائمة الأجهزة MDList
        devices_label = MDLabel(
            text="Discovered Devices",
            halign="center",
            font_style="Subtitle1",
            size_hint_y=None,
            height=dp(32),
        )
        root.add_widget(devices_label)

        scroll = MDScrollView(size_hint=(1, 1))
        self.devices_list = MDList(
            md_bg_color=COLORS['bg_dark'],
            padding=dp(8),
        )
        scroll.add_widget(self.devices_list)
        root.add_widget(scroll)

        # شريط سفلي
        bottom_row = MDBoxLayout(size_hint_y=None, height=dp(56), spacing=dp(8), padding=dp(8))
        self.btn_monitor = MDFillRoundFlatButton(
            text="Monitor",
            on_release=self._toggle_sniffer,
            size_hint_x=1,
            md_bg_color=COLORS['card_bg'],
        )
        btn_kill = MDFillRoundFlatButton(
            text="Kill Switch",
            on_release=self._kill_switch,
            size_hint_x=1,
            md_bg_color=COLORS['danger'],
        )
        btn_audit = MDFillRoundFlatButton(text="Security Audit", size_hint_x=1, md_bg_color=COLORS['card_bg'])
        btn_audit.bind(on_release=self._open_security_audit)
        bottom_row.add_widget(self.btn_monitor)
        bottom_row.add_widget(btn_audit)
        bottom_row.add_widget(btn_kill)
        root.add_widget(bottom_row)

        Clock.schedule_interval(self._pull_engine, 2.0)
        Clock.schedule_interval(self._update_bandwidth, 1.5)
        return root

    def on_start(self):
        self.engine.on_intruder = self._on_intruder_detected
        self.scanner = ScannerThread(
            engine=self.engine,
            interval=3.0,
            on_devices=self._on_devices_updated,
            on_log=lambda msg: print(msg),
            on_scan_start=self._scan_started,
            on_scan_end=self._scan_ended,
            deep_scan=True,
        )
        self.scanner.start()

    def _on_intruder_detected(self, device: Device):
        """تنبيه فوري عند دخول جهاز غير معروف"""
        def _notify():
            try:
                from plyer import notification
                notification.notify(
                    title='Nexus Vision - Intruder Alert',
                    message=f'New device: {device.vendor} {device.ip} ({device.mac})',
                    app_name='Nexus Vision',
                )
            except Exception:
                pass
        Clock.schedule_once(lambda dt: _notify(), 0)
        self._show_snackbar(f'⚠ Intruder: {device.ip} ({device.vendor})')

    def _update_bandwidth(self, dt):
        if self.engine and hasattr(self.engine, 'get_bandwidth_stats'):
            try:
                self.engine.get_bandwidth_stats()
                samples = getattr(self.engine, 'bandwidth_samples', [])
                if len(samples) >= 2:
                    _, rx, tx = samples[-1]
                    self.bandwidth_graph.update_samples(rx, tx)
                    self.bandwidth_graph._draw()
            except Exception:
                pass

    def _open_security_audit(self, *a):
        if not self.engine:
            return
        result = self.engine.run_security_audit()
        status = '✓ آمن' if result.get('secure', True) else '⚠ غير آمن'
        txt = f"البروتوكول: {result.get('protocol', 'Unknown')}\nالحالة: {status}\n\n"
        for d in result.get('details', []):
            txt += f"• {d}\n"
        self.dialog = MDDialog(
            title="Security Audit",
            text=txt or "لا يمكن تحديد الإعدادات",
            type="simple",
            buttons=[MDRaisedButton(text="Close", on_release=lambda x: self.dialog.dismiss())],
        )
        self.dialog.open()

    def on_stop(self):
        if self.scanner:
            self.scanner.stop()

    def _scan_started(self):
        Clock.schedule_once(lambda dt: setattr(self.progress, 'value', 50), 0)

    def _scan_ended(self):
        Clock.schedule_once(lambda dt: setattr(self.progress, 'value', 0), 0)

    def _on_devices_updated(self, devs: List[Device]):
        Clock.schedule_once(lambda dt: self._update_devices_ui(devs), 0)

    def _update_devices_ui(self, devs):
        self.radar.set_devices(devs)
        root_status = "✓ Root" if is_root_available() else "○ No Root"
        self.count_label.text = f"[color=00d9a5]Devices: {len(devs)}[/color]  |  [color=888888]{root_status}[/color]"

        self.devices_list.clear_widgets()
        self._device_list_items = {}
        for d in devs:
            item = DeviceListItem(d, engine=self.engine, on_click=self._on_device_clicked)
            self.devices_list.add_widget(item)
            self._device_list_items[d.mac.lower()] = item

        try:
            entry = {
                'ts': time.strftime('%Y-%m-%d %H:%M:%S'),
                'count': len(devs),
                'devices': [{'ip': d.ip, 'mac': d.mac, 'vendor': d.vendor, 'model': getattr(d, 'model', '')} for d in devs]
            }
            logs = []
            log_path = os.path.join(os.path.dirname(__file__), 'scan_log.json')
            if os.path.exists(log_path):
                with open(log_path, 'r', encoding='utf-8') as f:
                    try:
                        logs = json.load(f)
                    except Exception:
                        logs = []
            logs.append(entry)
            with open(log_path, 'w', encoding='utf-8') as f:
                json.dump(logs, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def _on_device_clicked(self, mac: str):
        if not mac:
            return
        d = None
        for dev in getattr(self.engine, 'devices', []):
            if dev.mac == mac:
                d = dev
                break
        reqs = []
        try:
            if hasattr(self.engine, 'get_requests_for_device'):
                reqs = self.engine.get_requests_for_device(mac)
        except Exception:
            reqs = []
        icon = VENDOR_ICONS.get(d.vendor, '📱') if d else '📱'
        model = getattr(d, 'model', 'Unknown') if d else 'Unknown'
        os_guess = getattr(d, 'os_guess', '') or 'Unknown'
        ports = getattr(d, 'open_ports', [])
        txt = f"{icon} {d.vendor if d else 'Device'} - {model}\n\n"
        txt += f"IP: {d.ip if d else '-'}\nMAC: {mac}\n"
        txt += f"OS: {os_guess}\n"
        if ports:
            txt += f"Open Ports: {ports}\n"
        txt += "\nRecent URLs (DNS/SNI):\n"
        for r in reqs[-12:]:
            txt += f" • [{r.get('time')}] {r.get('domain')}\n"
        self.dialog = MDDialog(
            title="Device Details",
            text=txt or "No data",
            type="simple",
            buttons=[MDRaisedButton(text="Close", on_release=lambda x: self.dialog.dismiss())],
        )
        self.dialog.open()

    def _intercept_action(self, *a):
        self._show_snackbar("Intercept (simulation). Opening Monitor.")
        self._open_monitor()

    def _kick_action(self, *a):
        """عرض قائمة الأجهزة لاختيار واحد للطرد"""
        if not self.engine or not getattr(self.engine, 'devices', []):
            self._show_snackbar("No devices to kick.")
            return
        devs = list(getattr(self.engine, 'devices', []))
        root_ok = is_root_available()
        can_kick_real = root_ok and hasattr(self.engine, 'kick_device')

        content = MDBoxLayout(orientation='vertical', spacing=dp(8))
        tip = MDLabel(text="Select device to kick:" if can_kick_real else "Root required for real kick. Simulating.", size_hint_y=None, height=dp(40))
        content.add_widget(tip)
        for d in devs[:8]:
            btn = MDFillRoundFlatButton(
                text=f"{d.vendor} {getattr(d,'model','')} ({d.ip})",
                on_release=lambda x, dd=d: self._do_kick(dd),
                size_hint_y=None,
                height=dp(44),
            )
            content.add_widget(btn)
        self.dialog = MDDialog(
            title="Kick Device",
            type="custom",
            content_cls=content,
            buttons=[MDRaisedButton(text="Cancel", on_release=lambda x: self.dialog.dismiss())],
        )
        self.dialog.open()

    def _do_kick(self, device: Device):
        if not self.engine:
            return
        root_ok = is_root_available()
        if root_ok and hasattr(self.engine, 'kick_device'):
            def _run():
                ok = self.engine.kick_device(device.ip, device.mac)
                Clock.schedule_once(lambda dt: self._show_snackbar("Kick sent!" if ok else "Kick failed (check root)"), 0)
            threading.Thread(target=_run, daemon=True).start()
        else:
            self._show_snackbar("Root required. Simulated only.")
        if hasattr(self, 'dialog') and self.dialog:
            self.dialog.dismiss()

    def _on_scan(self, *a):
        if self.engine:
            self.progress.value = 30
            def _scan():
                try:
                    self.engine.scan_network(allow_simulation=False)
                    Clock.schedule_once(lambda dt: setattr(self.progress, 'value', 0), 0)
                except Exception:
                    Clock.schedule_once(lambda dt: setattr(self.progress, 'value', 0), 0)
            threading.Thread(target=_scan, daemon=True).start()

    def _toggle_sniffer(self, *a):
        if not self.engine:
            return
        if not self._sniffer_running:
            started = self.engine.start_passive_sniffer(self._on_sniff_packet)
            if started:
                self._sniffer_running = True
                self.btn_monitor.text = "Stop Monitor"
        else:
            try:
                self.engine.stop_passive_sniffer()
            except Exception:
                pass
            self._sniffer_running = False
            self.btn_monitor.text = "Monitor"

    def _on_sniff_packet(self, info: dict):
        try:
            src_mac = info.get('src_mac')
            src_ip = info.get('src_ip')
            vendor = get_vendor_from_mac(src_mac) if src_mac else None
            from network_engine import get_model_for_vendor
            d = Device(ip=src_ip or '0.0.0.0', mac=src_mac or '00:00:00:00:00:00', vendor=vendor or 'Unknown', x=0.0, y=0.0)
            d.model = get_model_for_vendor(vendor or 'Unknown')
            with getattr(self.engine, '_lock', threading.Lock()):
                exists = False
                for ex in getattr(self.engine, 'devices', []):
                    if ex.mac == d.mac:
                        exists = True
                        ex.ip = d.ip or ex.ip
                        ex.vendor = d.vendor or ex.vendor
                        break
                if not exists:
                    self.engine.devices.append(d)
            Clock.schedule_once(lambda dt: self._update_devices_ui(list(getattr(self.engine, 'devices', []))), 0)
            if self._monitor_dialog and hasattr(self, '_refresh_monitor_log'):
                Clock.schedule_once(lambda dt: self._refresh_monitor_log(), 0)
        except Exception:
            pass

    def _kill_switch(self, *a):
        try:
            if self.engine:
                self.engine.stop_passive_sniffer()
        except Exception:
            pass
        self._show_snackbar("Kill Switch activated.")

    def _back_action(self):
        self._show_snackbar("Back (UI-only)")

    def _home_action(self):
        self._show_snackbar("Home (UI-only)")

    def _show_snackbar(self, text: str):
        try:
            Snackbar(text=text).open()
        except Exception:
            try:
                from kivymd.uix.snackbar import MDSnackbar
                MDSnackbar(MDLabel(text=text), y=dp(24)).open()
            except Exception:
                print(text)

    def _pull_engine(self, dt):
        if self.engine:
            total_rx = total_tx = 0.0
            if hasattr(self.engine, 'get_device_traffic_stats'):
                try:
                    stats = self.engine.get_device_traffic_stats()
                    items = getattr(self, '_device_list_items', {})
                    for mac, rec in stats.items():
                        total_rx += rec.get('rx_bps', 0)
                        total_tx += rec.get('tx_bps', 0)
                        if mac in items and hasattr(items[mac], 'update_speed_display'):
                            items[mac].update_speed_display(rec['rx_bps'], rec['tx_bps'])
                    if hasattr(self, 'total_down_lbl'):
                        self.total_down_lbl.text = f"↓ {total_rx/1024:.0f} KB/s"
                    if hasattr(self, 'total_up_lbl'):
                        self.total_up_lbl.text = f"↑ {total_tx/1024:.0f} KB/s"
                except Exception:
                    pass
            if total_rx == 0 and total_tx == 0 and hasattr(self.engine, 'bandwidth_samples'):
                samples = getattr(self.engine, 'bandwidth_samples', [])
                if len(samples) >= 1:
                    _, rx, tx = samples[-1]
                    if hasattr(self, 'total_down_lbl'):
                        self.total_down_lbl.text = f"↓ {rx/1024:.0f} KB/s"
                    if hasattr(self, 'total_up_lbl'):
                        self.total_up_lbl.text = f"↑ {tx/1024:.0f} KB/s"
            with getattr(self.engine, '_lock', threading.Lock()):
                devices = list(getattr(self.engine, 'devices', []))
            self.radar.set_devices(devices)

    def _open_monitor(self):
        content = MDBoxLayout(orientation='vertical', spacing=dp(8), size_hint_y=None, height=dp(450))

        toolbar = MDBoxLayout(size_hint_y=None, height=dp(48), spacing=dp(8))
        btn_refresh = MDRaisedButton(text="Refresh", size_hint_x=None, width=dp(100))
        btn_export = MDRaisedButton(text="Export CSV", size_hint_x=None, width=dp(120))
        toolbar.add_widget(btn_refresh)
        toolbar.add_widget(btn_export)
        content.add_widget(toolbar)

        log_label = MDLabel(text="[color=00d9a5]Live Log[/color] — URLs captured in real-time", markup=True, size_hint_y=None, height=dp(28))
        content.add_widget(log_label)

        scroll_content = MDList(padding=dp(8))
        sv = MDScrollView(size_hint=(1, 1))
        sv.add_widget(scroll_content)
        content.add_widget(sv)

        def build_tree():
            scroll_content.clear_widgets()
            all_entries = []
            if self.engine and hasattr(self.engine, 'get_live_domains'):
                for rec in self.engine.get_live_domains():
                    all_entries.append((rec.get('time'), rec.get('mac', ''), rec.get('domain', '')))
            if not all_entries and self.engine and hasattr(self.engine, 'requests_log'):
                for mac, recs in self.engine.requests_log.items():
                    for r in recs:
                        all_entries.append((r.get('time'), mac, r.get('domain')))
            all_entries.sort(key=lambda x: x[0], reverse=True)
            for t, mac, dom in all_entries[:50]:
                sub = OneLineAvatarListItem(text=f"[{t}] {mac[:8]}... → {dom}")
                sub.add_widget(IconLeftWidget(icon="web"))
                scroll_content.add_widget(sub)
            if self.engine:
                for d in getattr(self.engine, 'devices', []):
                    ip, mac = d.ip or '', d.mac or ''
                    vendor = getattr(d, 'model', '') or d.vendor or ''
                    item = TwoLineAvatarListItem(text=f"{VENDOR_ICONS.get(d.vendor,'📱')} {ip} | {vendor}", secondary_text=mac)
                    item.add_widget(IconLeftWidget(icon="cellphone"))
                    scroll_content.add_widget(item)
                    try:
                        reqs = self.engine.get_requests_for_device(mac) if hasattr(self.engine, 'get_requests_for_device') else []
                        for r in reqs[-10:]:
                            sub = OneLineAvatarListItem(text=f"  [{r.get('time')}] {r.get('domain')}")
                            scroll_content.add_widget(sub)
                    except Exception:
                        pass
            if len(scroll_content.children) == 0:
                scroll_content.add_widget(MDLabel(text="No data. Start Monitor to capture.", halign="center"))

        self._refresh_monitor_log = build_tree

        def do_export():
            try:
                export_path = os.path.join(os.path.dirname(__file__), 'requests_export.csv')
                import csv
                with open(export_path, 'w', newline='', encoding='utf-8') as f:
                    w = csv.writer(f)
                    w.writerow(['mac', 'time', 'domain'])
                    for mac, recs in getattr(self.engine, 'requests_log', {}).items():
                        for r in recs:
                            w.writerow([mac, r.get('time'), r.get('domain')])
                self._show_snackbar(f"Exported to {export_path}")
            except Exception as e:
                self._show_snackbar(f"Export Error: {e}")

        def on_close(x):
            self._monitor_dialog = None
            if self._monitor_log_refresh:
                Clock.unschedule(self._monitor_log_refresh)
            self.dialog.dismiss()

        btn_refresh.bind(on_release=lambda x: build_tree())
        btn_export.bind(on_release=lambda x: do_export())
        build_tree()

        self.dialog = MDDialog(
            title="Monitor — Live Log & Devices",
            type="custom",
            content_cls=content,
            buttons=[MDRaisedButton(text="Close", on_release=on_close)],
        )
        self._monitor_dialog = self.dialog
        self._monitor_log_refresh = Clock.schedule_interval(lambda dt: build_tree(), 2.0)
        self.dialog.open()


if __name__ == '__main__':
    from network_engine import NetworkEngine
    NexusVisionApp(engine=NetworkEngine()).run()
