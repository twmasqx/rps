#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kivy demo main for Nexus Vision (mobile-friendly UI)
- Single-file Kivy app for packaging with Buildozer
- SAFE: no packet injection or low-level sniffing inside the APK
- Reads local `requests_log.json` if present for demo Monitor view

Use this as the mobile UI client. Connect to a server API for live data.
"""
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.scrollview import ScrollView
from kivy.uix.gridlayout import GridLayout
from kivy.clock import Clock
from kivy.graphics import Color, Ellipse, Line, Rectangle
import json
import os
import time

REQ_LOG = os.path.join(os.path.dirname(__file__), 'requests_log.json')


class RadarWidget(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.size_hint_y = 0.6
        with self.canvas:
            Color(0.03, 0.05, 0.08)
            self.bg = Rectangle(pos=self.pos, size=self.size)
        self.bind(pos=self._update_rect, size=self._update_rect)
        Clock.schedule_interval(self.update, 1 / 30.)
        self.angle = 0.0
        self.devices = []

    def _update_rect(self, *args):
        self.bg.pos = self.pos
        self.bg.size = self.size

    def on_touch_down(self, touch):
        # simple hit test for devices (simulation)
        x, y = touch.pos
        for d in self.devices:
            dx = d.get('x', 0) - x
            dy = d.get('y', 0) - y
            if dx * dx + dy * dy < 30 * 30:
                return True
        return super().on_touch_down(touch)

    def set_devices(self, devices):
        self.devices = devices

    def update(self, dt):
        self.angle = (self.angle + 2.0) % 360
        self.canvas.clear()
        with self.canvas:
            Color(0.02, 0.12, 0.18)
            Rectangle(pos=self.pos, size=self.size)
            # radial circles
            Color(0.0, 0.6, 0.7, 0.12)
            cx = self.center_x
            cy = self.center_y
            r = min(self.width, self.height) * 0.45
            for i in range(1, 5):
                Line(circle=(cx, cy, r * i / 5), width=1)
            # sweep
            Color(0.0, 0.8, 0.9, 0.18)
            Line(circle=(cx, cy, r, 0, self.angle), width=6)
            # devices (simple)
            Color(1, 1, 1)
            for i, d in enumerate(self.devices):
                # devices have px/py normalized to widget
                px = cx + (d.get('nx', 0) * r)
                py = cy + (d.get('ny', 0) * r)
                Color(0.2, 0.9, 0.7, 1 if (i % 2 == 0) else 0.9)
                Ellipse(pos=(px - 8, py - 8), size=(16, 16))


class NexusApp(App):
    def build(self):
        root = BoxLayout(orientation='vertical', padding=8, spacing=8)
        self.radar = RadarWidget()
        root.add_widget(self.radar)

        # big neon buttons
        btn_row = BoxLayout(size_hint_y=0.18, spacing=8)
        b1 = Button(text='Intercept', font_size=20, background_normal='', background_color=(0, 0.2, 0.3, 1))
        b2 = Button(text='Kick', font_size=20, background_normal='', background_color=(0.2, 0, 0.1, 1))
        b3 = Button(text='Scan', font_size=20, background_normal='', background_color=(0, 0.1, 0.2, 1))
        b1.bind(on_release=self.on_intercept)
        b2.bind(on_release=self.on_kick)
        b3.bind(on_release=self.on_scan)
        btn_row.add_widget(b1)
        btn_row.add_widget(b2)
        btn_row.add_widget(b3)
        root.add_widget(btn_row)

        # bottom controls: Back/Home and Monitor
        bottom = BoxLayout(size_hint_y=0.12, spacing=8)
        back = Button(text='◀', size_hint_x=0.12)
        home = Button(text='⌂', size_hint_x=0.12)
        monitor = Button(text='Monitor')
        back.bind(on_release=lambda *_: self.show_msg('Back (UI-only)'))
        home.bind(on_release=lambda *_: self.show_msg('Home (UI-only)'))
        monitor.bind(on_release=lambda *_: self.open_monitor())
        bottom.add_widget(back)
        bottom.add_widget(home)
        bottom.add_widget(monitor)
        root.add_widget(bottom)

        # load demo devices
        Clock.schedule_once(lambda dt: self.load_demo(), 0.5)
        return root

    def load_demo(self):
        # Create some simulated devices for the mobile demo
        devs = []
        import random
        for i in range(6):
            devs.append({'mac': f'DEV{i:02X}', 'nx': random.uniform(-0.8, 0.8), 'ny': random.uniform(-0.8, 0.8), 'vendor': 'Apple' if i%2==0 else 'Samsung'})
        self.radar.set_devices(devs)

    def on_intercept(self, *a):
        self.show_msg('Intercept is simulation-only in this build.')

    def on_kick(self, *a):
        self.show_msg('Kick simulated (NO PACKETS SENT).')

    def on_scan(self, *a):
        self.show_msg('Scan triggered (uses server API in production).')

    def show_msg(self, text):
        p = Popup(title='Info', content=Label(text=text), size_hint=(0.8, 0.4))
        p.open()

    def open_monitor(self):
        content = GridLayout(cols=1, spacing=6, size_hint_y=None)
        content.bind(minimum_height=content.setter('height'))
        # load requests_log.json
        entries = []
        try:
            if os.path.exists(REQ_LOG):
                with open(REQ_LOG, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for mac, recs in data.items():
                        for r in recs[-8:]:
                            entries.append(f"{mac} - {r.get('time')} - {r.get('domain')}")
        except Exception:
            entries = ['No logs available']
        if not entries:
            entries = ['No logs available']
        for e in entries:
            content.add_widget(Label(text=e, size_hint_y=None, height=28))
        sv = ScrollView(size_hint=(1, 0.9))
        sv.add_widget(content)
        popup = Popup(title='Monitor Logs', content=sv, size_hint=(0.95, 0.8))
        popup.open()


if __name__ == '__main__':
    NexusApp().run()
