# -*- coding: utf-8 -*-
"""
نقطة الدخول للتطبيق: main.py
يربط بين محرك الشبكة وواجهة المستخدم
متوافق مع Android - بدون أكواد ويندوز (ctypes, windll)
"""
import sys
import os

# طلب صلاحيات Android عند التشغيل (يعمل فقط على Android)
try:
    from android.permissions import request_permissions, Permission
    request_permissions([
        Permission.INTERNET,
        Permission.ACCESS_NETWORK_STATE,
        Permission.ACCESS_FINE_LOCATION,
        Permission.ACCESS_COARSE_LOCATION,
        Permission.CHANGE_NETWORK_STATE,
    ])
except Exception:
    pass  # ليس Android أو الوحدة غير متوفرة

from ui_core import NexusVisionApp
from network_engine import NetworkEngine, precheck_environment


def main():
    # فحص بيئي سريع قبل البدء
    env = precheck_environment()
    missing = [k for k, v in env.items() if v in ('MISSING', 'NO')]
    if missing:
        details = '\n'.join([f'{k}: {v}' for k, v in env.items()])
        print('تنبيه: بعض المتطلبات قد تكون غير متوفرة. التطبيق سيعمل بوضع المحاكاة إذا لزم.')
        print(details)

    # إنشاء محرك الشبكة (يعمل في الخلفية عبر threading)
    engine = NetworkEngine()
    if hasattr(engine, 'request_root_or_warn'):
        engine.request_root_or_warn()

    # تشغيل تطبيق Kivy - المحرك والواجهة مرتبطان بـ threading
    app = NexusVisionApp(engine=engine)
    app.run()


if __name__ == '__main__':
    main()
