# -*- coding: utf-8 -*-
"""
سكريبت إعداد بسيط لفحص وتثبيت المتطلبات: PyQt6 و scapy
ويقوم بالتحقق من وجود Npcap على نظام ويندوز.
كل سطر مشروح باللغة العربية.
"""
import sys
import subprocess
import os


def pip_install(package: str) -> bool:
    # يحاول تثبيت حزمة عبر pip
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
        return True
    except Exception:
        return False


def check_npcap() -> (bool, str):
    # يفحص أماكن التثبيت الشائعة لـ Npcap على ويندوز
    possible = []
    pf = os.environ.get('ProgramFiles')
    pfx86 = os.environ.get('ProgramFiles(x86)')
    windir = os.environ.get('SystemRoot')
    if pf:
        possible.append(os.path.join(pf, 'Npcap'))
    if pfx86:
        possible.append(os.path.join(pfx86, 'Npcap'))
    if windir:
        possible.append(os.path.join(windir, 'System32', 'Npcap'))
    for p in possible:
        if os.path.exists(p):
            return True, p
    return False, ''


def ensure():
    # التحقق من PyQt6
    try:
        import PyQt6  # type: ignore
        pyqt_ok = True
    except Exception:
        pyqt_ok = pip_install('PyQt6')

    # التحقق من scapy
    try:
        import scapy.all as scapy  # type: ignore
        scapy_ok = True
    except Exception:
        scapy_ok = pip_install('scapy')

    # التحقق من Npcap
    npcap_ok, npcap_path = check_npcap()

    # طباعة النتائج
    print('PyQt6:', 'OK' if pyqt_ok else 'MISSING')
    print('scapy:', 'OK' if scapy_ok else 'MISSING')
    print('Npcap:', f'FOUND at {npcap_path}' if npcap_ok else 'NOT FOUND')

    if not npcap_ok:
        print('\nتنبيه: لم يتم العثور على Npcap. للحصول على دعم كامل للفحص على ويندوز، يرجى تثبيت Npcap من: https://nmap.org/npcap/')

    return pyqt_ok and scapy_ok


if __name__ == '__main__':
    ok = ensure()
    if ok:
        print('\nالتهيئة الأساسية جاهزة.')
    else:
        print('\nيرجى مراجعة الرسائل أعلاه وتثبيت الحزم المفقودة بصلاحيات مناسبة.')
