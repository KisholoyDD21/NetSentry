#!/usr/bin/env python3
"""
NetSentry entry point.

Usage:
    python run.py

On Windows, for full packet-capture functionality (Packet Analyzer tab),
install Npcap (https://npcap.com/#download) and run this from an
Administrator terminal. Live connection monitoring, threat detection on
connections, IP intelligence, and reporting all work without elevation.
"""
import sys
import traceback


def main():
    try:
        from netsentry.app import App
    except ImportError as exc:
        print(f"Missing dependency: {exc}")
        print("Install requirements first:  pip install -r requirements.txt")
        sys.exit(1)

    try:
        app = App()
        app.mainloop()
    except Exception:
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
