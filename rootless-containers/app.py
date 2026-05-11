#!/usr/bin/env python3
"""Demo app - prints UID/GID inside the container."""
import os

print("=" * 40)
print(f"  UID    : {os.getuid()}")
print(f"  GID    : {os.getgid()}")
print(f"  User   : {'root' if os.getuid() == 0 else 'non-root'}")
print("=" * 40)
