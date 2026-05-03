"""Сбор системных метрик для суточного heartbeat-отчёта.

Чистая stdlib — никаких внешних зависимостей (psutil и т.п.).
Собираем температуру, load average, использование дисков.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Optional

from .logger import get_logger

log = get_logger("xproxy.sysinfo")


# ---------- Температура ----------

def cpu_temp() -> Optional[float]:
    """Температура CPU в °C. Первый источник: x86_pkg_temp (Package id 0).
    Fallback: максимальное значение по coretemp через sensors -j.
    None → не удалось прочитать.
    """
    # Приоритет: x86_pkg_temp (Package id 0) — единая цифра для пакета
    for tz in sorted(Path("/sys/class/thermal").glob("thermal_zone*")):
        try:
            tz_type = (tz / "type").read_text().strip()
            if tz_type == "x86_pkg_temp":
                raw = int((tz / "temp").read_text().strip())
                return raw / 1000.0
        except (OSError, ValueError):
            continue

    # Fallback: максимальная температура ядер через sensors
    data = _sensors_json()
    if data is None:
        return None
    core_temps: list[float] = []
    for chip, entries in data.items():
        if not isinstance(entries, dict):
            continue
        for adapter, sensors in entries.items():
            if not isinstance(sensors, dict):
                continue
            # Пропускаем ключ "Adapter" — это мета-поле
            if adapter == "Adapter":
                continue
            for name, readings in sensors.items():
                if not isinstance(readings, dict):
                    continue
                if ("Core" in name or "Package" in name) and "temp1_input" in readings:
                    try:
                        core_temps.append(float(readings["temp1_input"]))
                    except (ValueError, TypeError):
                        pass
    if core_temps:
        return max(core_temps)

    return None


def nvme_temp() -> Optional[float]:
    """Температура NVMe диска через sensors -j (Composite sensor).

    Структура sensors -j для NVMe:
        {\"nvme-pci-0200\": {\"Adapter\": \"PCI adapter\", \"Composite\": {\"temp1_input\": 45.85, ...}}}
    Т.е. chip > sensor_name > readings (двухуровневая, а не трёхуровневая).
    """
    data = _sensors_json()
    if data is None:
        return None
    for chip, entries in data.items():
        if not isinstance(entries, dict):
            continue
        if "nvme" not in chip.lower():
            continue
        for key, val in entries.items():
            # Пропускаем мета-ключи вроде "Adapter"
            if not isinstance(val, dict):
                continue
            if "Composite" in key and "temp1_input" in val:
                try:
                    return float(val["temp1_input"])
                except (ValueError, TypeError):
                    pass
    return None


_sensors_cache: Optional[dict] = None


def _sensors_json() -> Optional[dict]:
    """Запустить 'sensors -j' и вернуть распарсенный JSON (кешируется)."""
    global _sensors_cache
    if _sensors_cache is not None:
        return _sensors_cache
    try:
        result = subprocess.run(
            ["sensors", "-j"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            import json
            _sensors_cache = json.loads(result.stdout)
            return _sensors_cache
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    except Exception:  # noqa: BLE001
        log.debug("sensors -j parse failed")
    _sensors_cache = {}  # не повторять попытки
    return None


def reset_sensors_cache() -> None:
    """Сбросить кэш sensors — для тестов."""
    global _sensors_cache
    _sensors_cache = None


# ---------- CPU Load ----------

def load_avg() -> str:
    """Load average за 1/5/15 мин: '0.42 0.38 0.35'."""
    try:
        with open("/proc/loadavg") as f:
            parts = f.read().split()
            return f"{parts[0]} {parts[1]} {parts[2]}"
    except OSError:
        return "?"


def cpu_count() -> int:
    """Число логических ядер."""
    try:
        return os.cpu_count() or 0
    except Exception:  # noqa: BLE001
        return 0


# ---------- Диски ----------

# Точки монтирования, которые не нужно показывать в отчёте
_SKIP_MOUNTS = frozenset({
    "/dev", "/dev/pts", "/dev/hugepages", "/dev/mqueue",
    "/boot/efi", "/boot",
    "/proc", "/sys", "/run", "/tmp",
    "/var/lib/docker", "/var/snap",
})

# Файловые системы, которые не нужно показывать
_SKIP_FS = frozenset({
    "tmpfs", "sysfs", "proc", "devpts", "cgroup", "cgroup2",
    "debugfs", "tracefs", "securityfs", "pstore", "efivarfs",
    "fusectl", "configfs", "squashfs", "mqueue", "hugetlbfs",
    "bpf", "overlay", "autofs", "binfmt_misc", "rpc_pipefs",
    "fuse.gvfsd-fuse", "fuse.portal",
    "devtmpfs",
})


def disk_usage() -> list[dict[str, str]]:
    """Использование примонтированных дисков.

    Возвращает список dict с ключами: mount, size, used, avail, pct.
    Только реальные блочные устройства; фильтруем шумные виртуальные точки.
    """
    disks = []
    seen_devices: set[str] = set()

    try:
        with open("/proc/mounts") as f:
            mounts = f.readlines()
    except OSError:
        return disks

    for line in mounts:
        parts = line.split()
        if len(parts) < 3:
            continue
        device, mount_point, fs_type = parts[0], parts[1], parts[2]

        # Пропускаем виртуальные FS
        if fs_type in _SKIP_FS:
            continue

        # Пропускаем snap/snapcraft loop mounts
        if "/snap/" in mount_point or "snapd" in device:
            continue

        # Пропускаем неинформативные точки монтирования
        if mount_point in _SKIP_MOUNTS:
            continue

        # Пропускаем bind-mount'ы того же устройства (оставляем первый)
        if device in seen_devices:
            continue
        seen_devices.add(device)

        # Пробуем получить информацию о месте
        try:
            stat = os.statvfs(mount_point)
        except OSError:
            continue

        block_size = stat.f_frsize if stat.f_frsize > 0 else stat.f_bsize
        total = stat.f_blocks * block_size
        free = stat.f_bavail * block_size   # доступно обычному пользователю
        used = total - stat.f_bfree * block_size  # реально занято

        if total == 0:
            continue

        pct = (used / total) * 100
        disks.append({
            "mount": mount_point,
            "_device": device,
            "size": _fmt_bytes(total),
            "used": _fmt_bytes(used),
            "avail": _fmt_bytes(free),
            "pct": f"{pct:.0f}%",
        })

    return disks


def _fmt_bytes(n: float) -> str:
    """Человекочитаемый размер: '937G', '18G', '1.7T'."""
    for unit in ("B", "K", "M", "G", "T"):
        if abs(n) < 1024.0:
            if unit in ("B", "K"):
                return f"{int(n)}{unit}"
            return f"{n:.1f}{unit}" if n < 10 else f"{int(n)}{unit}"
        n /= 1024.0
    return f"{int(n)}P"


# ---------- Сборка отчёта ----------


def _disk_label(device: str, mount: str) -> str:
    """Определить метку диска: 'ssd', 'hdd' или короткое имя точки монтирования.

    Для блочных устройств — проверяем /sys/block/.../queue/rotational:
      0 = SSD/NVMe, 1 = HDD.
    Если несколько блочных устройств одного типа — добавляем точку монтирования.
    Для неразрешимых устройств — fallback на имя точки монтирования.
    """
    import re

    # Проверяем, что это блочное устройство
    if not device.startswith("/dev/"):
        return mount.replace("/", "").rstrip("/") or "disk"

    # Имя устройства без /dev/: nvme0n1p2, sda1, etc.
    dev_name = device[5:]

    # Извлекаем базовое имя блочного устройства из имени партиции:
    # nvme0n1p2 → nvme0n1, sda1 → sda, vda2 → vda, mmcblk0p1 → mmcblk0
    block_name: Optional[str] = None
    m = re.match(r"(nvme\d+n\d+)(?:p\d+)?$", dev_name)
    if m:
        block_name = m.group(1)
    elif re.match(r"(mmcblk\d+)(?:p\d+)?$", dev_name):
        m2 = re.match(r"(mmcblk\d+)", dev_name)
        block_name = m2.group(1) if m2 else None
    else:
        # SCSI/Virtio/xen: sda1 → sda, vda2 → vda, xvd* → xvd?
        m3 = re.match(r"([a-z]+)", dev_name)
        if m3:
            block_name = m3.group(1)

    # Проверяем rotational
    if block_name:
        try:
            rot_path = Path(f"/sys/block/{block_name}/queue/rotational")
            rotational = int(rot_path.read_text().strip())
            if rotational == 0:
                return "ssd"
            else:
                return "hdd"
        except (OSError, ValueError):
            pass

    # Fallback: метка по точке монтирования
    if mount == "/":
        return "root"
    return mount.replace("/", "").rstrip("/") or "disk"


def system_report() -> str:
    """Компактная сводка для heartbeat-сообщения.

    Формат:
        cpu=73°C (load 3.1 2.9 2.4/8) | ssd=12%(105G/937G) hdd=1%(18G/1.8T) | nvme=46°C

    Метки дисков определяются автоматически через /sys/block/.../rotational:
    0 → ssd, 1 → hdd. Если несколько дисков одного типа, к метке
    добавляется точка монтирования (ssd/, hdd/mnt/data).
    """
    parts: list[str] = []

    # CPU
    temp = cpu_temp()
    ncpu = cpu_count()
    la = load_avg()
    if temp is not None:
        cpu_part = f"cpu={temp:.0f}°C"
    else:
        cpu_part = "cpu=?°C"
    cpu_part += f" (load {la}"
    if ncpu:
        cpu_part += f"/{ncpu}"
    cpu_part += ")"
    parts.append(cpu_part)

    # Диски — собираем метки и дедуплим (если два SSD — добавляем суффикс)
    disk_info = disk_usage()
    label_counts: dict[str, int] = {}
    labeled_disks: list[tuple[str, dict]] = []
    for d in disk_info:
        label = _disk_label(d.get("_device", ""), d["mount"])
        label_counts[label] = label_counts.get(label, 0) + 1
        labeled_disks.append((label, d))

    disk_parts: list[str] = []
    label_used: dict[str, int] = {}
    for label, d in labeled_disks:
        count = label_counts[label]
        if count > 1:
            # Дедупликация: добавляем суффикс с точкой монтирования
            idx = label_used.get(label, 0)
            label_used[label] = idx + 1
            if d["mount"] == "/":
                suffix = "/"
            else:
                # /mnt/hdd → mnt/hdd
                suffix = d["mount"].lstrip("/")
            final_label = f"{label}/{suffix}" if suffix else label
        else:
            final_label = label
        disk_parts.append(f"{final_label}={d['pct']}({d['used']}/{d['size']})")
    if disk_parts:
        parts.append(" ".join(disk_parts))

    # NVMe температура (может отсутствовать на серверах без NVMe)
    nvme = nvme_temp()
    if nvme is not None:
        parts.append(f"nvme={nvme:.0f}°C")

    return " | ".join(parts)