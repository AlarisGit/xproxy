"""Сбор системных метрик для суточного heartbeat-отчёта.

Чистая stdlib — никаких внешних зависимостей (psutil и т.п.).
Собираем температуру, load average, использование дисков.
"""
from __future__ import annotations

import os
import platform
import re
import socket
import subprocess
import time
from pathlib import Path
from typing import Optional

from .logger import get_logger

log = get_logger("xproxy.sysinfo")


def _short_hostname() -> str:
    try:
        return socket.gethostname().split(".", 1)[0] or "host"
    except OSError:
        return "host"


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
    """Load average за 1/5/15 мин: '0.42 0.38 0.35'. Кроссплатформенно."""
    try:
        a1, a5, a15 = os.getloadavg()
        return f"{a1:.2f} {a5:.2f} {a15:.2f}"
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

# macOS-специфичные FS и mount-точки которые нужно пропускать
_MACOS_SKIP_MOUNT_PREFIXES = (
    "/dev/", "/System/Volumes/VM", "/System/Volumes/Preboot",
    "/System/Volumes/Update", "/System/Volumes/xarts",
    "/System/Volumes/iSCPreboot", "/System/Volumes/Hardware",
    "/System/Volumes/Data",
    "/private/var/vm",
)

_MACOS_REAL_FS = frozenset({"apfs", "hfs", "exfat", "msdos", "ntfs", "ext4"})


def _read_mounts_linux() -> list[str]:
    """Читать /proc/mounts."""
    try:
        with open("/proc/mounts") as f:
            return f.readlines()
    except OSError:
        return []


def _read_mounts_macos() -> list[str]:
    """Получить список точек монтирования через 'mount' (macOS fallback).

    Формат вывода mount: /dev/disk3s1 on / (apfs, sealed, local, ...)
    """
    try:
        proc = subprocess.run(
            ["mount"], capture_output=True, text=True, timeout=5,
        )
        if proc.returncode != 0:
            return []
        lines = []
        for line in proc.stdout.splitlines():
            # Ищем " on " и тип ФС в скобках: ... on /mount/point (fstype, ...)
            m = re.search(r"^(.*?)\s+on\s+(/\S*)\s+\(([^)]+)\)", line)
            if not m:
                continue
            device = m.group(1)
            mount_point = m.group(2)
            fs_options = m.group(3)
            fs_type = fs_options.split(",")[0].strip()
            lines.append(f"{device} {mount_point} {fs_type}")
        return lines
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []


def disk_usage() -> list[dict[str, str]]:
    """Использование примонтированных дисков.

    Возвращает список dict с ключами: mount, size, used, avail, pct.
    Только реальные блочные устройства; фильтруем шумные виртуальные точки.
    """
    if platform.system().lower() == "linux":
        mount_lines = _read_mounts_linux()
    else:
        mount_lines = _read_mounts_macos()

    disks = []
    seen_devices: set[str] = set()

    for line in mount_lines:
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

        # macOS: пропускаем нереальные FS
        if platform.system().lower() != "linux" and fs_type not in _MACOS_REAL_FS:
            continue

        # macOS: пропускаем системные тома
        if any(mount_point.startswith(pfx) for pfx in _MACOS_SKIP_MOUNT_PREFIXES):
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


# ---------- Температура дисков (smartctl) ----------

def _smartctl_temp(device: str) -> Optional[float]:
    """Температура диска через smartctl -A. None если smartctl отсутствует или нет данных."""
    block = _base_block_device(device)
    if not block:
        return None
    try:
        proc = subprocess.run(
            ["smartctl", "-A", f"/dev/{block}"],
            capture_output=True, text=True, timeout=10,
        )
        if proc.returncode != 0:
            return None
        for line in proc.stdout.splitlines():
            if "Temperature_Celsius" not in line:
                continue
            parts = line.split()
            # RAW_VALUE в последней колонке — ищем последнее числовое поле
            for p in reversed(parts):
                try:
                    return float(p)
                except ValueError:
                    continue
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


def disk_temps() -> list[tuple[str, float]]:
    """Температуры всех не-NVMe блочных устройств. [(label, temp°C), ...]."""
    result: list[tuple[str, float]] = []
    seen_devices: set[str] = set()
    for d in disk_usage():
        device = d.get("_device", "")
        if not device or "nvme" in device.lower():
            continue
        block = _base_block_device(device)
        if not block or block in seen_devices:
            continue
        seen_devices.add(block)
        temp = _smartctl_temp(device)
        if temp is not None:
            label = _disk_label(device, d["mount"])
            if label not in ("ssd", "hdd"):
                label = "hdd"  # fallback
            result.append((label, temp))
    return result


def _fmt_bytes(n: float) -> str:
    """Человекочитаемый размер: '937G', '18G', '1.7T'."""
    for unit in ("B", "K", "M", "G", "T"):
        if abs(n) < 1024.0:
            if unit in ("B", "K"):
                return f"{int(n)}{unit}"
            return f"{n:.1f}{unit}" if n < 10 else f"{int(n)}{unit}"
        n /= 1024.0
    return f"{int(n)}P"


# ---------- Батарея ----------

_battery_cache: tuple[float, tuple[Optional[float], Optional[str]]] = (0.0, (None, None))


def battery() -> Optional[float]:
    """Заряд батареи в %, None если нет батареи/UPS."""
    pct, _ = _read_battery()
    return pct


def battery_status() -> Optional[str]:
    """Состояние батареи: 'charging', 'discharging', 'full' или None."""
    _, status = _read_battery()
    return status


def _read_battery() -> tuple[Optional[float], Optional[str]]:
    """(percentage, status) с коротким кэшем (5с)."""
    global _battery_cache
    now = time.time()
    expires, cached = _battery_cache
    if cached[0] is not None and now < expires:
        return cached

    result = _read_battery_platform()
    _battery_cache = (now + 5.0, result)
    return result


def _read_battery_platform() -> tuple[Optional[float], Optional[str]]:
    """Платформенно-специфичное чтение батареи."""
    system = platform.system().lower()
    if system == "linux":
        return _read_battery_linux()
    if system == "darwin":
        return _read_battery_macos()
    return None, None


def _read_battery_linux() -> tuple[Optional[float], Optional[str]]:
    """Чтение из /sys/class/power_supply/BAT*, затем UPS через apcaccess/upsc."""
    # 1. Ноутбучная батарея
    for bat in sorted(Path("/sys/class/power_supply").glob("BAT*")):
        try:
            cap = int((bat / "capacity").read_text().strip())
            status_raw = (bat / "status").read_text().strip().lower()
            status = "discharging" if "discharging" in status_raw else \
                     "charging" if "charging" in status_raw else \
                     "full" if "full" in status_raw else None
            return float(cap), status
        except (OSError, ValueError):
            continue

    # 2. UPS через apcaccess (apcupsd)
    result = _read_ups_apcaccess()
    if result[0] is not None:
        return result

    # 3. UPS через NUT (upsc)
    result = _read_ups_nut()
    if result[0] is not None:
        return result

    return None, None


def _read_ups_apcaccess() -> tuple[Optional[float], Optional[str]]:
    """Парсинг 'apcaccess' (APC UPS daemon)."""
    try:
        proc = subprocess.run(
            ["apcaccess"], capture_output=True, text=True, timeout=5,
        )
        if proc.returncode != 0:
            return None, None
        pct: Optional[float] = None
        status_raw: Optional[str] = None
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line.startswith("BCHARGE"):
                parts = line.split(":")
                if len(parts) >= 2:
                    try:
                        pct = float(parts[1].strip().split()[0])
                    except (ValueError, IndexError):
                        pass
            elif line.startswith("STATUS"):
                parts = line.split(":")
                if len(parts) >= 2:
                    status_raw = parts[1].strip().lower()
        if pct is None:
            return None, None
        if status_raw:
            if "onbatt" in status_raw:
                status = "discharging"
            elif "charging" in status_raw:
                status = "charging"
            else:
                status = "full"  # ONLINE, TRIMMED и т.д.
        else:
            status = None
        return pct, status
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None, None


def _read_ups_nut() -> tuple[Optional[float], Optional[str]]:
    """Парсинг 'upsc <upsname>' (Network UPS Tools)."""
    try:
        # Ищем имя UPS
        proc = subprocess.run(
            ["upsc", "-l"], capture_output=True, text=True, timeout=5,
        )
        if proc.returncode != 0:
            return None, None
        ups_names = [n.strip() for n in proc.stdout.splitlines() if n.strip()]
        if not ups_names:
            return None, None
        # Берём первый UPS
        proc = subprocess.run(
            ["upsc", ups_names[0]], capture_output=True, text=True, timeout=5,
        )
        if proc.returncode != 0:
            return None, None
        pct: Optional[float] = None
        status_raw: Optional[str] = None
        for line in proc.stdout.splitlines():
            if line.startswith("battery.charge:"):
                try:
                    pct = float(line.split(":")[1].strip())
                except (ValueError, IndexError):
                    pass
            elif line.startswith("ups.status:"):
                status_raw = line.split(":")[1].strip().lower()
        if pct is None:
            return None, None
        if status_raw:
            if "ob" in status_raw and "ol" not in status_raw:
                status = "discharging"
            elif "chrg" in status_raw:
                status = "charging"
            else:
                status = "full"  # OL, OL CHRG и т.д.
        else:
            status = None
        return pct, status
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None, None


def _read_battery_macos() -> tuple[Optional[float], Optional[str]]:
    """Парсинг 'pmset -g batt'."""
    try:
        proc = subprocess.run(
            ["pmset", "-g", "batt"],
            capture_output=True, text=True, timeout=5,
        )
        if proc.returncode != 0:
            return None, None
        for line in proc.stdout.splitlines():
            if "%" in line and ("InternalBattery" in line or "Battery" in line):
                import re
                m = re.search(r"(\d+)%", line)
                if not m:
                    continue
                pct = float(m.group(1))
                line_lower = line.lower()
                if "discharging" in line_lower:
                    status = "discharging"
                elif "charging" in line_lower:
                    status = "charging"
                elif "charged" in line_lower or "full" in line_lower:
                    status = "full"
                else:
                    status = None
                return pct, status
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return None, None


def reset_battery_cache() -> None:
    """Сбросить кэш батареи — для тестов."""
    global _battery_cache
    _battery_cache = (0.0, (None, None))


# ---------- Сборка отчёта ----------


def _base_block_device(device: str) -> Optional[str]:
    """Извлечь имя блочного устройства из партиции: nvme0n1p2 → nvme0n1, sda1 → sda."""
    if not device.startswith("/dev/"):
        return None
    dev_name = device[5:]
    m = re.match(r"(nvme\d+n\d+)(?:p\d+)?$", dev_name)
    if m:
        return m.group(1)
    if re.match(r"(mmcblk\d+)(?:p\d+)?$", dev_name):
        m2 = re.match(r"(mmcblk\d+)", dev_name)
        return m2.group(1) if m2 else None
    m3 = re.match(r"([a-z]+)", dev_name)
    return m3.group(1) if m3 else None


def _disk_label(device: str, mount: str) -> str:
    """Определить метку диска: 'ssd', 'hdd' или короткое имя точки монтирования.

    Для блочных устройств — проверяем /sys/block/.../queue/rotational:
      0 = SSD/NVMe, 1 = HDD.
    Для неразрешимых устройств — fallback на имя точки монтирования.
    """
    if not device.startswith("/dev/"):
        return mount.replace("/", "").rstrip("/") or "disk"

    block_name = _base_block_device(device)

    if block_name:
        try:
            rot_path = Path(f"/sys/block/{block_name}/queue/rotational")
            rotational = int(rot_path.read_text().strip())
            return "ssd" if rotational == 0 else "hdd"
        except (OSError, ValueError):
            pass

    # macOS: нет /sys/block, APFS всегда на SSD
    if platform.system().lower() == "darwin":
        return "ssd"

    if mount == "/":
        return "root"
    return mount.replace("/", "").rstrip("/") or "disk"


_HW_CACHE_TTL = 5 * 60  # 5 минут
_hw_cache: tuple[float, Optional[tuple[str, Optional[str]]]] = (0.0, None)


def hardware_status() -> tuple[str, Optional[str]]:
    """(hardware_line, battery_str) с кэшем на _HW_CACHE_TTL.

    hardware_line: 'cpu=52°C load=(2.1 1.8 1.5/8) | ssd=6%(...) | nvme=45°C'
    battery_str:   'battery=78% (charging)' или None
    """
    global _hw_cache
    now = time.time()
    expires, cached = _hw_cache
    if cached is not None and now < expires:
        return cached

    hw_parts: list[str] = []

    # CPU
    temp = cpu_temp()
    ncpu = cpu_count()
    la = load_avg()
    if temp is not None:
        cpu_str = f"cpu={temp:.0f}°C"
    else:
        cpu_str = "cpu=?°C"
    cpu_str += f" load=({la}"
    if ncpu:
        cpu_str += f"/{ncpu}"
    cpu_str += ")"
    hw_parts.append(cpu_str)

    # Диски
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
            idx = label_used.get(label, 0)
            label_used[label] = idx + 1
            if d["mount"] == "/":
                suffix = "/"
            else:
                suffix = d["mount"].lstrip("/")
            final_label = f"{label}/{suffix}" if suffix else label
        else:
            final_label = label
        disk_parts.append(f"{final_label}={d['pct']}({d['used']}/{d['size']})")
    if disk_parts:
        hw_parts.append(" ".join(disk_parts))

    # Температуры дисков
    temp_parts: list[str] = []
    nvme = nvme_temp()
    if nvme is not None:
        temp_parts.append(f"nvme={nvme:.0f}°C")
    for label, t in disk_temps():
        temp_parts.append(f"{label}={t:.0f}°C")
    if temp_parts:
        hw_parts.append(" ".join(temp_parts))

    hw_line = " | ".join(hw_parts)

    # Батарея
    bat = battery()
    if bat is not None:
        bstat = battery_status()
        if bstat == "charging":
            battery_str = f"battery={bat:.0f}% (charging)"
        elif bstat == "discharging":
            battery_str = f"battery={bat:.0f}% (discharging)"
        elif bstat == "full":
            battery_str = f"battery={bat:.0f}% (full)"
        else:
            battery_str = f"battery={bat:.0f}%"
    else:
        battery_str = None

    result = (hw_line, battery_str)
    _hw_cache = (now + _HW_CACHE_TTL, result)
    return result


def reset_hardware_cache() -> None:
    """Сбросить кэш hardware_status — для тестов."""
    global _hw_cache
    _hw_cache = (0.0, None)


def system_report(
    public_ip: Optional[str] = None,
    active_server: str = "-",
    proxy_ok: bool = True,
    uptime: str = "",
    rotations_today: int = 0,
    *,
    include_identity: bool = True,
) -> str:
    """Трёхстрочный статус-отчёт.

    Использует hardware_status() для кэшируемой части.
    """
    hw_line, battery_str = hardware_status()

    lines: list[str] = []

    # ── Строка 1: идентификация + связь ──
    proxy_str = "OK" if proxy_ok else "DOWN"
    if include_identity:
        host = _short_hostname()
        if public_ip:
            id_part = f"{host} ({public_ip})"
        else:
            id_part = host
        lines.append(f"{id_part} | active: {active_server} | proxy: {proxy_str}")
    else:
        lines.append(f"active: {active_server} | proxy: {proxy_str}")

    # ── Строка 2: железо ──
    lines.append(hw_line)

    # ── Строка 3: батарея + uptime + rotations ──
    stat_parts: list[str] = []
    if battery_str is not None:
        stat_parts.append(battery_str)
    if uptime:
        stat_parts.append(f"uptime={uptime}")
    stat_parts.append(f"rotations={rotations_today}")
    lines.append(" | ".join(stat_parts))

    return "\n".join(lines)