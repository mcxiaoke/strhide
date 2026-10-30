#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
release.py — StrHide CLI 与 GUI 一键打包与分发脚本

功能：
1. 自动从 rust/Cargo.toml 与 gui/src-tauri/tauri.conf.json 解析版本号（支持命令行覆盖）；
2. 编译 Rust CLI (cargo build --release --features cli)；
3. 编译 Tauri v2 GUI (pnpm tauri build --no-bundle)；
4. 将 4 个 CLI 入口（全量 sth + 三个域专用 sthc/sths/sthv）与文档打包为
   release/v<version>/strhide-cli-v<version>-<platform>.zip；
5. 将 GUI 便携式独立程序与文档打包为 release/v<version>/strhide-gui-v<version>-<platform>-portable.zip；
6. 自动收集可能存在的安装包（.msi / .exe，若生成）；
7. 自动生成 SHA256SUMS.txt 完整性校验和清单。

用法示例：
  python scripts/release.py                     # 默认一次性构建并打包 CLI 和 GUI
  python scripts/release.py 0.7.4               # 指定版本号
  python scripts/release.py --cli-only          # 仅构建打包 CLI
  python scripts/release.py --gui-only          # 仅构建打包 GUI
  python scripts/release.py --skip-build        # 跳过编译，仅对已有产物打包
  python scripts/release.py --clean             # 编译前清理对应的 release 产物
  python scripts/release.py --dry-run           # 试运行，仅打印步骤
  python scripts/release.py --open              # 构建完成后打开 release 目录
"""

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

# 确保控制台支持 UTF-8 输出
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

ROOT = Path(__file__).resolve().parent.parent
RUST_DIR = ROOT / "rust"
GUI_DIR = ROOT / "gui"
GUI_TAURI_DIR = GUI_DIR / "src-tauri"

# 默认分发包公共文档
DOC_FILES = [
    ROOT / "README.md",
    ROOT / "LICENSE",
]

# 四个 CLI 入口：全量 + 三个域专用。它们由同一个 Cargo package 的多个
# [[bin]] 产出，共享 strhide lib crate，因此行为与参数定义完全一致。
CLI_EXE_STEMS = ["sth", "sthc", "sths", "sthv"]


def cli_exe_names() -> list[str]:
    """四个 CLI 入口在 target/release 下的文件名（含平台扩展名）。"""
    suffix = ".exe" if platform.system() == "Windows" else ""
    return [f"{stem}{suffix}" for stem in CLI_EXE_STEMS]


def cli_bins() -> list[Path]:
    """四个 CLI 入口的 Release 产物路径。"""
    return [RUST_DIR / "target" / "release" / name for name in cli_exe_names()]


def print_banner(text: str) -> None:
    print(f"\n{'=' * 60}\n{text}\n{'=' * 60}")


def run(cmd: str, *, cwd: Path = ROOT, dry_run: bool = False, check: bool = True) -> int:
    """在指定目录执行命令，失败时打印并抛出异常。"""
    rel = cwd.relative_to(ROOT) if cwd != ROOT else Path(".")
    print(f"[{rel}] -> {cmd}")
    if dry_run:
        return 0

    start = time.perf_counter()
    ret = subprocess.run(cmd, shell=True, cwd=str(cwd), check=False).returncode
    elapsed = time.perf_counter() - start

    if check and ret != 0:
        raise SystemExit(f"\n[ERROR] 命令执行失败 (exit code: {ret}):\n  cd {cwd} && {cmd}")
    print(f"       -> 完成 (耗时: {elapsed:.2f}s)\n")
    return ret


def detect_version() -> str:
    """从 rust/Cargo.toml 解析版本号并与前端校验。"""
    cargo_toml = RUST_DIR / "Cargo.toml"
    if not cargo_toml.exists():
        raise SystemExit(f"找不到 {cargo_toml}")

    content = cargo_toml.read_text(encoding="utf-8")
    m = re.search(r'(?m)^version\s*=\s*"([^"]+)"', content)
    if not m:
        raise SystemExit("无法从 rust/Cargo.toml 解析 version")
    version = m.group(1).strip()

    # 交叉核验 GUI 版本
    tauri_conf = GUI_TAURI_DIR / "tauri.conf.json"
    if tauri_conf.exists():
        tauri_text = tauri_conf.read_text(encoding="utf-8")
        tm = re.search(r'"version"\s*:\s*"([^"]+)"', tauri_text)
        if tm and tm.group(1).strip() != version:
            print(f"[WARN] GUI tauri.conf.json 版本 ({tm.group(1)}) 与 rust/Cargo.toml ({version}) 不一致")

    return version


def get_platform_tag() -> str:
    """获取标准平台与架构标识，如 windows-x64, linux-x64, macos-arm64。"""
    sys_name = platform.system().lower()
    machine = platform.machine().lower()

    if sys_name == "windows":
        arch = "x64" if machine in ("amd64", "x86_64") else ("arm64" if "arm" in machine else machine)
        return f"windows-{arch}"
    elif sys_name == "darwin":
        arch = "arm64" if machine in ("arm64", "aarch64") else "x64"
        return f"macos-{arch}"
    elif sys_name == "linux":
        arch = "x64" if machine in ("x86_64", "amd64") else ("arm64" if "aarch64" in machine else machine)
        return f"linux-{arch}"
    return f"{sys_name}-{machine}"


def clean_build(clean_cli: bool, clean_gui: bool, dry_run: bool) -> None:
    """清理 Release 目标产物。"""
    if clean_cli:
        for cli_bin in cli_bins():
            if cli_bin.exists():
                print(f"-> 移除已有 CLI 产物: {cli_bin}")
                if not dry_run:
                    cli_bin.unlink(missing_ok=True)

    if clean_gui:
        gui_bin = GUI_TAURI_DIR / "target" / "release" / ("strhide-gui.exe" if platform.system() == "Windows" else "strhide-gui")
        if gui_bin.exists():
            print(f"-> 移除已有 GUI 产物: {gui_bin}")
            if not dry_run:
                gui_bin.unlink(missing_ok=True)


def build_cli(dry_run: bool) -> list[Path]:
    """构建 Rust CLI Release 二进制（全量入口 + 三个域专用入口）。

    `cargo build --release --features cli` 默认会构建 package 内所有满足
    required-features 的 bin，因此四个入口一次构建即可全部产出。
    """
    print_banner("1/2 构建 Rust CLI Release 二进制（4 个入口）")
    cmd = "cargo build --release --features cli"
    run(cmd, cwd=RUST_DIR, dry_run=dry_run)

    bins = cli_bins()
    if not dry_run:
        for out_bin in bins:
            if not out_bin.exists():
                raise SystemExit(f"[ERROR] 未找到 CLI 构建产物: {out_bin}")
    return bins


def build_gui(dry_run: bool) -> Path:
    """构建 Tauri v2 GUI Release 单文件程序。"""
    print_banner("2/2 构建 Tauri v2 GUI Release 程序")
    # 先确保前端编译并打包 Tauri
    cmd = "pnpm tauri build --no-bundle"
    run(cmd, cwd=GUI_DIR, dry_run=dry_run)

    exe_name = "strhide-gui.exe" if platform.system() == "Windows" else "strhide-gui"
    out_bin = GUI_TAURI_DIR / "target" / "release" / exe_name
    if not dry_run and not out_bin.exists():
        raise SystemExit(f"[ERROR] 未找到 GUI 构建产物: {out_bin}")
    return out_bin


def package_cli(
    release_dir: Path,
    version: str,
    platform_tag: str,
    dry_run: bool,
) -> Path:
    """将 4 个 CLI 入口及必要文档打包为 zip。"""
    zip_name = f"strhide-cli-v{version}-{platform_tag}.zip"
    zip_path = release_dir / zip_name

    print(f"-> 打包 CLI 便携压缩包: {zip_name}")
    if dry_run:
        return zip_path

    bins = cli_bins()
    for src_bin in bins:
        if not src_bin.exists():
            raise SystemExit(f"[ERROR] 找不到待打包的 CLI 产物: {src_bin}")

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        # 写入全部 4 个可执行文件（全量 + 三个域专用入口）
        for src_bin in bins:
            zf.write(src_bin, arcname=src_bin.name)
        # 写入文档文件
        for doc in DOC_FILES:
            if doc.exists():
                zf.write(doc, arcname=doc.name)

    size_mb = zip_path.stat().st_size / (1024 * 1024)
    print(f"   已生成: {zip_path.name} ({size_mb:.2f} MB)")
    return zip_path


def package_gui_portable(
    release_dir: Path,
    version: str,
    platform_tag: str,
    dry_run: bool,
) -> Path:
    """将 GUI 便携式单程序及必要文档打包为 portable zip。"""
    exe_name = "strhide-gui.exe" if platform.system() == "Windows" else "strhide-gui"
    src_bin = GUI_TAURI_DIR / "target" / "release" / exe_name
    zip_name = f"strhide-gui-v{version}-{platform_tag}-portable.zip"
    zip_path = release_dir / zip_name

    print(f"-> 打包 GUI 便携版 (Portable) 压缩包: {zip_name}")
    if dry_run:
        return zip_path

    if not src_bin.exists():
        raise SystemExit(f"[ERROR] 找不到待打包的 GUI 产物: {src_bin}")

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        # 写入主可执行文件 (仅保留单一 exe，避免包内重复)
        zf.write(src_bin, arcname=exe_name)
        # 写入文档文件
        for doc in DOC_FILES:
            if doc.exists():
                zf.write(doc, arcname=doc.name)

    size_mb = zip_path.stat().st_size / (1024 * 1024)
    print(f"   已生成: {zip_path.name} ({size_mb:.2f} MB)")
    return zip_path


def collect_installers(release_dir: Path, version: str, dry_run: bool) -> list[Path]:
    """若在支持 bundle 的环境编译产出了 .msi 或 .exe 安装包，一并归档到 release 目录。"""
    bundle_dir = GUI_TAURI_DIR / "target" / "release" / "bundle"
    if not bundle_dir.exists():
        return []

    collected: list[Path] = []
    candidates = list(bundle_dir.rglob("*.msi")) + list(bundle_dir.rglob("*.exe"))
    for src in candidates:
        dst = release_dir / src.name
        print(f"-> 发现并归档安装包: {src.name}")
        if not dry_run:
            shutil.copy2(src, dst)
        collected.append(dst)
    return collected


def generate_checksums(release_dir: Path, dry_run: bool) -> Path:
    """为 release 目录下所有分发文件生成 SHA256SUMS.txt 校验清单。"""
    checksum_file = release_dir / "SHA256SUMS.txt"
    print(f"\n-> 生成 SHA-256 校验和清单: {checksum_file.name}")
    if dry_run:
        return checksum_file

    targets = sorted(
        [
            f
            for f in release_dir.iterdir()
            if f.is_file() and f.name != "SHA256SUMS.txt" and not f.name.endswith(".tmp")
        ]
    )

    lines: list[str] = []
    for f in targets:
        digest = hashlib.sha256(f.read_bytes()).hexdigest()
        lines.append(f"{digest}  {f.name}\n")
        print(f"   {digest[:12]}...  {f.name}")

    checksum_file.write_text("".join(lines), encoding="utf-8")
    return checksum_file


def main() -> None:
    parser = argparse.ArgumentParser(
        description="StrHide CLI 与 GUI 一键自动化打包发布脚本",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "version",
        nargs="?",
        default=None,
        help="目标版本号（如 0.7.4 或 v0.7.4），留空则自动从 rust/Cargo.toml 读取",
    )
    parser.add_argument("--cli-only", action="store_true", help="仅编译并打包 CLI")
    parser.add_argument("--gui-only", action="store_true", help="仅编译并打包 GUI")
    parser.add_argument("--skip-build", action="store_true", help="跳过构建编译步骤，仅对现有产物重新打包")
    parser.add_argument("--clean", action="store_true", help="构建前清理旧的 Release 二进制产物")
    parser.add_argument("--dry-run", action="store_true", help="试运行模式，仅打印步骤与输出路径")
    parser.add_argument("--open", action="store_true", help="全部构建打包完成后打开输出目录")

    args = parser.parse_args()

    # 1. 确定版本号与平台标识
    raw_version = args.version or detect_version()
    clean_version = raw_version.lstrip("v")
    platform_tag = get_platform_tag()

    # 输出目录规范：release/v<version>/
    release_dir = (ROOT / "release" / f"v{clean_version}").resolve()
    if not args.dry_run:
        release_dir.mkdir(parents=True, exist_ok=True)

    do_cli = not args.gui_only
    do_gui = not args.cli_only

    print_banner(f"StrHide 发布打包中心 (Release Packaging)\n版本: v{clean_version}  |  平台架构: {platform_tag}\n目标输出目录: {release_dir}")

    # 2. 清理（若指定）
    if args.clean and not args.skip_build:
        clean_build(clean_cli=do_cli, clean_gui=do_gui, dry_run=args.dry_run)

    # 3. 编译阶段
    if not args.skip_build:
        if do_cli:
            build_cli(dry_run=args.dry_run)
        if do_gui:
            build_gui(dry_run=args.dry_run)

    # 4. 压缩打包阶段
    print_banner("3/3 生成发布压缩包与校验清单")
    generated_files: list[Path] = []

    if do_cli:
        cli_zip = package_cli(release_dir, clean_version, platform_tag, dry_run=args.dry_run)
        generated_files.append(cli_zip)

    if do_gui:
        gui_zip = package_gui_portable(release_dir, clean_version, platform_tag, dry_run=args.dry_run)
        generated_files.append(gui_zip)
        installers = collect_installers(release_dir, clean_version, dry_run=args.dry_run)
        generated_files.extend(installers)

    # 5. 生成校验和
    sums_file = generate_checksums(release_dir, dry_run=args.dry_run)
    generated_files.append(sums_file)

    # 6. 汇总报告
    print_banner(f"发布产物打包完成！文件存放在：\n{release_dir}")
    if not args.dry_run:
        for f in release_dir.iterdir():
            if f.is_file():
                mb = f.stat().st_size / (1024 * 1024)
                if mb >= 0.01:
                    print(f"  * {f.name:<45} ({mb:.2f} MB)")
                else:
                    kb = f.stat().st_size / 1024
                    print(f"  * {f.name:<45} ({kb:.2f} KB)")

    if args.open and not args.dry_run:
        if platform.system() == "Windows":
            os.startfile(str(release_dir))
        elif platform.system() == "Darwin":
            subprocess.run(["open", str(release_dir)], check=False)
        else:
            subprocess.run(["xdg-open", str(release_dir)], check=False)


if __name__ == "__main__":
    main()
