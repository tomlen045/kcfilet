#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""kcfilet 实拍图产线：真实输出 -> macOS 窗框 + One Dark 证据图。
PIL 符号纪律同 kcxport：特殊符号改手绘，含中文行黑体、纯 ASCII 行 Menlo。
"""
import os
import sys

sys.path.insert(0, "/Users/len/CodeBuddy/dx/kcxport")
import importlib.util

spec = importlib.util.spec_from_file_location("kcxport_shots", "/Users/len/CodeBuddy/dx/kcxport/make_shots.py")
# 不能直接 exec（会跑它的 main）；手动复制核心常量与 draw_terminal 逻辑
from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "shots_src")
OUT = os.path.join(HERE, "shots")
os.makedirs(OUT, exist_ok=True)

BG = (40, 44, 52)
BAR = (33, 37, 43)
FG = (171, 178, 191)
GREEN = (152, 195, 121)
RED = (224, 108, 117)
YELLOW = (229, 192, 123)
BLUE = (97, 175, 239)
GRAY = (92, 99, 112)
WHITE = (220, 223, 228)
MENLO = "/System/Library/Fonts/Menlo.ttc"
HEITI = "/System/Library/Fonts/STHeiti Medium.ttc"


def has_cjk(s):
    return any("\u4e00" <= ch <= "\u9fff" for ch in s)


def font_for(text, size):
    return ImageFont.truetype(HEITI if has_cjk(text) else MENLO, size)


def text_w(d, text, size):
    return d.textlength(text, font=font_for(text, size))


def draw_terminal(title, lines, out_name, width=1400, pad=28):
    fs = 24
    lh = int(fs * 1.75)
    header = 52
    tmp = Image.new("RGB", (10, 10))
    td = ImageDraw.Draw(tmp)
    wrapped = []
    for item in lines:
        text, color = item[0], item[1]
        indent = item[2] if len(item) > 2 else 0
        max_w = width - pad * 2 - indent * 36
        cur = ""
        for ch in text:
            if text_w(td, cur + ch, fs) > max_w and cur:
                wrapped.append((cur, color, indent))
                cur = "  " + ch
            else:
                cur += ch
        wrapped.append((cur, color, indent))
    h = header + pad * 2 + lh * len(wrapped) + pad
    img = Image.new("RGB", (width, h), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, width, header], fill=BAR)
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([20 + i * 30, header // 2 - 8, 36 + i * 30, header // 2 + 8], fill=c)
    f_title = font_for(title, 17)
    tw = d.textlength(title, font=f_title)
    d.text(((width - tw) // 2, (header - 22) // 2 - 1), title, font=f_title, fill=GRAY)
    y = header + pad
    for text, color, indent in wrapped:
        d.text((pad + indent * 36, y), text, font=font_for(text, fs), fill=color)
        y += lh
    out = os.path.join(OUT, out_name)
    img.save(out)
    print("saved", out, img.size)


def read(name):
    return open(os.path.join(SRC, name), encoding="utf-8").read().rstrip("\n")


def main():
    # 图1：真机漂移对账（核心卖点图）
    lines = []
    for ln in read("shot1_diff.txt").splitlines():
        if "[ADD]" in ln:
            lines.append((ln, RED))
        elif "[DEL]" in ln:
            lines.append((ln, RED))
        elif "[CHG]" in ln:
            lines.append((ln, YELLOW))
        elif ln.startswith("verdict"):
            lines.append((ln, RED))
        elif "高危" in ln and "/ 中危" in ln:
            lines.append((ln, YELLOW))
        elif ln.startswith("kcfilet v"):
            lines.append((ln, WHITE))
        else:
            lines.append((ln, FG))
    draw_terminal("kcfilet diff — master realm 周一 vs 周五，5 处计划内变更全中", lines, "01_diff.png")

    # 图2：rename 识别
    lines = []
    for ln in read("shot2_rename.txt").splitlines():
        if ln.startswith("$"):
            lines.append((ln, GREEN))
        elif "<=>" in ln:
            lines.append((ln, BLUE))
        elif ln.startswith("verdict"):
            lines.append((ln, GREEN))
        elif ln.startswith("kcfilet v"):
            lines.append((ln, WHITE))
        else:
            lines.append((ln, FG))
    draw_terminal("重命名不冤枉人 — 内容一致判 <=> rename，不出删+增", lines, "02_rename.png")

    # 图3：selftest
    lines = []
    for ln in read("shot3_selftest.txt").splitlines():
        if ln.startswith("PASS"):
            lines.append((ln, GREEN))
        elif ln.startswith("FAIL"):
            lines.append((ln, RED))
        elif ln.startswith("selftest"):
            lines.append((ln, YELLOW))
        else:
            lines.append((ln, FG))
    draw_terminal("kcfilet selftest — 18 项不变量全绿才交付", lines, "03_selftest.png")

    # 图4：inventory
    lines = []
    for ln in read("shot4_inventory.txt").splitlines():
        if ln.startswith("$"):
            lines.append((ln, GREEN))
        elif "clients:" in ln:
            lines.append((ln[:150] + " …" if len(ln) > 150 else ln, BLUE))
        elif "机密类字段" in ln:
            lines.append((ln, YELLOW))
        elif ln.strip().startswith("·"):
            lines.append((ln, GRAY))
        elif ln.startswith("kcfilet v") or ln.startswith("  sha8"):
            lines.append((ln, WHITE))
        else:
            lines.append((ln, FG))
    draw_terminal("kcfilet inventory — 一份档案里到底有什么", lines, "04_inventory.png")

    # 图5：报告落盘+台账
    lines = []
    for ln in read("shot5_report.txt").splitlines():
        if ln.startswith("$"):
            lines.append((ln, GREEN))
        elif "mode=0o600" in ln or "-rw-------" in ln:
            lines.append((ln, YELLOW))
        elif ln.startswith(("ts,", "2026-")):
            lines.append((ln, BLUE))
        elif ln.startswith("report") or ln.startswith("ledger"):
            lines.append((ln, FG))
        else:
            lines.append((ln, GRAY))
    draw_terminal("报告 0600 落盘 / 台账零字段值 — 证据文件自身也要安全", lines, "05_report.png")


if __name__ == "__main__":
    main()
