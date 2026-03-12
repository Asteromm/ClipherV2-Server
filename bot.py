from flask import Flask
import threading
import telebot

app = Flask(__name__)

@app.route("/", methods=["GET"])
def home():
    return "salom bot ishlayapti", 200

# ======================================
# BOT
TOKEN = "8748829205:AAEHYZCog9mQG8twA0tF0O2OmzC2Iea1bQ8"

bot = telebot.TeleBot(TOKEN)
# ======================================
# Botni kodlari
"""
CipherBot v2 — Telegram-бот для кодирования, декодирования и автоопределения текстовых форматов.
Улучшения по сравнению с v1:
  * Типизированные фабрики CallbackData (без магического парсинга строк)
  * Постраничные меню форматов (FORMATS_PER_PAGE на страницу)
  * Хлебные крошки на каждом экране
  * ThrottlingMiddleware (1 запрос/сек на пользователя, сброс + уведомление)
  * Быстрый доступ к недавним форматам (последние 3, хранятся в FSM)
  * 4 новых формата: Base58, фонетический NATO, Tap Code, столбцовая перестановка
  * Команда /find для поиска формата по ключевому слову
  * Улучшенное автоопределение с оценкой читаемости после декодирования
  * Чистая FSM: без дублирующихся хендлеров, поток pending_text встроен
"""

from __future__ import annotations

import asyncio
import base64
import io
import logging
import os
import re
import string
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Callable, Awaitable
from urllib.parse import quote, unquote

from aiogram import BaseMiddleware, Bot, Dispatcher, F, Router
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramBadRequest
from aiogram.filters import Command, CommandStart, StateFilter
from aiogram.filters.callback_data import CallbackData
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import (
    BufferedInputFile,
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
    TelegramObject,
)
from dotenv import load_dotenv

# ===============================================================================
# CONFIG & LOGGING
# ===============================================================================

load_dotenv()
BOT_TOKEN: str = os.environ["BOT_TOKEN"]

MAX_MESSAGE_LEN  = 4000
MAX_INPUT_LEN    = 10_000
FORMATS_PER_PAGE = 6
RECENT_MAX       = 3
THROTTLE_RATE    = 1.0   # minimum seconds between updates per user

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("cipherbot")

# ===============================================================================
# TYPED CALLBACK DATA FACTORIES
# ===============================================================================

class NavCB(CallbackData, prefix="nav"):
    action: str        # main | cancel | help

class MenuCB(CallbackData, prefix="menu"):
    action: str        # encode | decode | detect | formats | find_encode | find_decode

class CatCB(CallbackData, prefix="cat"):
    mode: str
    cat: str

class FmtCB(CallbackData, prefix="fmt"):
    mode: str
    name: str

class FmtPageCB(CallbackData, prefix="fpage"):
    mode: str
    cat: str
    page: int

class DetectPickCB(CallbackData, prefix="dpick"):
    fmt: str

class RepeatCB(CallbackData, prefix="repeat"):
    mode: str
    fmt: str

class FmtDirCB(CallbackData, prefix="fdir"):
    cat: str

class FindFmtCB(CallbackData, prefix="find"):
    mode: str
    name: str

class RecentFmtCB(CallbackData, prefix="recent"):
    mode: str
    name: str

# ===============================================================================
# FORMAT METADATA REGISTRY
# ===============================================================================

@dataclass
class FormatMeta:
    name: str
    display: str
    category: str           # base | classical | symbol | other
    short_desc: str
    requires_key: bool = False
    requires_shift: bool = False
    requires_rails: bool = False
    requires_alphabet: bool = False
    supports_encode: bool = True
    supports_decode: bool = True
    key_hint: str = ""


FORMATS: list[FormatMeta] = [
    # Base Encodings
    FormatMeta("binary",         "Бинарный",       "base", "0/1 для каждого Unicode-символа"),
    FormatMeta("ternary",        "Троичный",       "base", "Система счисления base-3 для каждого символа"),
    FormatMeta("decimal_ascii",  "Decimal ASCII",  "base", "Десятичные кодовые точки"),
    FormatMeta("hexadecimal",    "Шестнадцатеричный", "base", "Шестнадцатеричные кодовые точки (через пробел)"),
    FormatMeta("octal",          "Восьмеричный",   "base", "Восьмеричные кодовые точки"),
    FormatMeta("base16",         "Base16",         "base", "Base16 / байты RFC 4648"),
    FormatMeta("base32",         "Base32",         "base", "Base32 / байты RFC 4648"),
    FormatMeta("base58",         "Base58",         "base", "Base58 в стиле Bitcoin"),
    FormatMeta("base64",         "Base64",         "base", "Base64 / байты RFC 4648"),
    FormatMeta("base85",         "Base85/Ascii85", "base", "Байты Base85"),
    FormatMeta("url_encode",     "URL-кодирование", "base", "Процентное кодирование"),
    FormatMeta("unicode_escape", "Unicode Escape", "base", "\\uXXXX / \\UXXXXXXXX"),
    # Classical Ciphers
    FormatMeta("rot13",      "ROT13",                "classical", "Сдвиг букв на 13"),
    FormatMeta("caesar",     "Цезарь",               "classical", "Сдвиг на N",
               requires_shift=True, key_hint="целое число, например 3 или -5"),
    FormatMeta("caesar_bf",  "Цезарь Brute-Force",   "classical", "Все 25 сдвигов сразу",
               supports_encode=False),
    FormatMeta("atbash",     "Атбаш",                "classical", "Зеркальная замена A-Z"),
    FormatMeta("vigenere",   "Виженер",              "classical", "Полиалфавитный шифр",
               requires_key=True, key_hint="только буквы, например SECRET"),
    FormatMeta("bacon",      "Бэкон",                "classical", "5-битный алфавит A/B"),
    FormatMeta("rail_fence", "Rail Fence",           "classical", "Зигзагообразная перестановка",
               requires_rails=True, key_hint="целое число >= 2"),
    FormatMeta("columnar",   "Столбцовая перестановка","classical","Шифр перестановки по столбцам",
               requires_key=True, key_hint="ключевое слово из букв, например ZEBRA"),
    FormatMeta("simple_sub", "Простая замена",       "classical", "Ключевой алфавит из 26 символов",
               requires_alphabet=True,
               key_hint="26 уникальных букв, например QWERTYUIOPASDFGHJKLZXCVBNM"),
    # Symbol Systems
    FormatMeta("morse",    "Азбука Морзе",    "symbol", "Международный стандарт точек и тире"),
    FormatMeta("nato",     "Фонетический NATO", "symbol", "Alpha Bravo Charlie..."),
    FormatMeta("tap_code", "Tap Code",      "symbol", "Тюремный стуковый шифр (квадрат Полибия 5x5)"),
    FormatMeta("leetspeak","Leetspeak",     "symbol", "1337 5p34k"),
    FormatMeta("a1z26",    "A1Z26",         "symbol", "A=1 ... Z=26"),
    # Other
    FormatMeta("reverse",  "Текст наоборот", "other", "Разворот порядка символов"),
    FormatMeta("xor",      "XOR",          "other", "XOR с ключом -> hex-вывод",
               requires_key=True, key_hint="любой текстовый ключ"),
]

FORMAT_MAP: dict[str, FormatMeta] = {f.name: f for f in FORMATS}

CATEGORIES: dict[str, str] = {
    "base":      "Базовые кодировки",
    "classical": "Классические шифры",
    "symbol":    "Символьные системы",
    "other":     "Другое",
}

CAT_EMOJI: dict[str, str] = {
    "base": "📦", "classical": "🏺", "symbol": "🔣", "other": "🔀",
}

# ===============================================================================
# ALPHABETS / MAPPINGS
# ===============================================================================

MORSE_ENC: dict[str, str] = {
    'A':'.-','B':'-...','C':'-.-.','D':'-..','E':'.','F':'..-.','G':'--.','H':'....','I':'..','J':'.---',
    'K':'-.-','L':'.-..','M':'--','N':'-.','O':'---','P':'.--.','Q':'--.-','R':'.-.','S':'...','T':'-',
    'U':'..-','V':'...-','W':'.--','X':'-..-','Y':'-.--','Z':'--..',
    '0':'-----','1':'.----','2':'..---','3':'...--','4':'....-','5':'.....','6':'-....','7':'--...',
    '8':'---..','9':'----.',
    '.':'.-.-.-',',':'--..--','?':'..--..','!':'-.-.--','-':'-....-','/':'-..-.',
    '(':'-.--.',')':"-.--.-","'":".----.",'"':'.-..-.','@':'.--.-.','&':'.-...','=':'-...-',
}
MORSE_DEC: dict[str, str] = {v: k for k, v in MORSE_ENC.items()}

NATO_ENC: dict[str, str] = {
    'A':'Alpha','B':'Bravo','C':'Charlie','D':'Delta','E':'Echo','F':'Foxtrot',
    'G':'Golf','H':'Hotel','I':'India','J':'Juliett','K':'Kilo','L':'Lima',
    'M':'Mike','N':'November','O':'Oscar','P':'Papa','Q':'Quebec','R':'Romeo',
    'S':'Sierra','T':'Tango','U':'Uniform','V':'Victor','W':'Whiskey',
    'X':'X-ray','Y':'Yankee','Z':'Zulu',
    '0':'Zero','1':'One','2':'Two','3':'Three','4':'Four',
    '5':'Five','6':'Six','7':'Seven','8':'Eight','9':'Nine',
}
NATO_DEC: dict[str, str] = {v.lower(): k for k, v in NATO_ENC.items()}

# Tap Code: 5x5 Polybius square, C=K
_TAP_ROWS = ["ABCDE", "FGHIJ", "LMNOP", "QRSTU", "VWXYZ"]
TAP_ENC: dict[str, str] = {}
TAP_DEC: dict[str, str] = {}
for _r, _row in enumerate(_TAP_ROWS):
    for _c, _ch in enumerate(_row):
        _code = f"{_r+1} {_c+1}"
        TAP_ENC[_ch] = _code
        TAP_DEC[_code] = _ch
TAP_ENC["K"] = TAP_ENC["C"]

BACON_ENC: dict[str, str] = {
    'A':'AAAAA','B':'AAAAB','C':'AAABA','D':'AAABB','E':'AABAA',
    'F':'AABAB','G':'AABBA','H':'AABBB','I':'ABAAA','J':'ABAAA',
    'K':'ABAAB','L':'ABABA','M':'ABABB','N':'ABBAA','O':'ABBAB',
    'P':'ABBBA','Q':'ABBBB','R':'BAAAA','S':'BAAAB','T':'BAABA',
    'U':'BAABB','V':'BAABB','W':'BABAA','X':'BABAB','Y':'BABBA','Z':'BABBB',
}
BACON_DEC: dict[str, str] = {}
for _ch, _code in BACON_ENC.items():
    if _code not in BACON_DEC:
        BACON_DEC[_code] = _ch

LEET_ENC: dict[str, str] = {
    'a':'4','e':'3','g':'9','i':'1','l':'1','o':'0','s':'5','t':'7','b':'8','z':'2',
    'A':'4','E':'3','G':'9','I':'1','L':'1','O':'0','S':'5','T':'7','B':'8','Z':'2',
}
LEET_DEC: dict[str, str] = {
    '4':'a','3':'e','9':'g','1':'i','0':'o','5':'s','7':'t','8':'b','2':'z',
}

BASE58_ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_MAP   = {ch: i for i, ch in enumerate(BASE58_ALPHA)}

# ===============================================================================
# ENCODE / DECODE FUNCTIONS
# ===============================================================================

# -- helpers --

def _utf8(text: str) -> bytes:
    return text.encode("utf-8")

def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def _printable_ratio(text: str) -> float:
    if not text: return 0.0
    return sum(1 for c in text if c.isprintable()) / len(text)

def _letter_ratio(text: str) -> float:
    if not text: return 0.0
    return sum(1 for c in text if c.isalpha()) / len(text)

_COMMON_WORDS = frozenset(
    "the be to of and a in that have it for on with he as you do at this his "
    "by from they we say her she or an will my one all would there their what "
    "so up out if about who get which go me when make can like time no just him "
    "know take people into year your good some could them see other than then "
    "now look only come its over think also back after use two how our work first "
    "well way even new want because any these give day most us is are was were "
    "been has had did not but by at from hello world hi dear message secret".split()
)

def _word_score(text: str) -> float:
    words = re.findall(r"[a-zA-Z]{3,}", text.lower())
    if not words: return 0.0
    hits = sum(1 for w in words if w in _COMMON_WORDS)
    return min(1.0, hits / max(1, len(words)) * 2)

def _readability(text: str | None) -> float:
    if not text: return 0.0
    return _printable_ratio(text) * 0.3 + _letter_ratio(text) * 0.3 + _word_score(text) * 0.4

# -- Binary --

def encode_binary(text: str) -> str:
    return " ".join(format(ord(c), "b") for c in text)

def decode_binary(text: str) -> str:
    parts = text.strip().split()
    try:
        return "".join(chr(int(p, 2)) for p in parts)
    except ValueError as e:
        raise ValueError("Некорректная бинарная последовательность.") from e

# -- Ternary --

def _to_base3(n: int) -> str:
    if n == 0: return "0"
    d: list[str] = []
    while n:
        n, r = divmod(n, 3)
        d.append(str(r))
    return "".join(reversed(d))

def encode_ternary(text: str) -> str:
    return " ".join(_to_base3(ord(c)) for c in text)

def decode_ternary(text: str) -> str:
    try:
        return "".join(chr(int(p, 3)) for p in text.strip().split())
    except ValueError as e:
        raise ValueError("Некорректная троичная последовательность.") from e

# -- Decimal ASCII --

def encode_decimal_ascii(text: str) -> str:
    return " ".join(str(ord(c)) for c in text)

def decode_decimal_ascii(text: str) -> str:
    try:
        return "".join(chr(int(p)) for p in text.strip().split())
    except (ValueError, OverflowError) as e:
        raise ValueError("Некорректная десятичная последовательность.") from e

# -- Hexadecimal --

def encode_hexadecimal(text: str) -> str:
    return " ".join(format(ord(c), "x") for c in text)

def decode_hexadecimal(text: str) -> str:
    try:
        return "".join(chr(int(p, 16)) for p in text.strip().split())
    except ValueError as e:
        raise ValueError("Некорректная шестнадцатеричная последовательность.") from e

# -- Octal --

def encode_octal(text: str) -> str:
    return " ".join(format(ord(c), "o") for c in text)

def decode_octal(text: str) -> str:
    try:
        return "".join(chr(int(p, 8)) for p in text.strip().split())
    except ValueError as e:
        raise ValueError("Некорректная восьмеричная последовательность.") from e

# -- Base16 --

def encode_base16(text: str) -> str:
    return base64.b16encode(_utf8(text)).decode("ascii")

def decode_base16(text: str) -> str:
    try:
        return base64.b16decode(text.upper()).decode("utf-8")
    except Exception as e:
        raise ValueError("Некорректные данные Base16.") from e

# -- Base32 --

def encode_base32(text: str) -> str:
    return base64.b32encode(_utf8(text)).decode("ascii")

def decode_base32(text: str) -> str:
    try:
        p = text.upper()
        rem = len(p) % 8
        if rem: p += "=" * (8 - rem)
        return base64.b32decode(p).decode("utf-8")
    except Exception as e:
        raise ValueError("Некорректные данные Base32.") from e

# -- Base58 --

def encode_base58(text: str) -> str:
    data = _utf8(text)
    n = int.from_bytes(data, "big")
    result: list[str] = []
    while n > 0:
        n, r = divmod(n, 58)
        result.append(BASE58_ALPHA[r])
    leading = len(data) - len(data.lstrip(b"\x00"))
    return "1" * leading + "".join(reversed(result))

def decode_base58(text: str) -> str:
    text = text.strip()
    n = 0
    for ch in text:
        if ch not in BASE58_MAP:
            raise ValueError(f"Недопустимый символ Base58: {ch!r}")
        n = n * 58 + BASE58_MAP[ch]
    result: list[int] = []
    while n > 0:
        n, r = divmod(n, 256)
        result.append(r)
    leading = len(text) - len(text.lstrip("1"))
    raw = bytes([0] * leading + list(reversed(result)))
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError("Декодированные байты не являются корректным UTF-8.") from e

# -- Base64 --

def encode_base64(text: str) -> str:
    return base64.b64encode(_utf8(text)).decode("ascii")

def decode_base64(text: str) -> str:
    try:
        p = text.strip().replace("\n", "")
        rem = len(p) % 4
        if rem: p += "=" * (4 - rem)
        return base64.b64decode(p).decode("utf-8")
    except Exception as e:
        raise ValueError("Некорректные данные Base64.") from e

# -- Base85 --

def encode_base85(text: str) -> str:
    return base64.b85encode(_utf8(text)).decode("ascii")

def decode_base85(text: str) -> str:
    try:
        return base64.b85decode(text.strip()).decode("utf-8")
    except Exception as e:
        raise ValueError("Некорректные данные Base85.") from e

# -- URL Encode --

def encode_url(text: str) -> str:
    return quote(text, safe="")

def decode_url(text: str) -> str:
    try:
        return unquote(text, errors="strict")
    except Exception as e:
        raise ValueError("Некорректные URL-кодированные данные.") from e

# -- Unicode Escape --

def encode_unicode_escape(text: str) -> str:
    result = []
    for ch in text:
        cp = ord(ch)
        if cp > 0xFFFF:
            result.append(f"\\U{cp:08X}")
        elif cp > 0x7F:
            result.append(f"\\u{cp:04X}")
        else:
            result.append(ch)
    return "".join(result)

def decode_unicode_escape(text: str) -> str:
    try:
        return text.encode("raw_unicode_escape").decode("unicode_escape")
    except Exception as e:
        raise ValueError("Некорректная escape-последовательность Unicode.") from e

# -- Reverse --

def encode_reverse(text: str) -> str: return text[::-1]
def decode_reverse(text: str) -> str: return text[::-1]

# -- ROT13 --

def encode_rot13(text: str) -> str:
    return text.translate(str.maketrans(
        string.ascii_lowercase + string.ascii_uppercase,
        string.ascii_lowercase[13:] + string.ascii_lowercase[:13] +
        string.ascii_uppercase[13:] + string.ascii_uppercase[:13],
    ))

def decode_rot13(text: str) -> str:
    return encode_rot13(text)

# -- Caesar --

def _caesar_shift(text: str, shift: int) -> str:
    shift = shift % 26
    return text.translate(str.maketrans(
        string.ascii_lowercase + string.ascii_uppercase,
        string.ascii_lowercase[shift:] + string.ascii_lowercase[:shift] +
        string.ascii_uppercase[shift:] + string.ascii_uppercase[:shift],
    ))

def encode_caesar(text: str, shift: int) -> str: return _caesar_shift(text, shift)
def decode_caesar(text: str, shift: int) -> str: return _caesar_shift(text, -shift)

def decode_caesar_bruteforce(text: str) -> list[tuple[int, str]]:
    return [(s, _caesar_shift(text, -s)) for s in range(1, 26)]

# -- Atbash --

def encode_atbash(text: str) -> str:
    return text.translate(str.maketrans(
        string.ascii_lowercase + string.ascii_uppercase,
        string.ascii_lowercase[::-1] + string.ascii_uppercase[::-1],
    ))

def decode_atbash(text: str) -> str: return encode_atbash(text)

# -- Vigenere --

def _vigenere(text: str, key: str, encode: bool) -> str:
    key = re.sub(r"[^a-zA-Z]", "", key).upper()
    if not key: raise ValueError("Ключ должен содержать хотя бы одну букву.")
    result, ki = [], 0
    for ch in text:
        if ch.isalpha():
            shift = ord(key[ki % len(key)]) - ord("A")
            base  = ord("A") if ch.isupper() else ord("a")
            delta = shift if encode else -shift
            result.append(chr((ord(ch) - base + delta) % 26 + base))
            ki += 1
        else:
            result.append(ch)
    return "".join(result)

def encode_vigenere(text: str, key: str) -> str: return _vigenere(text, key, True)
def decode_vigenere(text: str, key: str) -> str: return _vigenere(text, key, False)

# -- Bacon --

def encode_bacon(text: str) -> str:
    result = []
    for ch in text.upper():
        if ch in BACON_ENC:  result.append(BACON_ENC[ch])
        elif ch == " ":      result.append(" ")
        else:                result.append(f"[{ch}]")
    return " ".join(result)

def decode_bacon(text: str) -> str:
    text = text.replace("  ", " SPACE ").strip()
    result = []
    for token in text.split():
        if re.match(r"^\[.\]$", token):  result.append(token[1])
        elif token == "SPACE":           result.append(" ")
        elif re.match(r"^[AB]{5}$", token): result.append(BACON_DEC.get(token, "?"))
        else: result.append(f"?[{token}]")
    return "".join(result)

# -- Rail Fence --

def encode_rail_fence(text: str, rails: int) -> str:
    if rails < 2: raise ValueError("Количество рельс должно быть не меньше 2.")
    if rails >= len(text): return text
    fence: list[list[str]] = [[] for _ in range(rails)]
    rail, direction = 0, 1
    for ch in text:
        fence[rail].append(ch)
        if rail == 0: direction = 1
        elif rail == rails - 1: direction = -1
        rail += direction
    return "".join("".join(r) for r in fence)

def decode_rail_fence(text: str, rails: int) -> str:
    if rails < 2: raise ValueError("Количество рельс должно быть не меньше 2.")
    n = len(text)
    if rails >= n: return text
    indices: list[int] = []
    rail, direction = 0, 1
    for _ in range(n):
        indices.append(rail)
        if rail == 0: direction = 1
        elif rail == rails - 1: direction = -1
        rail += direction
    order = sorted(range(n), key=lambda i: indices[i])
    result = [""] * n
    for pos, ch in zip(order, text):
        result[pos] = ch
    return "".join(result)

# -- Columnar Transposition --

def _col_order(key: str) -> list[int]:
    return sorted(range(len(key)), key=lambda i: (key[i], i))

def encode_columnar(text: str, key: str) -> str:
    key = re.sub(r"[^a-zA-Z]", "", key).upper()
    if len(key) < 2: raise ValueError("Ключ для столбцовой перестановки должен содержать минимум 2 буквы.")
    n = len(key)
    plain = re.sub(r"\s", "", text)
    while len(plain) % n: plain += "X"
    order = _col_order(key)
    cols = ["".join(plain[i + r * n] for r in range(len(plain) // n)) for i in order]
    return " ".join(cols)

def decode_columnar(text: str, key: str) -> str:
    key = re.sub(r"[^a-zA-Z]", "", key).upper()
    if len(key) < 2: raise ValueError("Ключ для столбцовой перестановки должен содержать минимум 2 буквы.")
    cols = text.split()
    if len(cols) != len(key):
        raise ValueError(
            f"Ожидалось {len(key)} групп столбцов (= длина ключа), но получено {len(cols)}. "
            "Используйте тот же ключ, что и при кодировании, и передавайте группы столбцов через пробел."
        )
    n_rows = len(cols[0])
    if not all(len(c) == n_rows for c in cols):
        raise ValueError("Все группы столбцов должны быть одинаковой длины.")
    order  = _col_order(key)
    result = [""] * (n_rows * len(key))
    for out_idx, col_data in zip(order, cols):
        for row, ch in enumerate(col_data):
            result[row * len(key) + out_idx] = ch
    return "".join(result)

# -- Morse --

def encode_morse(text: str) -> str:
    result = []
    for ch in text.upper():
        if ch == " ":        result.append("/")
        elif ch in MORSE_ENC: result.append(MORSE_ENC[ch])
        else:                result.append(f"[{ch}]")
    return " ".join(result)

def decode_morse(text: str) -> str:
    text = re.sub(r"\s*/\s*", " / ", text.strip())
    parts, result = text.split(" / "), []
    for part in parts:
        if not part: result.append(" "); continue
        decoded_word = []
        for token in part.split():
            if token in MORSE_DEC:          decoded_word.append(MORSE_DEC[token])
            elif re.match(r"^\[.\]$", token): decoded_word.append(token[1])
            else:                            decoded_word.append(f"?[{token}]")
        result.append("".join(decoded_word))
    return " ".join(result)

# -- NATO Phonetic --

def encode_nato(text: str) -> str:
    result = []
    for ch in text.upper():
        if ch in NATO_ENC:  result.append(NATO_ENC[ch])
        elif ch == " ":     result.append("[space]")
        else:               result.append(f"[{ch}]")
    return " | ".join(result)

def decode_nato(text: str) -> str:
    result = []
    for token in re.split(r"\s*\|\s*", text.strip()):
        token = token.strip().lower()
        if token == "[space]":             result.append(" ")
        elif re.match(r"^\[.\]$", token): result.append(token[1].upper())
        elif token in NATO_DEC:            result.append(NATO_DEC[token])
        else:                              result.append(f"?[{token}]")
    return "".join(result)

# -- Tap Code --

def encode_tap(text: str) -> str:
    result = []
    for ch in text.upper():
        if ch == "K":        result.append(TAP_ENC["C"] + "(K)")
        elif ch in TAP_ENC:  result.append(TAP_ENC[ch])
        elif ch == " ":      result.append("/")
        else:                result.append(f"[{ch}]")
    return " | ".join(result)

def decode_tap(text: str) -> str:
    result = []
    for token in re.split(r"\s*\|\s*", text.strip()):
        token = token.strip()
        if token == "/":
            result.append(" ")
        elif re.match(r"^\[.\]$", token):
            result.append(token[1])
        elif "(K)" in token:
            result.append("K")
        elif re.fullmatch(r"[1-5] [1-5]", token):
            result.append(TAP_DEC.get(token, f"?[{token}]"))
        else:
            result.append(f"?[{token}]")
    return "".join(result)

# -- Leetspeak --

def encode_leet(text: str) -> str: return "".join(LEET_ENC.get(c, c) for c in text)
def decode_leet(text: str) -> str: return "".join(LEET_DEC.get(c, c) for c in text)

# -- A1Z26 --

def encode_a1z26(text: str) -> str:
    result = []
    for ch in text.upper():
        if "A" <= ch <= "Z": result.append(str(ord(ch) - ord("A") + 1))
        elif ch == " ":      result.append("/")
        else:                result.append(f"[{ch}]")
    return " ".join(result)

def decode_a1z26(text: str) -> str:
    result = []
    for token in text.split():
        if token == "/": result.append(" ")
        elif re.match(r"^\[.\]$", token): result.append(token[1])
        else:
            try:
                n = int(token)
                result.append(chr(n + ord("A") - 1) if 1 <= n <= 26 else f"?[{token}]")
            except ValueError:
                result.append(f"?[{token}]")
    return "".join(result)

# -- XOR --

def encode_xor(text: str, key: str) -> str:
    if not key: raise ValueError("XOR-ключ не может быть пустым.")
    tb, kb = _utf8(text), _utf8(key)
    return bytes(b ^ kb[i % len(kb)] for i, b in enumerate(tb)).hex()

def decode_xor(text: str, key: str) -> str:
    if not key: raise ValueError("XOR-ключ не может быть пустым.")
    try:
        xored = bytes.fromhex(text.strip())
    except ValueError as e:
        raise ValueError("Вход для XOR должен быть hex-строкой (как после кодирования).") from e
    kb = _utf8(key)
    result = bytes(b ^ kb[i % len(kb)] for i, b in enumerate(xored))
    try:
        return result.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError("Декодированные байты не являются корректным UTF-8 — проверьте ключ.") from e

# -- Simple Substitution --

def _validate_sub_alpha(alphabet: str) -> str:
    clean = alphabet.upper()
    if len(clean) != 26:
        raise ValueError("Алфавит замены должен содержать ровно 26 символов.")
    if not all(c in string.ascii_uppercase for c in clean):
        raise ValueError("В алфавите замены допускаются только латинские буквы.")
    if len(set(clean)) != 26:
        raise ValueError("Алфавит замены не должен содержать повторяющиеся буквы.")
    return clean

def encode_simple_sub(text: str, alphabet: str) -> str:
    a = _validate_sub_alpha(alphabet)
    return text.translate(str.maketrans(
        string.ascii_uppercase + string.ascii_lowercase,
        a + a.lower(),
    ))

def decode_simple_sub(text: str, alphabet: str) -> str:
    a = _validate_sub_alpha(alphabet)
    return text.translate(str.maketrans(
        a + a.lower(),
        string.ascii_uppercase + string.ascii_lowercase,
    ))

# ===============================================================================
# CENTRAL DISPATCH
# ===============================================================================

def dispatch_encode(fmt: str, text: str, params: dict[str, Any]) -> str:
    match fmt:
        case "binary":         return encode_binary(text)
        case "ternary":        return encode_ternary(text)
        case "decimal_ascii":  return encode_decimal_ascii(text)
        case "hexadecimal":    return encode_hexadecimal(text)
        case "octal":          return encode_octal(text)
        case "base16":         return encode_base16(text)
        case "base32":         return encode_base32(text)
        case "base58":         return encode_base58(text)
        case "base64":         return encode_base64(text)
        case "base85":         return encode_base85(text)
        case "url_encode":     return encode_url(text)
        case "unicode_escape": return encode_unicode_escape(text)
        case "reverse":        return encode_reverse(text)
        case "rot13":          return encode_rot13(text)
        case "caesar":         return encode_caesar(text, int(params["shift"]))
        case "atbash":         return encode_atbash(text)
        case "vigenere":       return encode_vigenere(text, params["key"])
        case "bacon":          return encode_bacon(text)
        case "rail_fence":     return encode_rail_fence(text, int(params["rails"]))
        case "columnar":       return encode_columnar(text, params["key"])
        case "simple_sub":     return encode_simple_sub(text, params["alphabet"])
        case "morse":          return encode_morse(text)
        case "nato":           return encode_nato(text)
        case "tap_code":       return encode_tap(text)
        case "leetspeak":      return encode_leet(text)
        case "a1z26":          return encode_a1z26(text)
        case "xor":            return encode_xor(text, params["key"])
        case _: raise ValueError(f"Неизвестный формат: {fmt}")


def dispatch_decode(fmt: str, text: str, params: dict[str, Any]) -> str:
    match fmt:
        case "binary":         return decode_binary(text)
        case "ternary":        return decode_ternary(text)
        case "decimal_ascii":  return decode_decimal_ascii(text)
        case "hexadecimal":    return decode_hexadecimal(text)
        case "octal":          return decode_octal(text)
        case "base16":         return decode_base16(text)
        case "base32":         return decode_base32(text)
        case "base58":         return decode_base58(text)
        case "base64":         return decode_base64(text)
        case "base85":         return decode_base85(text)
        case "url_encode":     return decode_url(text)
        case "unicode_escape": return decode_unicode_escape(text)
        case "reverse":        return decode_reverse(text)
        case "rot13":          return decode_rot13(text)
        case "caesar":         return decode_caesar(text, int(params["shift"]))
        case "atbash":         return decode_atbash(text)
        case "vigenere":       return decode_vigenere(text, params["key"])
        case "bacon":          return decode_bacon(text)
        case "rail_fence":     return decode_rail_fence(text, int(params["rails"]))
        case "columnar":       return decode_columnar(text, params["key"])
        case "simple_sub":     return decode_simple_sub(text, params["alphabet"])
        case "morse":          return decode_morse(text)
        case "nato":           return decode_nato(text)
        case "tap_code":       return decode_tap(text)
        case "leetspeak":      return decode_leet(text)
        case "a1z26":          return decode_a1z26(text)
        case "xor":            return decode_xor(text, params["key"])
        case _: raise ValueError(f"Неизвестный формат: {fmt}")

# ===============================================================================
# HEURISTICS / AUTO-DETECT ENGINE
# ===============================================================================

@dataclass
class Candidate:
    format: str
    score: float
    reason: str
    decoded: str | None = None

def _clamp(v: float) -> float: return max(0.0, min(1.0, v))

def _try_decode(fmt: str, text: str, params: dict | None = None) -> str | None:
    try:
        return dispatch_decode(fmt, text, params or {})
    except Exception:
        return None


def auto_detect(text: str) -> list[Candidate]:
    candidates: list[Candidate] = []
    s = text.strip()
    tokens = s.split()

    def _add(fmt: str, base: float, reason: str, decoded: str | None = None) -> None:
        score = base
        if decoded:
            score += _readability(decoded) * 0.20
        candidates.append(Candidate(fmt, _clamp(score), reason, decoded))

    # Binary
    if re.fullmatch(r"[01]+(\s[01]+)*", s):
        _add("binary", 0.80, "только группы 0/1", _try_decode("binary", s))

    # Ternary
    if re.fullmatch(r"[012]+(\s[012]+)*", s) and "2" in s:
        _add("ternary", 0.65, "только группы 0/1/2", _try_decode("ternary", s))

    # Octal
    if re.fullmatch(r"[0-7]+(\s[0-7]+)*", s) and re.search(r"[3-7]", s):
        _add("octal", 0.60, "только группы 0-7", _try_decode("octal", s))

    # Decimal ASCII
    if tokens and all(re.fullmatch(r"\d+", t) for t in tokens):
        nums = [int(t) for t in tokens]
        if all(0 <= n <= 0x10FFFF for n in nums):
            _add("decimal_ascii", 0.55, "десятичные кодовые точки", _try_decode("decimal_ascii", s))

    # A1Z26
    if tokens and all(re.fullmatch(r"\d+", t) or t == "/" for t in tokens):
        only_nums = [int(t) for t in tokens if t != "/"]
        if only_nums and all(1 <= n <= 26 for n in only_nums):
            _add("a1z26", 0.72, "числа 1-26 с разделителями слов /", _try_decode("a1z26", s))

    # Hex / Base16
    if re.fullmatch(r"[0-9a-fA-F]+(\s[0-9a-fA-F]+)*", s):
        _add("hexadecimal", 0.55, "hex-токены", _try_decode("hexadecimal", s))
        if " " not in s and len(s) % 2 == 0:
            _add("base16", 0.62, "hex-строка чётной длины", _try_decode("base16", s))

    # Base32
    if re.fullmatch(r"[A-Z2-7=]+", s.upper()) and len(s) >= 8:
        _add("base32", 0.65, "набор символов Base32 A-Z 2-7", _try_decode("base32", s))

    # Base64
    b64c = s.replace("\n", "").replace(" ", "")
    if re.fullmatch(r"[A-Za-z0-9+/=]+", b64c) and len(b64c) >= 4 and len(b64c) % 4 == 0:
        _add("base64", 0.72, "набор символов Base64, len%4==0", _try_decode("base64", b64c))

    # Base58
    if re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]+", s) and len(s) >= 6:
        _add("base58", 0.50, "корректный набор символов Base58", _try_decode("base58", s))

    # Base85
    if re.fullmatch(r"[!-u]+", s) and len(s) >= 5:
        _add("base85", 0.45, "символы в диапазоне Base85", _try_decode("base85", s))

    # URL Encode
    if "%" in s and re.search(r"%[0-9A-Fa-f]{2}", s):
        _add("url_encode", 0.84, "процентно-кодированные последовательности", _try_decode("url_encode", s))

    # Unicode Escape
    if re.search(r"\\u[0-9A-Fa-f]{4}|\\U[0-9A-Fa-f]{8}|\\x[0-9A-Fa-f]{2}", s):
        _add("unicode_escape", 0.88, r"шаблоны \uXXXX", _try_decode("unicode_escape", s))

    # Morse
    if re.fullmatch(r"[.\-/ ]+", s) and ("." in s or "-" in s):
        _add("morse", 0.78, "структура точек/тире/слешей", _try_decode("morse", s))

    # NATO Phonetic
    parts_lower = [p.strip().lower() for p in re.split(r"\s*\|\s*", s)]
    nato_hits   = sum(1 for p in parts_lower if p in NATO_DEC or p == "[space]")
    if len(parts_lower) >= 2 and nato_hits / len(parts_lower) > 0.7:
        _add("nato", 0.75, "фонетические слова NATO с |", _try_decode("nato", s))

    # Tap Code
    tap_parts = [p.strip() for p in re.split(r"\s*\|\s*", s)]
    tap_hits  = sum(1 for p in tap_parts if re.fullmatch(r"[1-5] [1-5]", p) or p in ("/", ""))
    if len(tap_parts) >= 2 and tap_hits / len(tap_parts) > 0.7:
        _add("tap_code", 0.73, "пары Tap Code 5x5 с |", _try_decode("tap_code", s))

    # Classical text transforms (only when text looks like readable text)
    if _letter_ratio(s) > 0.55:
        rot13_d = encode_rot13(s)
        ws_r = _word_score(rot13_d)
        if ws_r > 0.25:
            _add("rot13", 0.48 + ws_r * 0.42, "правдоподобный результат ROT13", rot13_d)

        atbash_d = encode_atbash(s)
        ws_a = _word_score(atbash_d)
        if ws_a > 0.25:
            _add("atbash", 0.38 + ws_a * 0.42, "правдоподобный результат Атбаша", atbash_d)

        best_shift = max(range(1, 26), key=lambda sh: _word_score(_caesar_shift(s, -sh)))
        best_dec   = _caesar_shift(s, -best_shift)
        ws_c = _word_score(best_dec)
        if ws_c > 0.20:
            _add("caesar", 0.33 + ws_c * 0.50, f"вероятный сдвиг Цезаря={best_shift}", best_dec)

    # Deduplicate: keep highest score per format
    seen: dict[str, Candidate] = {}
    for c in candidates:
        if c.format not in seen or c.score > seen[c.format].score:
            seen[c.format] = c

    return sorted(seen.values(), key=lambda c: c.score, reverse=True)

# ===============================================================================
# THROTTLING MIDDLEWARE
# ===============================================================================

class ThrottlingMiddleware(BaseMiddleware):
    """Simple rate limiter: 1 request per THROTTLE_RATE seconds per user."""

    def __init__(self, rate: float = THROTTLE_RATE) -> None:
        self._last: dict[int, float] = defaultdict(float)
        self._rate = rate

    async def __call__(
        self,
        handler: Callable[[TelegramObject, dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: dict[str, Any],
    ) -> Any:
        user_id: int | None = None
        if isinstance(event, Message) and event.from_user:
            user_id = event.from_user.id
        elif isinstance(event, CallbackQuery) and event.from_user:
            user_id = event.from_user.id

        if user_id is not None:
            now     = time.monotonic()
            elapsed = now - self._last[user_id]
            if elapsed < self._rate:
                if isinstance(event, CallbackQuery):
                    try:
                        await event.answer("Не так быстро...", show_alert=False)
                    except Exception:
                        pass
                return  # drop silently
            self._last[user_id] = now

        return await handler(event, data)

# ===============================================================================
# FSM STATES
# ===============================================================================

class EncodeState(StatesGroup):
    choose_category = State()
    choose_format   = State()
    wait_shift      = State()
    wait_key        = State()
    wait_rails      = State()
    wait_alphabet   = State()
    wait_text       = State()

class DecodeState(StatesGroup):
    choose_category = State()
    choose_format   = State()
    wait_shift      = State()
    wait_key        = State()
    wait_rails      = State()
    wait_alphabet   = State()
    wait_text       = State()

class AutoDetectState(StatesGroup):
    wait_text     = State()
    choose_format = State()

class FindState(StatesGroup):
    wait_query = State()

# ===============================================================================
# KEYBOARD BUILDERS
# ===============================================================================

def _btn(text: str, cb: CallbackData) -> InlineKeyboardButton:
    return InlineKeyboardButton(text=text, callback_data=cb.pack())

def kb_main() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [_btn("🔐 Кодировать",      MenuCB(action="encode")),
         _btn("🔓 Декодировать",      MenuCB(action="decode"))],
        [_btn("🧠 Автоопределение", MenuCB(action="detect"))],
        [_btn("📚 Форматы",     MenuCB(action="formats")),
         _btn("ℹ️ Помощь",         NavCB(action="help"))],
    ])

def kb_categories(mode: str, recent: list[str] | None = None) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    if recent:
        fmts = [FORMAT_MAP[n] for n in recent if n in FORMAT_MAP]
        if fmts:
            rows.append([_btn(
                f"🕐 {f.display}", RecentFmtCB(mode=mode, name=f.name)
            ) for f in fmts])
    for cat_key, cat_label in CATEGORIES.items():
        rows.append([_btn(f"{CAT_EMOJI[cat_key]} {cat_label}", CatCB(mode=mode, cat=cat_key))])
    rows.append([
        _btn("🔍 Найти формат", MenuCB(action=f"find_{mode}")),
        _btn("🏠 Главное меню",   NavCB(action="main")),
    ])
    return InlineKeyboardMarkup(inline_keyboard=rows)

def kb_formats(mode: str, category: str, page: int = 0) -> InlineKeyboardMarkup:
    eligible = [
        f for f in FORMATS
        if f.category == category
        and (mode != "encode" or f.supports_encode)
        and (mode != "decode" or f.supports_decode)
    ]
    total_pages = max(1, (len(eligible) + FORMATS_PER_PAGE - 1) // FORMATS_PER_PAGE)
    page = max(0, min(page, total_pages - 1))
    chunk = eligible[page * FORMATS_PER_PAGE:(page + 1) * FORMATS_PER_PAGE]

    rows: list[list[InlineKeyboardButton]] = []
    for fmt in chunk:
        lock = "🔑" if (fmt.requires_key or fmt.requires_shift or fmt.requires_rails or fmt.requires_alphabet) else ""
        rows.append([_btn(f"{lock}{fmt.display}" if lock else fmt.display, FmtCB(mode=mode, name=fmt.name))])

    pag_row = []
    if page > 0:
        pag_row.append(_btn("◀️ Назад", FmtPageCB(mode=mode, cat=category, page=page - 1)))
    if total_pages > 1:
        pag_row.append(InlineKeyboardButton(
            text=f"Страница {page+1}/{total_pages}", callback_data="noop"))
    if page < total_pages - 1:
        pag_row.append(_btn("Далее ▶️", FmtPageCB(mode=mode, cat=category, page=page + 1)))
    if pag_row:
        rows.append(pag_row)

    rows.append([
        _btn("⬅️ Назад",      CatCB(mode=mode, cat=category)),
        _btn("🏠 Главное меню", NavCB(action="main")),
    ])
    return InlineKeyboardMarkup(inline_keyboard=rows)

def kb_detect_candidates(candidates: list[Candidate]) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    for c in candidates[:5]:
        pct  = int(c.score * 100)
        name = FORMAT_MAP[c.format].display if c.format in FORMAT_MAP else c.format
        rows.append([_btn(f"{name}  —  {pct}%", DetectPickCB(fmt=c.format))])
    rows.append([
        _btn("🔁 Повторить", MenuCB(action="detect")),
        _btn("🏠 Главное меню", NavCB(action="main")),
    ])
    return InlineKeyboardMarkup(inline_keyboard=rows)

def kb_after_result(mode: str, fmt_name: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            _btn("🔁 Повтор",        RepeatCB(mode=mode, fmt=fmt_name)),
            _btn("🔄 Сменить формат", MenuCB(action=mode)),
        ],
        [_btn("🏠 Главное меню", NavCB(action="main"))],
    ])

def kb_cancel_only() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [_btn("❌ Отмена", NavCB(action="cancel"))]
    ])

def kb_formats_directory() -> InlineKeyboardMarkup:
    rows = [
        [_btn(f"{CAT_EMOJI[cat]} {label}", FmtDirCB(cat=cat))]
        for cat, label in CATEGORIES.items()
    ]
    rows.append([_btn("🏠 Главное меню", NavCB(action="main"))])
    return InlineKeyboardMarkup(inline_keyboard=rows)

# ===============================================================================
# TEXT TEMPLATES & HELPERS
# ===============================================================================

WELCOME_TEXT = (
    "👋 <b>Добро пожаловать в CipherBot!</b>\n\n"
    "Я умею кодировать, декодировать и автоматически определять <b>27 форматов</b>, включая классические шифры, "
    "базовые кодировки, символьные системы и не только.\n\n"
    "Используйте кнопки или введите команду:\n"
    "<code>/encode</code>  <code>/decode</code>  "
    "<code>/detect</code>  <code>/find</code>  <code>/formats</code>"
)

HELP_TEXT = (
    "ℹ️ <b>Помощь по CipherBot</b>\n\n"
    "<b>Команды:</b>\n"
    "/start — приветствие + главное меню\n"
    "/encode — закодировать текст\n"
    "/decode — декодировать текст\n"
    "/detect — автоопределение и декодирование\n"
    "/formats — просмотр всех форматов\n"
    "/find — поиск формата по ключевому слову\n"
    "/cancel — отмена и возврат назад\n\n"
    "<b>Режимы:</b>\n"
    "• <b>Кодирование</b> — обычный текст → закодированная форма\n"
    "• <b>Декодирование</b> — закодированная форма → обычный текст\n"
    "• <b>Автоопределение</b> — вставьте что угодно, я сам определю формат\n\n"
    "<b>Навигация:</b>\n"
    "• <b>⬅️ Назад</b> — на один шаг назад\n"
    "• <b>🏠 Главное меню</b> — начать заново\n"
    "• <b>🕐 Недавние</b> — последние 3 использованных формата показываются сверху\n"
    "• <b>🔍 Найти формат</b> — поиск по ключевому слову\n"
    "• Форматы, которым нужен ключ/сдвиг, отмечены значком 🔑\n\n"
    "<b>Совет:</b> очень длинные результаты отправляются как .txt-файлы"
)

def _fmt_info(fmt: FormatMeta) -> str:
    lines = [f"<b>{fmt.display}</b>", f"<i>{fmt.short_desc}</i>"]
    if fmt.requires_key:      lines.append(f"🔑 Ключ: {fmt.key_hint}")
    if fmt.requires_shift:    lines.append(f"🔢 Сдвиг: {fmt.key_hint}")
    if fmt.requires_rails:    lines.append(f"🛤 Рельсы: {fmt.key_hint}")
    if fmt.requires_alphabet: lines.append(f"🔡 Алфавит: {fmt.key_hint}")
    enc_dec = []
    if fmt.supports_encode: enc_dec.append("✅ Кодирование")
    if fmt.supports_decode: enc_dec.append("✅ Декодирование")
    lines.append(" | ".join(enc_dec))
    return "\n".join(lines)

def _breadcrumb(mode_emoji: str, mode_label: str, fmt_label: str = "") -> str:
    parts = [f"{mode_emoji} <b>{mode_label}</b>"]
    if fmt_label: parts.append(f"<b>{fmt_label}</b>")
    return " › ".join(parts)

def _result_msg(mode: str, fmt_display: str, input_text: str, result: str) -> str:
    emoji = "🔐" if mode == "encode" else "🔓"
    label = "Кодирование" if mode == "encode" else "Декодирование"
    preview = _esc(input_text[:300]) + ("..." if len(input_text) > 300 else "")
    return (
        f"{_breadcrumb(emoji, label, fmt_display)}\n\n"
        f"<b>Вход:</b>\n<code>{preview}</code>\n\n"
        f"<b>Результат:</b>\n<code>{_esc(result)}</code>"
    )

# ===============================================================================
# SAFE SEND HELPERS
# ===============================================================================

async def send_long(
    message: Message,
    text: str,
    reply_markup: InlineKeyboardMarkup | None = None,
) -> None:
    if len(text) <= MAX_MESSAGE_LEN:
        await message.answer(text, parse_mode=ParseMode.HTML, reply_markup=reply_markup)
        return
    buf = io.BytesIO(text.encode("utf-8"))
    await message.answer_document(
        document=BufferedInputFile(buf.getvalue(), filename="result.txt"),
        caption="📄 Результат слишком длинный — отправлен файлом.",
        reply_markup=reply_markup,
    )

async def edit_or_send(
    query: CallbackQuery,
    text: str,
    reply_markup: InlineKeyboardMarkup | None = None,
) -> None:
    try:
        await query.message.edit_text(text, parse_mode=ParseMode.HTML, reply_markup=reply_markup)
    except TelegramBadRequest:
        await query.message.answer(text, parse_mode=ParseMode.HTML, reply_markup=reply_markup)

# ===============================================================================
# RECENT FORMATS
# ===============================================================================

async def _push_recent(state: FSMContext, mode: str, fmt_name: str) -> None:
    data   = await state.get_data()
    key    = f"recent_{mode}"
    recent: list[str] = list(data.get(key, []))
    if fmt_name in recent: recent.remove(fmt_name)
    recent.insert(0, fmt_name)
    await state.update_data({key: recent[:RECENT_MAX]})

async def _get_recent(state: FSMContext, mode: str) -> list[str]:
    data = await state.get_data()
    return list(data.get(f"recent_{mode}", []))

# ===============================================================================
# INPUT VALIDATION
# ===============================================================================

def _check_input(text: str) -> str | None:
    if not text.strip():    return "❌ Отправьте непустой текст."
    if len(text) > MAX_INPUT_LEN: return f"❌ Текст слишком длинный (максимум {MAX_INPUT_LEN:,} символов)."
    return None

# ===============================================================================
# ROUTER
# ===============================================================================

router = Router()

# ===============================================================================
# COMMAND HANDLERS
# ===============================================================================

@router.message(CommandStart())
async def cmd_start(message: Message, state: FSMContext) -> None:
    await state.clear()
    await message.answer(WELCOME_TEXT, parse_mode=ParseMode.HTML, reply_markup=kb_main())

@router.message(Command("help"))
async def cmd_help(message: Message) -> None:
    await message.answer(HELP_TEXT, parse_mode=ParseMode.HTML, reply_markup=kb_main())

@router.message(Command("cancel"))
async def cmd_cancel(message: Message, state: FSMContext) -> None:
    await state.clear()
    await message.answer(
        "❌ <b>Отменено.</b> Возврат в главное меню.",
        parse_mode=ParseMode.HTML, reply_markup=kb_main())

@router.message(Command("encode"))
async def cmd_encode(message: Message, state: FSMContext) -> None:
    await _start_mode_msg(message, state, "encode")

@router.message(Command("decode"))
async def cmd_decode(message: Message, state: FSMContext) -> None:
    await _start_mode_msg(message, state, "decode")

@router.message(Command("detect"))
async def cmd_detect(message: Message, state: FSMContext) -> None:
    await state.clear()
    await state.set_state(AutoDetectState.wait_text)
    await message.answer(
        "🧠 <b>Автоопределение</b>\n\nВставьте любой закодированный текст, и я определю формат:",
        parse_mode=ParseMode.HTML, reply_markup=kb_cancel_only())

@router.message(Command("formats"))
async def cmd_formats(message: Message) -> None:
    await message.answer(
        "📚 <b>Каталог форматов</b>\n\nВыберите категорию:",
        parse_mode=ParseMode.HTML, reply_markup=kb_formats_directory())

@router.message(Command("find"))
async def cmd_find(message: Message, state: FSMContext) -> None:
    await state.clear()
    await state.set_state(FindState.wait_query)
    await message.answer(
        "🔍 <b>Найти формат</b>\n\nВведите ключевое слово "
        "(например, <code>base64</code>, <code>morse</code>, <code>caesar</code>):",
        parse_mode=ParseMode.HTML, reply_markup=kb_cancel_only())

# ===============================================================================
# FIND HANDLER
# ===============================================================================

@router.message(FindState.wait_query)
async def find_handler(message: Message, state: FSMContext) -> None:
    query = (message.text or "").strip().lower()
    if not query:
        await message.answer("❌ Пустой запрос.", reply_markup=kb_cancel_only()); return

    results = [
        f for f in FORMATS
        if query in f.name.lower() or query in f.display.lower() or query in f.short_desc.lower()
    ]
    await state.clear()

    if not results:
        await message.answer(
            f"🔍 Форматы по запросу <code>{_esc(query)}</code> не найдены. Попробуйте другое ключевое слово.",
            parse_mode=ParseMode.HTML, reply_markup=kb_main()); return

    lines = [f"🔍 <b>Результаты для</b> <code>{_esc(query)}</code>:\n"]
    for f in results:
        lines.append(_fmt_info(f))
        lines.append("")

    rows: list[list[InlineKeyboardButton]] = []
    for f in results[:4]:
        btns: list[InlineKeyboardButton] = []
        if f.supports_encode:
            btns.append(_btn(f"🔐 {f.display}", FindFmtCB(mode="encode", name=f.name)))
        if f.supports_decode:
            btns.append(_btn(f"🔓 {f.display}", FindFmtCB(mode="decode", name=f.name)))
        if btns: rows.append(btns)
    rows.append([_btn("🏠 Главное меню", NavCB(action="main"))])

    text = "\n".join(lines).strip()
    if len(text) > MAX_MESSAGE_LEN:
        await message.answer_document(
            document=BufferedInputFile(text.encode(), filename="search_results.txt"),
            caption=f"Результаты для '{query}' (отправлены файлом)",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=rows))
    else:
        await message.answer(text, parse_mode=ParseMode.HTML,
                             reply_markup=InlineKeyboardMarkup(inline_keyboard=rows))

@router.callback_query(FindFmtCB.filter())
async def cb_find_fmt(query: CallbackQuery, callback_data: FindFmtCB, state: FSMContext) -> None:
    await query.answer()
    await state.clear()
    await state.update_data(mode=callback_data.mode, fmt=callback_data.name, params={})
    await _start_fmt_flow(query, state, callback_data.mode, callback_data.name)

# ===============================================================================
# NAVIGATION CALLBACKS
# ===============================================================================

@router.callback_query(NavCB.filter(F.action == "main"))
async def cb_nav_main(query: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    await query.answer()
    await edit_or_send(query, WELCOME_TEXT, kb_main())

@router.callback_query(NavCB.filter(F.action == "cancel"))
async def cb_nav_cancel(query: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    await query.answer("Отменено.")
    await edit_or_send(query, "❌ <b>Отменено.</b> Возврат в главное меню.", kb_main())

@router.callback_query(NavCB.filter(F.action == "help"))
async def cb_nav_help(query: CallbackQuery) -> None:
    await query.answer()
    await edit_or_send(query, HELP_TEXT, kb_main())

# ===============================================================================
# MENU ACTION CALLBACKS
# ===============================================================================

@router.callback_query(MenuCB.filter(F.action == "encode"))
async def cb_menu_encode(query: CallbackQuery, state: FSMContext) -> None:
    await query.answer()
    await _start_mode_query(query, state, "encode")

@router.callback_query(MenuCB.filter(F.action == "decode"))
async def cb_menu_decode(query: CallbackQuery, state: FSMContext) -> None:
    await query.answer()
    await _start_mode_query(query, state, "decode")

@router.callback_query(MenuCB.filter(F.action == "detect"))
async def cb_menu_detect(query: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    await state.set_state(AutoDetectState.wait_text)
    await query.answer()
    await edit_or_send(
        query,
        "🧠 <b>Автоопределение</b>\n\nВставьте любой закодированный текст, и я определю формат:",
        kb_cancel_only())

@router.callback_query(MenuCB.filter(F.action == "formats"))
async def cb_menu_formats(query: CallbackQuery) -> None:
    await query.answer()
    await edit_or_send(query, "📚 <b>Каталог форматов</b>\n\nВыберите категорию:", kb_formats_directory())

@router.callback_query(MenuCB.filter(F.action.startswith("find_")))
async def cb_menu_find(query: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    await state.set_state(FindState.wait_query)
    await query.answer()
    await edit_or_send(query, "🔍 <b>Найти формат</b>\n\nВведите ключевое слово:", kb_cancel_only())

# ===============================================================================
# FORMAT DIRECTORY CALLBACKS
# ===============================================================================

@router.callback_query(FmtDirCB.filter())
async def cb_fmtdir(query: CallbackQuery, callback_data: FmtDirCB) -> None:
    cat_key = callback_data.cat
    await query.answer()
    text = (
        f"📚 <b>{CAT_EMOJI[cat_key]} {CATEGORIES[cat_key]}</b>\n\n"
        + "\n\n".join(_fmt_info(f) for f in FORMATS if f.category == cat_key)
    )
    back_kb = InlineKeyboardMarkup(inline_keyboard=[
        [_btn("⬅️ Назад",      MenuCB(action="formats")),
         _btn("🏠 Главное меню", NavCB(action="main"))],
    ])
    if len(text) > MAX_MESSAGE_LEN:
        await query.message.answer_document(
            document=BufferedInputFile(text.encode(), filename=f"{cat_key}_formats.txt"),
            caption=f"{CATEGORIES[cat_key]} — список форматов",
            reply_markup=back_kb)
    else:
        await edit_or_send(query, text, back_kb)

# ===============================================================================
# CATEGORY CALLBACKS
# ===============================================================================

@router.callback_query(CatCB.filter())
async def cb_category(query: CallbackQuery, callback_data: CatCB, state: FSMContext) -> None:
    mode, cat = callback_data.mode, callback_data.cat
    await state.update_data(mode=mode, category=cat)
    if mode == "encode": await state.set_state(EncodeState.choose_format)
    else:                await state.set_state(DecodeState.choose_format)
    await query.answer()
    emoji = "🔐" if mode == "encode" else "🔓"
    label = "Кодирование" if mode == "encode" else "Декодирование"
    text  = (
        f"{_breadcrumb(emoji, label)}\n"
        f"{CAT_EMOJI[cat]} <b>{CATEGORIES[cat]}</b>\n\n"
        "Выберите формат:"
    )
    await edit_or_send(query, text, kb_formats(mode, cat, page=0))

@router.callback_query(FmtPageCB.filter())
async def cb_fmt_page(query: CallbackQuery, callback_data: FmtPageCB) -> None:
    mode, cat, page = callback_data.mode, callback_data.cat, callback_data.page
    await query.answer()
    emoji = "🔐" if mode == "encode" else "🔓"
    label = "Кодирование" if mode == "encode" else "Декодирование"
    text  = (
        f"{_breadcrumb(emoji, label)}\n"
        f"{CAT_EMOJI[cat]} <b>{CATEGORIES[cat]}</b>\n\n"
        "Выберите формат:"
    )
    await edit_or_send(query, text, kb_formats(mode, cat, page=page))

# ===============================================================================
# RECENT FORMAT CALLBACK
# ===============================================================================

@router.callback_query(RecentFmtCB.filter())
async def cb_recent_fmt(query: CallbackQuery, callback_data: RecentFmtCB, state: FSMContext) -> None:
    mode, fmt_name = callback_data.mode, callback_data.name
    await state.update_data(mode=mode, fmt=fmt_name, params={})
    await query.answer()
    await _start_fmt_flow(query, state, mode, fmt_name)

# ===============================================================================
# FORMAT SELECTION CALLBACK
# ===============================================================================

@router.callback_query(FmtCB.filter())
async def cb_format_chosen(query: CallbackQuery, callback_data: FmtCB, state: FSMContext) -> None:
    mode, fmt_name = callback_data.mode, callback_data.name
    if fmt_name not in FORMAT_MAP:
        await query.answer("Неизвестный формат.", show_alert=True); return
    await state.update_data(mode=mode, fmt=fmt_name, params={})
    await query.answer()
    await _start_fmt_flow(query, state, mode, fmt_name)

# ===============================================================================
# REPEAT CALLBACK
# ===============================================================================

@router.callback_query(RepeatCB.filter())
async def cb_repeat(query: CallbackQuery, callback_data: RepeatCB, state: FSMContext) -> None:
    mode, fmt_name = callback_data.mode, callback_data.fmt
    fmt = FORMAT_MAP.get(fmt_name)
    if not fmt:
        await query.answer("Неизвестный формат.", show_alert=True); return
    await query.answer()
    if mode == "encode": await state.set_state(EncodeState.wait_text)
    else:                await state.set_state(DecodeState.wait_text)
    emoji = "🔐" if mode == "encode" else "🔓"
    label = "Кодирование" if mode == "encode" else "Декодирование"
    await edit_or_send(
        query,
        f"{_breadcrumb(emoji, label, fmt.display)}\n\nОтправьте текст (параметры сохранены):",
        kb_cancel_only())

# ===============================================================================
# FLOW STARTERS
# ===============================================================================

async def _start_mode_msg(message: Message, state: FSMContext, mode: str) -> None:
    recent = await _get_recent(state, mode)
    await state.clear()
    await state.update_data(mode=mode)
    if mode == "encode": await state.set_state(EncodeState.choose_category)
    else:                await state.set_state(DecodeState.choose_category)
    emoji = "🔐" if mode == "encode" else "🔓"
    label = "Кодирование" if mode == "encode" else "Декодирование"
    await message.answer(
        f"{emoji} <b>Режим: {label}</b>\n\nВыберите категорию:",
        parse_mode=ParseMode.HTML,
        reply_markup=kb_categories(mode, recent))

async def _start_mode_query(query: CallbackQuery, state: FSMContext, mode: str) -> None:
    recent = await _get_recent(state, mode)
    await state.clear()
    await state.update_data(mode=mode)
    if mode == "encode": await state.set_state(EncodeState.choose_category)
    else:                await state.set_state(DecodeState.choose_category)
    emoji = "🔐" if mode == "encode" else "🔓"
    label = "Кодирование" if mode == "encode" else "Декодирование"
    await edit_or_send(
        query,
        f"{emoji} <b>Режим: {label}</b>\n\nВыберите категорию:",
        kb_categories(mode, recent))

async def _start_fmt_flow(
    query: CallbackQuery,
    state: FSMContext,
    mode: str,
    fmt_name: str,
) -> None:
    fmt = FORMAT_MAP[fmt_name]
    emoji = "🔐" if mode == "encode" else "🔓"
    label = "Кодирование" if mode == "encode" else "Декодирование"
    crumb = _breadcrumb(emoji, label, fmt.display)

    if fmt_name == "caesar_bf":
        if mode == "encode":
            await query.answer("Caesar Brute-Force доступен только для декодирования.", show_alert=True)
            return
        await state.set_state(DecodeState.wait_text)
        await edit_or_send(
            query,
            f"{crumb}\n\nОтправьте шифротекст — я покажу все 25 сдвигов.",
            kb_cancel_only())
        return

    if fmt.requires_shift:
        st = EncodeState.wait_shift if mode == "encode" else DecodeState.wait_shift
        await state.set_state(st)
        await edit_or_send(
            query,
            f"{crumb}\n\nВведите сдвиг (целое число, например <code>3</code> или <code>-7</code>):",
            kb_cancel_only())
        return

    if fmt.requires_key:
        st = EncodeState.wait_key if mode == "encode" else DecodeState.wait_key
        await state.set_state(st)
        await edit_or_send(query, f"{crumb}\n\nВведите ключ ({fmt.key_hint}):", kb_cancel_only())
        return

    if fmt.requires_rails:
        st = EncodeState.wait_rails if mode == "encode" else DecodeState.wait_rails
        await state.set_state(st)
        await edit_or_send(
            query,
            f"{crumb}\n\nВведите количество рельс (целое число >= 2):",
            kb_cancel_only())
        return

    if fmt.requires_alphabet:
        st = EncodeState.wait_alphabet if mode == "encode" else DecodeState.wait_alphabet
        await state.set_state(st)
        await edit_or_send(
            query,
            f"{crumb}\n\nВведите алфавит замены из 26 символов:\n"
            "Пример: <code>QWERTYUIOPASDFGHJKLZXCVBNM</code>",
            kb_cancel_only())
        return

    st = EncodeState.wait_text if mode == "encode" else DecodeState.wait_text
    await state.set_state(st)
    await edit_or_send(query, f"{crumb}\n\nОтправьте текст:", kb_cancel_only())

# ===============================================================================
# PARAM INPUT HANDLERS
# ===============================================================================

async def _handle_shift(message: Message, state: FSMContext, mode: str) -> None:
    data  = await state.get_data()
    fmt   = FORMAT_MAP.get(data.get("fmt", ""))
    crumb = _breadcrumb("🔐" if mode == "encode" else "🔓",
                        "Кодирование" if mode == "encode" else "Декодирование",
                        fmt.display if fmt else "")
    try:
        shift = int((message.text or "").strip())
    except ValueError:
        await message.answer(
            f"{crumb}\n\n❌ Введите целое число (например, <code>3</code> или <code>-5</code>).",
            parse_mode=ParseMode.HTML, reply_markup=kb_cancel_only()); return
    params = data.get("params", {})
    params["shift"] = shift
    await state.update_data(params=params)
    st = EncodeState.wait_text if mode == "encode" else DecodeState.wait_text
    await state.set_state(st)
    await message.answer(
        f"{crumb}\n\n✅ Сдвиг = <b>{shift}</b>. Теперь отправьте текст:",
        parse_mode=ParseMode.HTML, reply_markup=kb_cancel_only())

@router.message(EncodeState.wait_shift)
async def enc_wait_shift(message: Message, state: FSMContext) -> None:
    await _handle_shift(message, state, "encode")

@router.message(DecodeState.wait_shift)
async def dec_wait_shift(message: Message, state: FSMContext) -> None:
    await _handle_shift(message, state, "decode")


async def _handle_key(message: Message, state: FSMContext, mode: str) -> None:
    key = (message.text or "").strip()
    if not key:
        await message.answer("❌ Ключ не может быть пустым.", reply_markup=kb_cancel_only()); return
    data   = await state.get_data()
    fmt    = FORMAT_MAP.get(data.get("fmt", ""))
    params = data.get("params", {})
    params["key"] = key
    await state.update_data(params=params)
    st = EncodeState.wait_text if mode == "encode" else DecodeState.wait_text
    await state.set_state(st)
    crumb = _breadcrumb("🔐" if mode == "encode" else "🔓",
                        "Кодирование" if mode == "encode" else "Декодирование",
                        fmt.display if fmt else "")
    await message.answer(
        f"{crumb}\n\n✅ Ключ сохранён. Теперь отправьте текст:",
        parse_mode=ParseMode.HTML, reply_markup=kb_cancel_only())

@router.message(EncodeState.wait_key)
async def enc_wait_key(message: Message, state: FSMContext) -> None:
    await _handle_key(message, state, "encode")

@router.message(DecodeState.wait_key)
async def dec_wait_key(message: Message, state: FSMContext) -> None:
    await _handle_key(message, state, "decode")


async def _handle_rails(message: Message, state: FSMContext, mode: str) -> None:
    try:
        rails = int((message.text or "").strip())
        if rails < 2: raise ValueError
    except ValueError:
        await message.answer("❌ Введите целое число >= 2.", reply_markup=kb_cancel_only()); return
    data   = await state.get_data()
    params = data.get("params", {})
    params["rails"] = rails
    await state.update_data(params=params)
    st = EncodeState.wait_text if mode == "encode" else DecodeState.wait_text
    await state.set_state(st)
    await message.answer(
        f"✅ Количество рельс = <b>{rails}</b>. Теперь отправьте текст:",
        parse_mode=ParseMode.HTML, reply_markup=kb_cancel_only())

@router.message(EncodeState.wait_rails)
async def enc_wait_rails(message: Message, state: FSMContext) -> None:
    await _handle_rails(message, state, "encode")

@router.message(DecodeState.wait_rails)
async def dec_wait_rails(message: Message, state: FSMContext) -> None:
    await _handle_rails(message, state, "decode")


async def _handle_alphabet(message: Message, state: FSMContext, mode: str) -> None:
    alphabet = (message.text or "").strip().upper()
    try:
        _validate_sub_alpha(alphabet)
    except ValueError as exc:
        await message.answer(
            f"❌ {exc}\n\nExample: <code>QWERTYUIOPASDFGHJKLZXCVBNM</code>",
            parse_mode=ParseMode.HTML, reply_markup=kb_cancel_only()); return
    data   = await state.get_data()
    params = data.get("params", {})
    params["alphabet"] = alphabet
    await state.update_data(params=params)
    st = EncodeState.wait_text if mode == "encode" else DecodeState.wait_text
    await state.set_state(st)
    await message.answer(
        "✅ Алфавит сохранён. Теперь отправьте текст:",
        parse_mode=ParseMode.HTML, reply_markup=kb_cancel_only())

@router.message(EncodeState.wait_alphabet)
async def enc_wait_alphabet(message: Message, state: FSMContext) -> None:
    await _handle_alphabet(message, state, "encode")

@router.message(DecodeState.wait_alphabet)
async def dec_wait_alphabet(message: Message, state: FSMContext) -> None:
    await _handle_alphabet(message, state, "decode")

# ===============================================================================
# CORE TEXT HANDLERS — ENCODE
# ===============================================================================

@router.message(EncodeState.wait_text)
async def enc_wait_text(message: Message, state: FSMContext) -> None:
    text = message.text or ""
    err = _check_input(text)
    if err:
        await message.answer(err, reply_markup=kb_cancel_only()); return

    data     = await state.get_data()
    fmt_name = data.get("fmt", "")
    params   = data.get("params", {})
    fmt      = FORMAT_MAP.get(fmt_name)
    if not fmt:
        await state.clear()
        await message.answer("❌ Формат не выбран. Пожалуйста, начните заново.", reply_markup=kb_main())
        return

    try:
        result = dispatch_encode(fmt_name, text, params)
    except ValueError as exc:
        await message.answer(
            f"❌ <b>Ошибка кодирования:</b> {_esc(str(exc))}",
            parse_mode=ParseMode.HTML, reply_markup=kb_after_result("encode", fmt_name))
        return

    await _push_recent(state, "encode", fmt_name)
    await send_long(message, _result_msg("encode", fmt.display, text, result),
                    kb_after_result("encode", fmt_name))

# ===============================================================================
# CORE TEXT HANDLERS — DECODE
# ===============================================================================

async def _run_decode(message: Message, state: FSMContext, input_text: str) -> None:
    data     = await state.get_data()
    fmt_name = data.get("fmt", "")
    params   = data.get("params", {})
    fmt      = FORMAT_MAP.get(fmt_name)
    if not fmt:
        await state.clear()
        await message.answer("❌ Формат не выбран. Пожалуйста, начните заново.", reply_markup=kb_main())
        return

    if fmt_name == "caesar_bf":
        shifts = decode_caesar_bruteforce(input_text)
        lines  = ["🔓 <b>Caesar Brute-Force</b> — все 25 сдвигов:\n"]
        for s, dec in shifts:
            lines.append(f"<b>+{s:02d}:</b> <code>{_esc(dec[:120])}</code>")
        await _push_recent(state, "decode", "caesar_bf")
        await send_long(message, "\n".join(lines), kb_after_result("decode", "caesar_bf"))
        return

    try:
        result = dispatch_decode(fmt_name, input_text, params)
    except ValueError as exc:
        await message.answer(
            f"❌ <b>Ошибка декодирования:</b> {_esc(str(exc))}\n\nПроверьте входные данные и попробуйте снова.",
            parse_mode=ParseMode.HTML, reply_markup=kb_after_result("decode", fmt_name))
        return

    await _push_recent(state, "decode", fmt_name)
    await send_long(message, _result_msg("decode", fmt.display, input_text, result),
                    kb_after_result("decode", fmt_name))


@router.message(DecodeState.wait_text)
async def dec_wait_text(message: Message, state: FSMContext) -> None:
    data    = await state.get_data()
    pending: str | None = data.get("pending_text")
    if pending:
        await state.update_data(pending_text=None)
        await _run_decode(message, state, pending)
        return
    text = message.text or ""
    err  = _check_input(text)
    if err:
        await message.answer(err, reply_markup=kb_cancel_only()); return
    await _run_decode(message, state, text)

# ===============================================================================
# AUTO-DETECT HANDLERS
# ===============================================================================

@router.message(AutoDetectState.wait_text)
async def detect_input(message: Message, state: FSMContext) -> None:
    text = message.text or ""
    err  = _check_input(text)
    if err:
        await message.answer(err, reply_markup=kb_cancel_only()); return

    candidates = auto_detect(text)

    if not candidates:
        await state.clear()
        await message.answer(
            "🧠 <b>Результат автоопределения</b>\n\n"
            "Не найдено ни одного известного шаблона кодирования. "
            "Попробуйте режим кодирования/декодирования и выберите формат вручную.",
            parse_mode=ParseMode.HTML, reply_markup=kb_main())
        return

    top = candidates[0]

    if top.score >= 0.85 and top.decoded:
        name = FORMAT_MAP[top.format].display if top.format in FORMAT_MAP else top.format
        msg  = (
            f"🧠 <b>Автоопределение завершено</b>\n\n"
            f"<b>Формат:</b> {name}  —  {int(top.score * 100)}%\n"
            f"<i>{top.reason}</i>\n\n"
            f"<b>Декодировано:</b>\n<code>{_esc(top.decoded)}</code>"
        )
        await _push_recent(state, "decode", top.format)
        await state.clear()
        await send_long(message, msg, kb_after_result("decode", top.format))
        return

    await state.update_data(detect_text=text)
    await state.set_state(AutoDetectState.choose_format)

    lines = ["🧠 <b>Результат автоопределения</b>\n\n<b>Лучшие варианты:</b>"]
    for c in candidates[:5]:
        fn = FORMAT_MAP[c.format].display if c.format in FORMAT_MAP else c.format
        lines.append(f"• <b>{fn}</b>  —  {int(c.score * 100)}%\n  <i>{c.reason}</i>")
    lines.append("\nВыберите формат для декодирования:")

    await message.answer(
        "\n".join(lines),
        parse_mode=ParseMode.HTML,
        reply_markup=kb_detect_candidates(candidates))


@router.callback_query(DetectPickCB.filter())
async def cb_detect_pick(query: CallbackQuery, callback_data: DetectPickCB, state: FSMContext) -> None:
    fmt_name = callback_data.fmt
    fmt = FORMAT_MAP.get(fmt_name)
    if not fmt:
        await query.answer("Неизвестный формат.", show_alert=True); return

    data = await state.get_data()
    text: str = data.get("detect_text", "")
    if not text:
        await query.answer("Сессия истекла. Пожалуйста, начните заново.", show_alert=True)
        await state.clear(); return

    await query.answer()

    needs_param = (
        fmt.requires_key or fmt.requires_shift or
        fmt.requires_rails or fmt.requires_alphabet
    )

    if needs_param:
        await state.clear()
        await state.update_data(mode="decode", fmt=fmt_name, params={}, pending_text=text)
        crumb = _breadcrumb("🔓", "Декодирование", fmt.display)
        if fmt.requires_shift:
            await state.set_state(DecodeState.wait_shift)
            await edit_or_send(query, f"{crumb}\n\nВведите сдвиг (целое число):", kb_cancel_only())
        elif fmt.requires_key:
            await state.set_state(DecodeState.wait_key)
            await edit_or_send(query, f"{crumb}\n\nВведите ключ ({fmt.key_hint}):", kb_cancel_only())
        elif fmt.requires_rails:
            await state.set_state(DecodeState.wait_rails)
            await edit_or_send(query, f"{crumb}\n\nВведите количество рельс:", kb_cancel_only())
        else:
            await state.set_state(DecodeState.wait_alphabet)
            await edit_or_send(query, f"{crumb}\n\nВведите алфавит замены:", kb_cancel_only())
        return

    try:
        result = dispatch_decode(fmt_name, text, {})
    except ValueError as exc:
        await edit_or_send(
            query,
            f"❌ <b>Ошибка декодирования ({fmt.display}):</b> {_esc(str(exc))}",
            kb_main())
        await state.clear(); return

    msg = (
        f"🔓 <b>Декодировано с помощью {fmt.display}</b>\n\n"
        f"<b>Вход:</b>\n<code>{_esc(text[:300])}{'...' if len(text) > 300 else ''}</code>\n\n"
        f"<b>Результат:</b>\n<code>{_esc(result)}</code>"
    )
    await _push_recent(state, "decode", fmt_name)
    await state.clear()
    await edit_or_send(query, msg, kb_after_result("decode", fmt_name))

# ===============================================================================
# FALLBACK HANDLER
# ===============================================================================

@router.callback_query(F.data == "noop")
async def cb_noop(query: CallbackQuery) -> None:
    await query.answer()

@router.message(StateFilter(None))
async def fallback_handler(message: Message) -> None:
    await message.answer(
        "👋 Используйте меню ниже или /start для начала.",
        parse_mode=ParseMode.HTML, reply_markup=kb_main())

# ===============================================================================
# GLOBAL ERROR HANDLER
# ===============================================================================

async def error_handler(update: Any, exception: Exception) -> bool:
    logger.exception("Unhandled exception for update %s: %s", update, exception)
    return True

# ===============================================================================
# MAIN
# ===============================================================================

async def main() -> None:
    bot = Bot(token=BOT_TOKEN)
    dp  = Dispatcher(storage=MemoryStorage())

    throttle = ThrottlingMiddleware(rate=THROTTLE_RATE)
    dp.message.middleware(throttle)
    dp.callback_query.middleware(throttle)

    dp.include_router(router)
    dp.errors.register(error_handler)

    logger.info("CipherBot v2 запускается — polling...")
    await dp.start_polling(bot, allowed_updates=["message", "callback_query"])


if __name__ == "__main__":
    asyncio.run(main())

# ======================================
#  Botni va Serverni ishga tushrsh

def run_bot():
    bot.polling(non_stop=True)

if __name__ == "__main__":
    threading.Thread(target=run_bot).start()
    app.run(host="0.0.0.0", port=5000, debug=True)
