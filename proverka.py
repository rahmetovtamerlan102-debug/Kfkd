#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import logging
import os
import sqlite3
import threading
from datetime import datetime
from flask import Flask

from aiogram import Bot, Dispatcher, types
from aiogram.contrib.middlewares.logging import LoggingMiddleware
from aiogram.dispatcher import FSMContext
from aiogram.dispatcher.filters import Command
from aiogram.dispatcher.filters.state import State, StatesGroup
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from dotenv import load_dotenv

load_dotenv()

# ==================== КОНФИГУРАЦИЯ ====================
BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN не задан")

ADMIN_IDS = list(map(int, os.getenv("ADMIN_IDS", "0").split(',')))
PORT = int(os.getenv("PORT", "8080"))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher(bot)
dp.middleware.setup(LoggingMiddleware())

# ==================== БАЗА ДАННЫХ (SQLite) ====================
DB_NAME = "scanner.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            risk_score INTEGER,
            risk_level TEXT,
            details TEXT,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS monitored_channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            added_by INTEGER,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS channel_blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            reason TEXT,
            added_by INTEGER,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    logger.info("База данных инициализирована")

init_db()

# ==================== FSM ====================
class CheckForm(StatesGroup):
    waiting_for_username = State()

class MonitorForm(StatesGroup):
    waiting_for_username = State()

class BlacklistForm(StatesGroup):
    waiting_for_username = State()

# ==================== ФУНКЦИИ БАЗЫ ДАННЫХ ====================
def save_scan_log(username, risk_score, risk_level, details=""):
    conn = sqlite3.connect(DB_NAME)
    conn.execute(
        "INSERT INTO scan_logs (username, risk_score, risk_level, details) VALUES (?, ?, ?, ?)",
        (username, risk_score, risk_level, details)
    )
    conn.commit()
    conn.close()

def get_stats():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM scan_logs")
    total = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM scan_logs WHERE risk_level = 'high'")
    high = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM scan_logs WHERE risk_level = 'medium'")
    medium = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM scan_logs WHERE risk_level = 'low'")
    low = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM channel_blacklist")
    blacklisted = cur.fetchone()[0]
    conn.close()
    return total, high, medium, low, blacklisted

def get_top_risky(limit=10):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute('''
        SELECT DISTINCT username, risk_score, risk_level, scanned_at 
        FROM scan_logs 
        ORDER BY scanned_at DESC
    ''')
    rows = cur.fetchall()
    conn.close()
    latest = {}
    for row in rows:
        if row[0] not in latest:
            latest[row[0]] = row
    sorted_rows = sorted(latest.values(), key=lambda x: x[1], reverse=True)[:limit]
    return sorted_rows

def add_to_monitor(username, added_by):
    conn = sqlite3.connect(DB_NAME)
    try:
        conn.execute("INSERT INTO monitored_channels (username, added_by) VALUES (?, ?)", (username, added_by))
        conn.commit()
        conn.close()
        return True
    except:
        conn.close()
        return False

def get_monitored_channels():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT username, added_at FROM monitored_channels ORDER BY added_at")
    rows = cur.fetchall()
    conn.close()
    return rows

def remove_from_monitor(username):
    conn = sqlite3.connect(DB_NAME)
    conn.execute("DELETE FROM monitored_channels WHERE username = ?", (username,))
    conn.commit()
    conn.close()

def add_to_blacklist(username, reason, added_by):
    conn = sqlite3.connect(DB_NAME)
    try:
        conn.execute("INSERT INTO channel_blacklist (username, reason, added_by) VALUES (?, ?, ?)", (username, reason, added_by))
        conn.commit()
        conn.close()
        return True
    except:
        conn.close()
        return False

def get_blacklist():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT username, reason, added_at FROM channel_blacklist ORDER BY added_at")
    rows = cur.fetchall()
    conn.close()
    return rows

def remove_from_blacklist(username):
    conn = sqlite3.connect(DB_NAME)
    conn.execute("DELETE FROM channel_blacklist WHERE username = ?", (username,))
    conn.commit()
    conn.close()

def is_blacklisted(username):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM channel_blacklist WHERE username = ?", (username,))
    result = cur.fetchone()
    conn.close()
    return result is not None

# ==================== ЛОГИКА ПРОВЕРКИ ====================
async def check_channel(username: str) -> dict:
    result = {"username": username, "risk_score": 0, "risk_level": "low", "details": {}}
    try:
        if is_blacklisted(username):
            result["risk_score"] = 100
            result["risk_level"] = "high"
            result["details"]["reason"] = "Канал в чёрном списке"
            save_scan_log(username, result["risk_score"], result["risk_level"], str(result["details"]))
            return result
        
        chat = await bot.get_chat(username)
        
        is_scam = getattr(chat, 'has_restricted', False)
        is_fake = getattr(chat, 'has_hidden_members', False)
        is_verified = getattr(chat, 'has_verified', False)
        
        result["details"]["is_scam"] = is_scam
        result["details"]["is_fake"] = is_fake
        result["details"]["is_verified"] = is_verified
        
        if is_scam or is_fake:
            result["risk_score"] = 100
            result["risk_level"] = "high"
            result["details"]["reason"] = "Канал отмечен Telegram как мошеннический"
            save_scan_log(username, result["risk_score"], result["risk_level"], str(result["details"]))
            return result
        
        title = chat.title or ""
        suspicious = ["official", "real", "verified", "original", "authentic", "admin", "support"]
        if any(w in title.lower() for w in suspicious):
            result["risk_score"] += 15
            result["details"]["suspect_name"] = True
        
        try:
            member_count = await bot.get_chat_members_count(username)
            result["details"]["member_count"] = member_count
            if member_count < 50:
                result["risk_score"] += 20
        except:
            pass
        
        known_brands = ["google", "apple", "microsoft", "telegram", "binance", "bybit", "okx", "crypto", "wallet"]
        if any(brand in username.lower() for brand in known_brands):
            result["risk_score"] += 10
            result["details"]["brand_impersonation"] = True
        
        result["risk_score"] = min(result["risk_score"], 100)
        if result["risk_score"] >= 70:
            result["risk_level"] = "high"
        elif result["risk_score"] >= 40:
            result["risk_level"] = "medium"
        else:
            result["risk_level"] = "low"
        
        save_scan_log(username, result["risk_score"], result["risk_level"], str(result["details"]))
        
    except Exception as e:
        result["error"] = str(e)
    return result

def get_recommendations(risk_level: str) -> str:
    if risk_level == "high":
        return "🔴 **НЕ доверяйте этому каналу!**\n• Не переходите по ссылкам\n• Не вводите личные данные\n• Пожалуйтесь на канал через @BotFather"
    elif risk_level == "medium":
        return "🟡 **Будьте осторожны!**\n• Проверьте отзывы о канале\n• Не спешите доверять\n• Свяжитесь с поддержкой напрямую"
    else:
        return "🟢 **Канал выглядит безопасным**, но всегда проверяйте информацию"

# ==================== КЛАВИАТУРЫ ====================
def main_kb():
    buttons = [
        [InlineKeyboardButton(text="🔍 Проверить канал", callback_data="check")],
        [InlineKeyboardButton(text="📊 Статистика", callback_data="stats")],
        [InlineKeyboardButton(text="🏆 Топ опасных", callback_data="top_risky")],
    ]
    return InlineKeyboardMarkup(inline_keyboard=buttons)

def admin_kb():
    buttons = [
        [InlineKeyboardButton(text="➕ Добавить в мониторинг", callback_data="admin_monitor_add")],
        [InlineKeyboardButton(text="📋 Список мониторинга", callback_data="admin_monitor_list")],
        [InlineKeyboardButton(text="❌ Удалить из мониторинга", callback_data="admin_monitor_remove")],
        [InlineKeyboardButton(text="🚫 Чёрный список", callback_data="admin_blacklist_menu")],
        [InlineKeyboardButton(text="◀ Назад", callback_data="back")]
    ]
    return InlineKeyboardMarkup(inline_keyboard=buttons)

def blacklist_kb():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="➕ Добавить в ЧС", callback_data="admin_blacklist_add")],
        [InlineKeyboardButton(text="📋 Список ЧС", callback_data="admin_blacklist_list")],
        [InlineKeyboardButton(text="❌ Удалить из ЧС", callback_data="admin_blacklist_remove")],
        [InlineKeyboardButton(text="◀ Назад", callback_data="admin_panel")]
    ])

def back_kb():
    return InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="◀ Назад", callback_data="back")]])

# ==================== ХЕНДЛЕРЫ ====================
@dp.message_handler(commands=['start'])
async def start(message: types.Message):
    await message.answer("👋 *Бот проверки каналов на мошенничество*\n\nВыберите действие:", parse_mode="Markdown", reply_markup=main_kb())

@dp.callback_query_handler(lambda c: c.data == "back")
async def back(callback_query: types.CallbackQuery):
    await callback_query.message.edit_text("👋 Главное меню", reply_markup=main_kb())
    await callback_query.answer()

@dp.callback_query_handler(lambda c: c.data == "check")
async def check_prompt(callback_query: types.CallbackQuery):
    await CheckForm.waiting_for_username.set()
    await callback_query.message.edit_text("🔍 *Введите username канала:*\nПример: @durov", parse_mode="Markdown")
    await callback_query.answer()

@dp.message_handler(state=CheckForm.waiting_for_username)
async def process_check(message: types.Message, state: FSMContext):
    username = message.text.strip()
    if username.startswith("@"):
        username = username[1:]
    await state.finish()
    await message.answer(f"🔍 Проверяю @{username}...")
    result = await check_channel(username)
    if "error" in result:
        await message.answer(f"❌ {result['error']}", reply_markup=main_kb())
        return
    emoji = {"low": "🟢", "medium": "🟡", "high": "🔴"}
    level = {"low": "Низкий", "medium": "Средний", "high": "Высокий"}
    text = (
        f"📊 *Результат проверки @{username}*\n\n"
        f"{emoji[result['risk_level']]} *Риск:* {level[result['risk_level']]} ({result['risk_score']} баллов)\n\n"
        f"📋 *Детали:*\n"
        f"├ Скам-флаг: {'✅' if result['details'].get('is_scam') else '❌'}\n"
        f"├ Фейк-флаг: {'✅' if result['details'].get('is_fake') else '❌'}\n"
        f"├ Верифицирован: {'✅' if result['details'].get('is_verified') else '❌'}\n"
        f"├ Подозрительное имя: {'✅' if result['details'].get('suspect_name') else '❌'}\n"
        f"├ Подписчиков: {result['details'].get('member_count', '?')}\n"
        f"└ Имитация бренда: {'✅' if result['details'].get('brand_impersonation') else '❌'}\n\n"
    )
    text += get_recommendations(result['risk_level'])
    await message.answer(text, parse_mode="Markdown", reply_markup=main_kb())

@dp.callback_query_handler(lambda c: c.data == "stats")
async def stats(callback_query: types.CallbackQuery):
    total, high, medium, low, blacklisted = get_stats()
    text = (
        f"📊 *Статистика проверок*\n\n"
        f"📋 Всего проверок: {total}\n"
        f"🔴 Высокий риск: {high}\n"
        f"🟡 Средний риск: {medium}\n"
        f"🟢 Низкий риск: {low}\n"
        f"🚫 В чёрном списке: {blacklisted}"
    )
    await callback_query.message.edit_text(text, parse_mode="Markdown", reply_markup=back_kb())
    await callback_query.answer()

@dp.callback_query_handler(lambda c: c.data == "top_risky")
async def top_risky(callback_query: types.CallbackQuery):
    rows = get_top_risky(10)
    if not rows:
        await callback_query.message.edit_text("📭 Нет данных для рейтинга", reply_markup=back_kb())
        await callback_query.answer()
        return
    text = "🏆 *Топ-10 самых опасных каналов:*\n\n"
    for i, row in enumerate(rows, 1):
        emoji = "🔴" if row[2] == "high" else "🟡" if row[2] == "medium" else "🟢"
        text += f"{i}. {emoji} @{row[0]} — {row[1]} баллов\n"
    await callback_query.message.edit_text(text, parse_mode="Markdown", reply_markup=back_kb())
    await callback_query.answer()

# ==================== АДМИН-ПАНЕЛЬ ====================
@dp.callback_query_handler(lambda c: c.data == "admin_panel")
async def admin_panel(callback_query: types.CallbackQuery):
    if callback_query.from_user.id not in ADMIN_IDS:
        await callback_query.answer("Доступ запрещён", show_alert=True)
        return
    await callback_query.message.edit_text("🔐 *Админ панель*", parse_mode="Markdown", reply_markup=admin_kb())
    await callback_query.answer()

@dp.callback_query_handler(lambda c: c.data == "admin_blacklist_menu")
async def admin_blacklist_menu(callback_query: types.CallbackQuery):
    if callback_query.from_user.id not in ADMIN_IDS:
        return
    await callback_query.message.edit_text("🚫 *Управление чёрным списком*", parse_mode="Markdown", reply_markup=blacklist_kb())
    await callback_query.answer()

@dp.callback_query_handler(lambda c: c.data == "admin_blacklist_add")
async def admin_blacklist_add_prompt(callback_query: types.CallbackQuery):
    if callback_query.from_user.id not in ADMIN_IDS:
        return
    await BlacklistForm.waiting_for_username.set()
    await callback_query.message.edit_text("🚫 *Введите username канала для добавления в чёрный список:*\nПример: @scam_channel", parse_mode="Markdown")
    await callback_query.answer()

@dp.message_handler(state=BlacklistForm.waiting_for_username)
async def process_blacklist_add(message: types.Message, state: FSMContext):
    if message.from_user.id not in ADMIN_IDS:
        await state.finish()
        return
    username = message.text.strip()
    if username.startswith("@"):
        username = username[1:]
    if add_to_blacklist(username, "Добавлен администратором", message.from_user.id):
        await message.answer(f"✅ Канал @{username} добавлен в чёрный список", reply_markup=main_kb())
    else:
        await message.answer(f"❌ Канал @{username} уже в чёрном списке", reply_markup=main_kb())
    await state.finish()

@dp.callback_query_handler(lambda c: c.data == "admin_blacklist_list")
async def admin_blacklist_list(callback_query: types.CallbackQuery):
    if callback_query.from_user.id not in ADMIN_IDS:
        return
    rows = get_blacklist()
    if not rows:
        await callback_query.message.edit_text("📭 Чёрный список пуст", reply_markup=blacklist_kb())
        return
    text = "🚫 *Чёрный список каналов:*\n\n"
    for r in rows:
        text += f"├ @{r[0]} (добавлен {r[2][:10]})\n"
    await callback_query.message.edit_text(text, parse_mode="Markdown", reply_markup=blacklist_kb())
    await callback_query.answer()

@dp.callback_query_handler(lambda c: c.data == "admin_blacklist_remove")
async def admin_blacklist_remove_prompt(callback_query: types.CallbackQuery):
    if callback_query.from_user.id not in ADMIN_IDS:
        return
    await BlacklistForm.waiting_for_username.set()
    await callback_query.message.edit_text("🗑 *Введите username канала для удаления из чёрного списка:*", parse_mode="Markdown")
    await callback_query.answer()

@dp.message_handler(state=BlacklistForm.waiting_for_username)
async def process_blacklist_remove(message: types.Message, state: FSMContext):
    if message.from_user.id not in ADMIN_IDS:
        await state.finish()
        return
    username = message.text.strip()
    if username.startswith("@"):
        username = username[1:]
    remove_from_blacklist(username)
    await message.answer(f"✅ Канал @{username} удалён из чёрного списка", reply_markup=main_kb())
    await state.finish()

@dp.callback_query_handler(lambda c: c.data == "admin_monitor_add")
async def admin_monitor_add_prompt(callback_query: types.CallbackQuery):
    if callback_query.from_user.id not in ADMIN_IDS:
        return
    await MonitorForm.waiting_for_username.set()
    await callback_query.message.edit_text("📋 *Введите username канала для мониторинга:*\nПример: @durov", parse_mode="Markdown")
    await callback_query.answer()

@dp.message_handler(state=MonitorForm.waiting_for_username)
async def process_monitor_add(message: types.Message, state: FSMContext):
    if message.from_user.id not in ADMIN_IDS:
        await state.finish()
        return
    username = message.text.strip()
    if username.startswith("@"):
        username = username[1:]
    if add_to_monitor(username, message.from_user.id):
        await message.answer(f"✅ Канал @{username} добавлен в мониторинг", reply_markup=main_kb())
    else:
        await message.answer(f"❌ Канал @{username} уже в списке", reply_markup=main_kb())
    await state.finish()

@dp.callback_query_handler(lambda c: c.data == "admin_monitor_list")
async def admin_monitor_list(callback_query: types.CallbackQuery):
    if callback_query.from_user.id not in ADMIN_IDS:
        return
    rows = get_monitored_channels()
    if not rows:
        await callback_query.message.edit_text("📭 Список мониторинга пуст", reply_markup=admin_kb())
        return
    text = "📋 *Отслеживаемые каналы:*\n"
    for r in rows:
        text += f"├ @{r[0]} (добавлен {r[1][:10]})\n"
    await callback_query.message.edit_text(text, parse_mode="Markdown", reply_markup=admin_kb())
    await callback_query.answer()

@dp.callback_query_handler(lambda c: c.data == "admin_monitor_remove")
async def admin_monitor_remove_prompt(callback_query: types.CallbackQuery):
    if callback_query.from_user.id not in ADMIN_IDS:
        return
    await MonitorForm.waiting_for_username.set()
    await callback_query.message.edit_text("🗑 *Введите username канала для удаления из мониторинга:*", parse_mode="Markdown")
    await callback_query.answer()

@dp.message_handler(state=MonitorForm.waiting_for_username)
async def process_monitor_remove(message: types.Message, state: FSMContext):
    if message.from_user.id not in ADMIN_IDS:
        await state.finish()
        return
    username = message.text.strip()
    if username.startswith("@"):
        username = username[1:]
    remove_from_monitor(username)
    await message.answer(f"✅ Канал @{username} удалён из мониторинга", reply_markup=main_kb())
    await state.finish()

# ==================== FLASK ДЛЯ HEALTHCHECK ====================
flask_app = Flask(__name__)

@flask_app.route('/')
def health():
    return "OK", 200

def run_flask():
    flask_app.run(host='0.0.0.0', port=PORT, debug=False, use_reloader=False)

# ==================== ЗАПУСК ====================
async def main():
    threading.Thread(target=run_flask, daemon=True).start()
    await bot.delete_webhook()
    logger.info("Бот проверки каналов запущен")
    await dp.start_polling()

if __name__ == "__main__":
    asyncio.run(main())
