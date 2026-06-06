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
from aiogram.dispatcher.filters import Command, Text
from aiogram.dispatcher.filters.state import State, StatesGroup
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.utils.executor import start_webhook, start_polling
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
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# ==================== FSM ====================
class CheckForm(StatesGroup):
    waiting_for_username = State()

# ==================== ЛОГИКА ПРОВЕРКИ ====================
async def check_channel(username: str) -> dict:
    result = {"username": username, "risk_score": 0, "risk_level": "low"}
    try:
        chat = await bot.get_chat(username)
        
        # Флаги Telegram
        is_scam = getattr(chat, 'has_restricted', False)
        is_fake = getattr(chat, 'has_hidden_members', False)
        
        if is_scam or is_fake:
            result["risk_score"] = 100
            result["risk_level"] = "high"
            return result
        
        # Подозрительное название
        title = chat.title or ""
        suspicious = ["official", "real", "verified", "original", "authentic"]
        risk = 0
        if any(w in title.lower() for w in suspicious):
            risk += 15
        
        # Количество подписчиков
        try:
            member_count = await bot.get_chat_members_count(username)
            if member_count < 50:
                risk += 20
        except:
            pass
        
        result["risk_score"] = min(risk, 100)
        if result["risk_score"] >= 70:
            result["risk_level"] = "high"
        elif result["risk_score"] >= 40:
            result["risk_level"] = "medium"
        else:
            result["risk_level"] = "low"
        
        # Сохраняем в базу
        conn = sqlite3.connect(DB_NAME)
        conn.execute("INSERT INTO scan_logs (username, risk_score, risk_level) VALUES (?, ?, ?)",
                    (username, result["risk_score"], result["risk_level"]))
        conn.commit()
        conn.close()
        
    except Exception as e:
        result["error"] = str(e)
    return result

# ==================== КЛАВИАТУРЫ ====================
def main_kb():
    buttons = [
        [InlineKeyboardButton(text="🔍 Проверить канал", callback_data="check")],
        [InlineKeyboardButton(text="📊 Статистика", callback_data="stats")]
    ]
    return InlineKeyboardMarkup(inline_keyboard=buttons)

def back_kb():
    return InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="◀ Назад", callback_data="back")]])

# ==================== ХЕНДЛЕРЫ ====================
@dp.message_handler(commands=['start'])
async def start(message: types.Message):
    await message.answer("👋 *Бот проверки каналов*\n\nВыберите действие:", parse_mode="Markdown", reply_markup=main_kb())

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
        f"{emoji[result['risk_level']]} *Риск:* {level[result['risk_level']]} ({result['risk_score']} баллов)"
    )
    await message.answer(text, parse_mode="Markdown", reply_markup=main_kb())

@dp.callback_query_handler(lambda c: c.data == "stats")
async def stats(callback_query: types.CallbackQuery):
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
    conn.close()
    text = (
        f"📊 *Статистика проверок*\n\n"
        f"📋 Всего проверок: {total}\n"
        f"🔴 Высокий риск: {high}\n"
        f"🟡 Средний риск: {medium}\n"
        f"🟢 Низкий риск: {low}"
    )
    await callback_query.message.edit_text(text, parse_mode="Markdown", reply_markup=back_kb())
    await callback_query.answer()

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
    logger.info("Бот запущен")
    await dp.start_polling()

if __name__ == "__main__":
    asyncio.run(main())
