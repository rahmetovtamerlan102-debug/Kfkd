#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import logging
import os
import re
import pickle
import threading
import csv
import io
from datetime import datetime
from typing import Dict, Any, Optional, Tuple, List

from flask import Flask
import aiohttp
import asyncpg
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from aiogram import Bot, Dispatcher, types, F
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton, BufferedInputFile
from aiogram.filters import Command, StateFilter
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from dotenv import load_dotenv

load_dotenv()

# ==================== КОНФИГУРАЦИЯ ====================
BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN не задан")

ADMIN_IDS = list(map(int, os.getenv("ADMIN_IDS", "0").split(',')))
PORT = int(os.getenv("PORT", "8080"))
PUBLIC_URL = os.getenv("PUBLIC_URL", f"https://{os.getenv('RENDER_EXTERNAL_HOSTNAME', 'localhost')}")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher(storage=MemoryStorage())

# ==================== FSM ====================
class CheckForm(StatesGroup):
    waiting_for_username = State()

class MonitorForm(StatesGroup):
    waiting_for_username = State()

class TeachForm(StatesGroup):
    waiting_for_description = State()

class BlacklistForm(StatesGroup):
    waiting_for_username = State()

# ==================== БАЗА ДАННЫХ ====================
DB_NAME = "scanner.db"
db_pool = None

async def init_db():
    global db_pool
    db_pool = await asyncpg.create_pool(DB_NAME, min_size=2, max_size=10)
    async with db_pool.acquire() as conn:
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS monitored_channels (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE,
                added_by BIGINT,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS scan_logs (
                id SERIAL PRIMARY KEY,
                username TEXT,
                risk_score INTEGER,
                risk_level TEXT,
                details TEXT,
                scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS teach_examples (
                id SERIAL PRIMARY KEY,
                description TEXT,
                keywords TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS channel_blacklist (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE,
                reason TEXT,
                added_by BIGINT,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
    logger.info("База данных инициализирована")

# ==================== ML МОДЕЛЬ ====================
MODEL_PATH = "models/scam_model.pkl"
VECTORIZER_PATH = "models/vectorizer.pkl"

def load_model() -> Tuple[Optional[RandomForestClassifier], Optional[TfidfVectorizer]]:
    if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
        with open(MODEL_PATH, 'rb') as f:
            model = pickle.load(f)
        with open(VECTORIZER_PATH, 'rb') as f:
            vectorizer = pickle.load(f)
        return model, vectorizer
    return None, None

def save_model(model, vectorizer):
    os.makedirs("models", exist_ok=True)
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
    with open(VECTORIZER_PATH, 'wb') as f:
        pickle.dump(vectorizer, f)

async def train_model():
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("SELECT description, keywords FROM teach_examples")
    if len(rows) < 3:
        return False
    texts = [f"{row['description']} {row['keywords']}" for row in rows]
    y = [1] * len(texts)
    vectorizer = TfidfVectorizer(max_features=100)
    X = vectorizer.fit_transform(texts)
    model = RandomForestClassifier(n_estimators=50, random_state=42)
    model.fit(X, y)
    save_model(model, vectorizer)
    return True

def predict_risk(text: str) -> Tuple[int, str]:
    model, vectorizer = load_model()
    if model is None or vectorizer is None:
        return 0, "unknown"
    X = vectorizer.transform([text])
    proba = model.predict_proba(X)[0]
    risk = int(proba[1] * 100) if len(proba) > 1 else 0
    level = "high" if risk >= 70 else "medium" if risk >= 40 else "low"
    return min(risk, 100), level

# ==================== ОСНОВНАЯ ЛОГИКА ====================
async def is_channel_blacklisted(username: str) -> bool:
    async with db_pool.acquire() as conn:
        return await conn.fetchval("SELECT 1 FROM channel_blacklist WHERE username = $1", username) is not None

async def check_channel(username: str) -> Dict[str, Any]:
    result = {"username": username, "risk_score": 0, "risk_level": "low", "details": {}}
    try:
        # Проверка в чёрном списке
        if await is_channel_blacklisted(username):
            result["risk_score"] = 100
            result["risk_level"] = "high"
            result["details"]["reason"] = "Канал в чёрном списке администратора"
            return result
        
        chat = await bot.get_chat(username)
        
        # 1. Флаги Telegram
        result["details"]["is_scam"] = getattr(chat, 'has_restricted', False)
        result["details"]["is_fake"] = getattr(chat, 'has_hidden_members', False)
        result["details"]["is_verified"] = getattr(chat, 'has_verified', False)
        
        if result["details"]["is_scam"] or result["details"]["is_fake"]:
            result["risk_score"] = 100
            result["risk_level"] = "high"
            result["details"]["reason"] = "Канал отмечен Telegram как мошеннический"
            return result
        
        # 2. Подозрительное название
        title = chat.title or ""
        suspicious = ["official", "real", "verified", "original", "authentic", "admin", "support"]
        if any(w in title.lower() for w in suspicious):
            result["risk_score"] += 15
            result["details"]["suspect_name"] = True
        
        # 3. Количество подписчиков
        try:
            member_count = await bot.get_chat_members_count(username)
            result["details"]["member_count"] = member_count
            if member_count < 50:
                result["risk_score"] += 20
            elif member_count > 100000:
                result["risk_score"] += 5
        except:
            pass
        
        # 4. Анализ описания через ML
        description = chat.description or ""
        ml_risk, _ = predict_risk(description)
        result["details"]["ml_risk"] = ml_risk
        result["risk_score"] += ml_risk // 3
        
        # 5. Имитация известного бренда
        known_brands = ["google", "apple", "microsoft", "telegram", "binance", "bybit", "okx", "crypto", "wallet"]
        if any(brand in username.lower() for brand in known_brands):
            result["risk_score"] += 10
            result["details"]["brand_impersonation"] = True
        
        # 6. Проверка на повторную проверку (если уже был в логах)
        async with db_pool.acquire() as conn:
            prev = await conn.fetchval("SELECT risk_score FROM scan_logs WHERE username = $1 ORDER BY scanned_at DESC LIMIT 1", username)
            if prev:
                result["details"]["previous_score"] = prev
                if prev >= 70:
                    result["risk_score"] += 5  # уже был опасным
        
        # Итоговый риск
        result["risk_score"] = min(result["risk_score"], 100)
        if result["risk_score"] >= 70:
            result["risk_level"] = "high"
        elif result["risk_score"] >= 40:
            result["risk_level"] = "medium"
        else:
            result["risk_level"] = "low"
        
        # Сохраняем лог
        async with db_pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO scan_logs (username, risk_score, risk_level, details) VALUES ($1, $2, $3, $4)",
                username, result["risk_score"], result["risk_level"], str(result["details"])
            )
    except Exception as e:
        result["error"] = str(e)
    return result

def get_recommendations(risk_level: str, details: dict) -> str:
    if risk_level == "high":
        return "🔴 **НЕ доверяйте этому каналу!**\n• Не переходите по ссылкам\n• Не вводите личные данные\n• Пожалуйтесь на канал через @BotFather"
    elif risk_level == "medium":
        return "🟡 **Будьте осторожны!**\n• Проверьте отзывы о канале\n• Не спешите доверять\n• Свяжитесь с поддержкой напрямую, а не через канал"
    else:
        return "🟢 **Канал выглядит безопасным**, но всегда проверяйте информацию"

# ==================== КЛАВИАТУРЫ ====================
def main_kb(user_id):
    buttons = [
        [InlineKeyboardButton(text="🔍 Проверить канал", callback_data="check")],
        [InlineKeyboardButton(text="📋 Мониторинг", callback_data="monitor_menu")],
        [InlineKeyboardButton(text="📊 Статистика", callback_data="stats")],
        [InlineKeyboardButton(text="🏆 Топ опасных", callback_data="top_risky")],
    ]
    if user_id in ADMIN_IDS:
        buttons.append([InlineKeyboardButton(text="🔐 Админ панель", callback_data="admin_panel")])
    return InlineKeyboardMarkup(inline_keyboard=buttons)

def admin_panel_kb():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="➕ Добавить в мониторинг", callback_data="admin_monitor_add")],
        [InlineKeyboardButton(text="📋 Список мониторинга", callback_data="admin_monitor_list")],
        [InlineKeyboardButton(text="❌ Удалить из мониторинга", callback_data="admin_monitor_remove")],
        [InlineKeyboardButton(text="🚫 Чёрный список каналов", callback_data="admin_blacklist_menu")],
        [InlineKeyboardButton(text="🧠 Обучить модель", callback_data="admin_teach")],
        [InlineKeyboardButton(text="📁 Экспорт CSV", callback_data="admin_export")],
        [InlineKeyboardButton(text="◀ Назад", callback_data="back")]
    ])

def admin_blacklist_kb():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="➕ Добавить в ЧС", callback_data="admin_blacklist_add")],
        [InlineKeyboardButton(text="📋 Список ЧС", callback_data="admin_blacklist_list")],
        [InlineKeyboardButton(text="❌ Удалить из ЧС", callback_data="admin_blacklist_remove")],
        [InlineKeyboardButton(text="◀ Назад", callback_data="admin_panel")]
    ])

def back_kb():
    return InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="◀ Назад", callback_data="back")]])

def monitor_kb():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="➕ Добавить канал", callback_data="monitor_add")],
        [InlineKeyboardButton(text="📋 Список", callback_data="monitor_list")],
        [InlineKeyboardButton(text="❌ Удалить", callback_data="monitor_remove")],
        [InlineKeyboardButton(text="◀ Назад", callback_data="back")]
    ])

# ==================== ХЕНДЛЕРЫ ====================
@dp.message(Command("start"))
async def start(m: types.Message, state: FSMContext):
    await state.clear()
    await m.answer("👋 *Бот проверки каналов на мошенничество*\n\nВыберите действие:", parse_mode="Markdown", reply_markup=main_kb(m.from_user.id))

@dp.callback_query(F.data == "back")
async def back(c: types.CallbackQuery, state: FSMContext):
    await state.clear()
    await c.message.edit_text("👋 Главное меню", reply_markup=main_kb(c.from_user.id))

# -------------------- ПРОВЕРКА --------------------
@dp.callback_query(F.data == "check")
async def check_prompt(c: types.CallbackQuery, state: FSMContext):
    await state.set_state(CheckForm.waiting_for_username)
    await c.message.edit_text("🔍 *Введите username канала:*\nПример: @durov", parse_mode="Markdown")
    await c.answer()

@dp.message(StateFilter(CheckForm.waiting_for_username))
async def process_check(m: types.Message, state: FSMContext):
    username = m.text.strip()
    if username.startswith("@"):
        username = username[1:]
    await state.clear()
    await m.answer(f"🔍 Проверяю @{username}...")
    result = await check_channel(username)
    if "error" in result:
        await m.answer(f"❌ {result['error']}", reply_markup=main_kb(m.from_user.id))
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
        f"├ Имитация бренда: {'✅' if result['details'].get('brand_impersonation') else '❌'}\n"
        f"├ ML оценка: {result['details'].get('ml_risk', '?')} баллов\n"
        f"└ Предыдущий риск: {result['details'].get('previous_score', 'нет')}\n\n"
    )
    text += get_recommendations(result['risk_level'], result['details'])
    await m.answer(text, parse_mode="Markdown", reply_markup=main_kb(m.from_user.id))

# -------------------- ТОП ОПАСНЫХ --------------------
@dp.callback_query(F.data == "top_risky")
async def top_risky(c: types.CallbackQuery):
    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT DISTINCT ON (username) username, risk_score, risk_level, scanned_at "
            "FROM scan_logs ORDER BY username, scanned_at DESC"
        )
        sorted_rows = sorted(rows, key=lambda x: x['risk_score'], reverse=True)[:10]
    if not sorted_rows:
        await c.message.edit_text("📭 Нет данных для рейтинга", reply_markup=back_kb())
        return
    text = "🏆 *Топ-10 самых опасных каналов:*\n\n"
    for i, row in enumerate(sorted_rows, 1):
        emoji = "🔴" if row['risk_level'] == "high" else "🟡" if row['risk_level'] == "medium" else "🟢"
        text += f"{i}. {emoji} @{row['username']} — {row['risk_score']} баллов\n"
    await c.message.edit_text(text, parse_mode="Markdown", reply_markup=back_kb())
    await c.answer()

# -------------------- МОНИТОРИНГ --------------------
@dp.callback_query(F.data == "monitor_menu")
async def monitor_menu(c: types.CallbackQuery):
    await c.message.edit_text("📋 *Управление мониторингом*", parse_mode="Markdown", reply_markup=monitor_kb())
    await c.answer()

@dp.callback_query(F.data == "monitor_add")
async def monitor_add_prompt(c: types.CallbackQuery, state: FSMContext):
    if c.from_user.id not in ADMIN_IDS:
        await c.answer("❌ Только для админа", show_alert=True)
        return
    await state.set_state(MonitorForm.waiting_for_username)
    await c.message.edit_text("📋 *Введите username канала для мониторинга:*\nПример: @durov", parse_mode="Markdown")
    await c.answer()

@dp.message(StateFilter(MonitorForm.waiting_for_username))
async def process_monitor_add(m: types.Message, state: FSMContext):
    username = m.text.strip()
    if username.startswith("@"):
        username = username[1:]
    async with db_pool.acquire() as conn:
        try:
            await conn.execute("INSERT INTO monitored_channels (username, added_by) VALUES ($1, $2)", username, m.from_user.id)
            await m.answer(f"✅ Канал @{username} добавлен в мониторинг", reply_markup=main_kb(m.from_user.id))
        except:
            await m.answer(f"❌ Канал @{username} уже в списке", reply_markup=main_kb(m.from_user.id))
    await state.clear()

@dp.callback_query(F.data == "monitor_list")
async def monitor_list(c: types.CallbackQuery):
    if c.from_user.id not in ADMIN_IDS:
        await c.answer("❌ Только для админа", show_alert=True)
        return
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("SELECT username, added_at FROM monitored_channels ORDER BY added_at")
    if not rows:
        await c.message.edit_text("📭 Список мониторинга пуст", reply_markup=monitor_kb())
        return
    text = "📋 *Отслеживаемые каналы:*\n"
    for r in rows:
        text += f"├ @{r['username']} (добавлен {r['added_at'].strftime('%d.%m.%Y')})\n"
    await c.message.edit_text(text, parse_mode="Markdown", reply_markup=monitor_kb())
    await c.answer()

@dp.callback_query(F.data == "monitor_remove")
async def monitor_remove_prompt(c: types.CallbackQuery, state: FSMContext):
    if c.from_user.id not in ADMIN_IDS:
        await c.answer("❌ Только для админа", show_alert=True)
        return
    await state.set_state("waiting_remove_username")
    await c.message.edit_text("🗑 *Введите username канала для удаления из мониторинга:*\nПример: @durov", parse_mode="Markdown")
    await c.answer()

@dp.message(lambda m: m.state == "waiting_remove_username")
async def process_monitor_remove(m: types.Message, state: FSMContext):
    username = m.text.strip()
    if username.startswith("@"):
        username = username[1:]
    async with db_pool.acquire() as conn:
        await conn.execute("DELETE FROM monitored_channels WHERE username = $1", username)
    await m.answer(f"✅ Канал @{username} удалён из мониторинга", reply_markup=main_kb(m.from_user.id))
    await state.clear()

# -------------------- СТАТИСТИКА --------------------
@dp.callback_query(F.data == "stats")
async def stats(c: types.CallbackQuery):
    async with db_pool.acquire() as conn:
        total = await conn.fetchval("SELECT COUNT(*) FROM scan_logs")
        high = await conn.fetchval("SELECT COUNT(*) FROM scan_logs WHERE risk_level = 'high'")
        medium = await conn.fetchval("SELECT COUNT(*) FROM scan_logs WHERE risk_level = 'medium'")
        low = await conn.fetchval("SELECT COUNT(*) FROM scan_logs WHERE risk_level = 'low'")
        blacklisted = await conn.fetchval("SELECT COUNT(*) FROM channel_blacklist")
    text = (
        f"📊 *Статистика проверок*\n\n"
        f"📋 Всего проверок: {total}\n"
        f"🔴 Высокий риск: {high}\n"
        f"🟡 Средний риск: {medium}\n"
        f"🟢 Низкий риск: {low}\n"
        f"🚫 В чёрном списке: {blacklisted}"
    )
    await c.message.edit_text(text, parse_mode="Markdown", reply_markup=back_kb())
    await c.answer()

# -------------------- АДМИН-ПАНЕЛЬ --------------------
@dp.callback_query(F.data == "admin_panel")
async def admin_panel(c: types.CallbackQuery):
    if c.from_user.id not in ADMIN_IDS:
        await c.answer("Доступ запрещён", show_alert=True)
        return
    await c.message.edit_text("🔐 *Админ панель*", parse_mode="Markdown", reply_markup=admin_panel_kb())
    await c.answer()

@dp.callback_query(F.data == "admin_blacklist_menu")
async def admin_blacklist_menu(c: types.CallbackQuery):
    if c.from_user.id not in ADMIN_IDS:
        return
    await c.message.edit_text("🚫 *Управление чёрным списком каналов*", parse_mode="Markdown", reply_markup=admin_blacklist_kb())
    await c.answer()

@dp.callback_query(F.data == "admin_blacklist_add")
async def admin_blacklist_add_prompt(c: types.CallbackQuery, state: FSMContext):
    if c.from_user.id not in ADMIN_IDS:
        return
    await state.set_state(BlacklistForm.waiting_for_username)
    await c.message.edit_text("🚫 *Введите username канала для добавления в чёрный список:*\nПример: @scam_channel", parse_mode="Markdown")
    await c.answer()

@dp.message(StateFilter(BlacklistForm.waiting_for_username))
async def process_blacklist_add(m: types.Message, state: FSMContext):
    username = m.text.strip()
    if username.startswith("@"):
        username = username[1:]
    async with db_pool.acquire() as conn:
        try:
            await conn.execute("INSERT INTO channel_blacklist (username, reason, added_by) VALUES ($1, $2, $3)", 
                              username, "Добавлен администратором", m.from_user.id)
            await m.answer(f"✅ Канал @{username} добавлен в чёрный список", reply_markup=main_kb(m.from_user.id))
        except:
            await m.answer(f"❌ Канал @{username} уже в чёрном списке", reply_markup=main_kb(m.from_user.id))
    await state.clear()

@dp.callback_query(F.data == "admin_blacklist_list")
async def admin_blacklist_list(c: types.CallbackQuery):
    if c.from_user.id not in ADMIN_IDS:
        return
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("SELECT username, reason, added_at FROM channel_blacklist ORDER BY added_at")
    if not rows:
        await c.message.edit_text("📭 Чёрный список пуст", reply_markup=admin_blacklist_kb())
        return
    text = "🚫 *Чёрный список каналов:*\n\n"
    for r in rows:
        text += f"├ @{r['username']} (добавлен {r['added_at'].strftime('%d.%m.%Y')})\n"
    await c.message.edit_text(text, parse_mode="Markdown", reply_markup=admin_blacklist_kb())
    await c.answer()

@dp.callback_query(F.data == "admin_blacklist_remove")
async def admin_blacklist_remove_prompt(c: types.CallbackQuery, state: FSMContext):
    if c.from_user.id not in ADMIN_IDS:
        return
    await state.set_state("waiting_blacklist_remove")
    await c.message.edit_text("🗑 *Введите username канала для удаления из чёрного списка:*", parse_mode="Markdown")
    await c.answer()

@dp.message(lambda m: m.state == "waiting_blacklist_remove")
async def process_blacklist_remove(m: types.Message, state: FSMContext):
    username = m.text.strip()
    if username.startswith("@"):
        username = username[1:]
    async with db_pool.acquire() as conn:
        await conn.execute("DELETE FROM channel_blacklist WHERE username = $1", username)
    await m.answer(f"✅ Канал @{username} удалён из чёрного списка", reply_markup=main_kb(m.from_user.id))
    await state.clear()

@dp.callback_query(F.data == "admin_monitor_add")
async def admin_monitor_add(c: types.CallbackQuery, state: FSMContext):
    await state.set_state(MonitorForm.waiting_for_username)
    await c.message.edit_text("📋 *Введите username канала:*", parse_mode="Markdown")
    await c.answer()

@dp.callback_query(F.data == "admin_monitor_list")
async def admin_monitor_list(c: types.CallbackQuery):
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("SELECT username, added_at FROM monitored_channels ORDER BY added_at")
    if not rows:
        await c.message.edit_text("📭 Список пуст", reply_markup=admin_panel_kb())
        return
    text = "📋 *Мониторинг:*\n"
    for r in rows:
        text += f"├ @{r['username']}\n"
    await c.message.edit_text(text, parse_mode="Markdown", reply_markup=admin_panel_kb())
    await c.answer()

@dp.callback_query(F.data == "admin_monitor_remove")
async def admin_monitor_remove(c: types.CallbackQuery, state: FSMContext):
    await state.set_state("waiting_remove_username")
    await c.message.edit_text("🗑 *Введите username канала для удаления:*", parse_mode="Markdown")
    await c.answer()

@dp.callback_query(F.data == "admin_teach")
async def admin_teach(c: types.CallbackQuery, state: FSMContext):
    await state.set_state(TeachForm.waiting_for_description)
    await c.message.edit_text(
        "🧠 *Обучение модели*\n\n"
        "Опишите новый вид мошенничества. Пример:\n"
        "`Канал обещает раздачу криптовалюты за переход по ссылке`",
        parse_mode="Markdown"
    )
    await c.answer()

@dp.message(StateFilter(TeachForm.waiting_for_description))
async def process_teach(m: types.Message, state: FSMContext):
    description = m.text.strip()
    keywords = ' '.join(re.findall(r'\b\w{5,}\b', description.lower()))
    async with db_pool.acquire() as conn:
        await conn.execute("INSERT INTO teach_examples (description, keywords) VALUES ($1, $2)", description, keywords)
    success = await train_model()
    if success:
        await m.answer("✅ Модель обучена!", reply_markup=main_kb(m.from_user.id))
    else:
        await m.answer("⚠️ Нужно минимум 3 примера", reply_markup=main_kb(m.from_user.id))
    await state.clear()

@dp.callback_query(F.data == "admin_export")
async def admin_export(c: types.CallbackQuery):
    if c.from_user.id not in ADMIN_IDS:
        return
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("SELECT username, risk_score, risk_level, scanned_at FROM scan_logs ORDER BY scanned_at DESC")
    if not rows:
        await c.answer("Нет данных для экспорта", show_alert=True)
        return
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Username", "Risk Score", "Risk Level", "Scanned At"])
    for row in rows:
        writer.writerow([row['username'], row['risk_score'], row['risk_level'], row['scanned_at'].strftime("%Y-%m-%d %H:%M:%S")])
    output.seek(0)
    file = BufferedInputFile(output.getvalue().encode('utf-8-sig'), filename="scan_export.csv")
    await c.message.answer_document(file, caption="📁 Экспорт всех проверок")
    await c.answer()

# -------------------- ЕЖЕДНЕВНЫЙ МОНИТОРИНГ --------------------
async def daily_monitor():
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("SELECT username FROM monitored_channels")
    for row in rows:
        result = await check_channel(row['username'])
        if result.get("risk_level") == "high":
            for admin_id in ADMIN_IDS:
                await bot.send_message(admin_id, f"⚠️ *Высокий риск!* Канал @{row['username']} ({result['risk_score']} баллов)\nПроверьте @{row['username']}", parse_mode="Markdown")

# ==================== FLASK ДЛЯ HEALTHCHECK ====================
flask_app = Flask(__name__)

@flask_app.route('/')
def health():
    return "OK", 200

def run_flask():
    flask_app.run(host='0.0.0.0', port=PORT, debug=False, use_reloader=False)

async def self_pinger():
    url = f"{PUBLIC_URL}/"
    while True:
        await asyncio.sleep(240)
        try:
            async with aiohttp.ClientSession() as s:
                await s.get(url, timeout=10)
        except:
            pass

# ==================== ЗАПУСК ====================
async def main():
    await init_db()
    scheduler = AsyncIOScheduler()
    scheduler.add_job(daily_monitor, 'cron', hour=9, minute=0)
    scheduler.start()
    threading.Thread(target=run_flask, daemon=True).start()
    asyncio.create_task(self_pinger())
    await bot.delete_webhook(drop_pending_updates=True)
    logger.info("Бот запущен (с топом, чёрным списком и экспортом)")
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
