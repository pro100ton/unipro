import asyncio
import os
import logging
from pathlib import Path

from aiogram import Bot, Dispatcher, executor, types
from dotenv import load_dotenv
from aiogram.types.inline_keyboard import InlineKeyboardMarkup, InlineKeyboardButton

# Configuring logger
logging.basicConfig(level=logging.INFO)
dotenv_path = Path(__file__).parent.parent.absolute()
load_dotenv(dotenv_path=os.path.join(dotenv_path, '.env.dev'))
BOT_TOKEN = os.getenv('BOT_TOKEN')

# Initializing bot and Dispatcher
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher(bot)

@dp.message_handler(commands=['start', 'help'])
async def send_welcome(message: types.Message):
    await message.reply("Hello from bot")

@dp.message_handler(commands=['kb'])
async def send_keyboard(message: types.Message):
    button_one = InlineKeyboardButton("✅", url="github.com")
    button_two = InlineKeyboardButton("❌", url="vk.com")
    ikb = InlineKeyboardMarkup()
    ikb.row(
            button_one,
            button_two
            )
    await message.reply("Test keyboard", reply_markup=ikb)

if __name__ == '__main__':
    executor.start_polling(dp, skip_updates=True)
