import asyncio
from aiogram import Bot
from dotenv import load_dotenv
from pathlib import Path
import os

dotenv_path = Path(__file__).parent.parent.absolute()
load_dotenv(dotenv_path=os.path.join(dotenv_path, '.env.dev'))
BOT_TOKEN = os.getenv('BOT_TOKEN')

async def main():
    bot = Bot(token=BOT_TOKEN)
    try:
        me = await bot.get_me()
        print("Hello")
    finally:
        await bot.close()

asyncio.run(main())

