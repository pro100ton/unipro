import asyncio
import logging
import os
from pathlib import Path

from dotenv import load_dotenv
import telegram


# Configuring logger
logging.basicConfig(level=logging.INFO)
dotenv_path = Path(__file__).parent.parent.absolute()
load_dotenv(dotenv_path=os.path.join(dotenv_path, '.env.dev'))
BOT_TOKEN = os.getenv('BOT_TOKEN')

bot = telegram.Bot(token=BOT_TOKEN)
print(bot.get_me())
