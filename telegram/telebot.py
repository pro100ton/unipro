import asyncio
import logging
import os
from pathlib import Path

from dotenv import load_dotenv
import telegram
from telegram.ext import CallbackContext, Updater, CommandHandler


# Configuring logger
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                     level=logging.INFO)

dotenv_path = Path(__file__).parent.parent.absolute()
load_dotenv(dotenv_path=os.path.join(dotenv_path, '.env.dev'))
BOT_TOKEN = os.getenv('BOT_TOKEN')

updater = Updater(token=BOT_TOKEN, use_context=True)
dispatcher = updater.dispatcher

def start(update: Updater, context: CallbackContext):
    context.bot.send_message(chat_id = update.effective_chat.id, text="Hello, im bot")

start_handler = CommandHandler('start', start)
dispatcher.add_handler(start_handler)

updater.start_polling()
