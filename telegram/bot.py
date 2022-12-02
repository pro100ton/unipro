import asyncio
import logging
import os
from pathlib import Path
import concurrent.futures

from dotenv import load_dotenv
from telegram.ext.filters import MessageFilter

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes, MessageHandler, filters

# Configuring logger
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                     level=logging.INFO)
executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)

dotenv_path = Path(__file__).parent.parent.absolute()
load_dotenv(dotenv_path=os.path.join(dotenv_path, '.env.dev'))
BOT_TOKEN = os.getenv('BOT_TOKEN')


logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

async def echo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await context.bot.send_message(chat_id=update.effective_chat.id, text=update.message.text)

async def rule_parser(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # context.bot.get_file(update.message.document).download()
    with open("file.json", "wb") as f:
        await context.bot.get_file(update.message.document).download(out=f)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [
        [
            InlineKeyboardButton("Option 1", callback_data='1'),
            InlineKeyboardButton("Option 2", callback_data='2'),
        ],
        [InlineKeyboardButton("Option 3", callback_data='3')],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    # await context.bot.send_message(chat_id=update.effective_chat.id, text="I'm a bot, please talk to me!")
    await update.message.reply_text("Please choose:", reply_markup=reply_markup)

if __name__ == '__main__':
    application = ApplicationBuilder().token(BOT_TOKEN).build()
    start_handler = CommandHandler('start', start)
    echo_handler = MessageHandler(filters.TEXT & (~filters.COMMAND), echo)
    application.add_handler(start_handler)
    application.add_handler(echo_handler)
    application.add_handler(MessageHandler(filters.Document.ALL, rule_parser))
    
    application.run_polling()
