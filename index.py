import os
from flask import Flask, request
import google.generativeai as genai
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters

app = Flask(__name__)

# استدعاء آمن من إعدادات Vercel
TOKEN = os.getenv("TELEGRAM_TOKEN")
GEMINI_KEY = os.getenv("GEMINI_API_KEY")

genai.configure(api_key=GEMINI_KEY)
model = genai.GenerativeModel('gemini-2.0-flash')

application = Application.builder().token(TOKEN).build()

async def start(update, context):
    await update.message.reply_text("Dragon Bot Online! 🐉 دابا البوت محمي 100%.")

async def handle_message(update, context):
    try:
        response = model.generate_content(update.message.text)
        await update.message.reply_text(response.text)
    except:
        await update.message.reply_text("مشكل ف Gemini.")

application.add_handler(CommandHandler("start", start))
application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

@app.route('/webhook', methods=['POST'])
async def webhook():
    update = Update.de_json(request.get_json(force=True), application.bot)
    await application.initialize()
    await application.process_update(update)
    return "ok", 200

@app.route('/')
def home():
    return "Secure Bot is Running!"

