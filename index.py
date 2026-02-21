from flask import Flask, request
import google.generativeai as genai
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
import os, asyncio

app = Flask(__name__)

# السواريت ديالك حطيتهم ليك هنا نيشان باش يخدم البوت فالحين
TOKEN = "8276762679:AAFaTnZB7Hv-hedxsTXG4h6jny1A6-88Aog"
GEMINI_KEY = "AIzaSyDzQHHjUxj61fd5RUDmM3wEm5ND3yAXWS4"

genai.configure(api_key=GEMINI_KEY)
model = genai.GenerativeModel('gemini-2.0-flash')

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Dragon Bot Online! صيفط أي سؤال دابا وغادي يجاوبك Gemini 🚀")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_msg = update.message.text
    try:
        # هنا Gemini كيتكلف بالجواب
        response = model.generate_content(user_msg)
        await update.message.reply_text(response.text)
    except Exception as e:
        await update.message.reply_text("عذراً، وقع مشكل ف الاتصال بـ Gemini.")

@app.route('/webhook', methods=['POST'])
async def webhook():
    application = Application.builder().token(TOKEN).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    
    async with application:
        update = Update.de_json(request.get_json(force=True), application.bot)
        await application.process_update(update)
    return "ok"

@app.route('/')
def home():
    return "Dragon Bot is Running!"
