import os
import asyncio
from flask import Flask, request
import google.generativeai as genai
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters

app = Flask(__name__)

# السواريت (بما أنهم تفضحوا، عاود بدلهم فاش تسالي التجربة)
TOKEN = "8276762679:AAFaTnZB7HvAhedxsTXG4h6jny1A6-88Aog"
GEMINI_KEY = "AIzaSyDzQHHjUxj61fd5RUDmM3wEm5ND3yAXWS4"

genai.configure(api_key=GEMINI_KEY)
model = genai.GenerativeModel('gemini-2.0-flash')

application = Application.builder().token(TOKEN).build()

async def start(update: Update, context):
    await update.message.reply_text("Dragon Bot Online! 🐉 صيفط سؤالك دابا.")

async def handle_message(update: Update, context):
    try:
        response = model.generate_content(update.message.text)
        await update.message.reply_text(response.text)
    except Exception:
        await update.message.reply_text("Error with Gemini API.")

application.add_handler(CommandHandler("start", start))
application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

@app.route('/webhook', methods=['POST'])
async def webhook():
    if request.method == "POST":
        update = Update.de_json(request.get_json(force=True), application.bot)
        # ضروري نديرو initialize و start للتطبيق ف الـ Serverless
        await application.initialize()
        await application.process_update(update)
        return "ok", 200

@app.route('/')
def home():
    return "Bot is Running! 🚀"
