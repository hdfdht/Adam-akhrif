import os
import asyncio
from flask import Flask, request
import google.generativeai as genai
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters

app = Flask(__name__)

# --- الإعدادات النهائية ---
# التوكن الجديد اللي عطيتي لي
TOKEN = "8276762679:AAFaTnZB7HvAhedxsTXG4h6jny1A6-88Aog"
# مفتاح Gemini
GEMINI_KEY = "AIzaSyDzQHHjUxj61fd5RUDmM3wEm5ND3yAXWS4"

# إعداد Gemini
genai.configure(api_key=GEMINI_KEY)
model = genai.GenerativeModel('gemini-2.0-flash')

# إعداد تطبيق تيليجرام
# كنخدمو بـ builder باش نجهزو التطبيق ف Vercel
application = Application.builder().token(TOKEN).build()

# --- وظائف البوت (Handlers) ---

async def start(update: Update, context):
    """هاد الدالة كتجاوب ملي المستخدم كيدير /start"""
    await update.message.reply_text("Dragon Bot Online! 🐉 صيفط سؤالك دابا وغادي يجاوبك Gemini.")

async def handle_message(update: Update, context):
    """هاد الدالة كتاخد الميساج وتصيفطو لـ Gemini"""
    user_msg = update.message.text
    try:
        # إرسال النص لـ Gemini وتوليد الجواب
        response = model.generate_content(user_msg)
        if response.text:
            await update.message.reply_text(response.text)
        else:
            await update.message.reply_text("عذراً، ما قدرتش نولد جواب.")
    except Exception as e:
        print(f"Error: {e}")
        await update.message.reply_text("وقع مشكل ف الاتصال بـ Gemini.")

# إضافة الأوامر للتطبيق
application.add_handler(CommandHandler("start", start))
application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

# --- مسارات Flask (Webhooks) ---

@app.route('/webhook', methods=['POST'])
async def webhook():
    """هاد المسار هو اللي كيستقبل الميساجات من تيليجرام"""
    if request.method == "POST":
        # تحويل البيانات اللي جاية من تيليجرام لـ Update object
        update = Update.de_json(request.get_json(force=True), application.bot)
        
        # تشغيل المعالجة
        async with application:
            await application.process_update(update)
            
        return "ok", 200

@app.route('/')
def home():
    """صفحة عادية باش تعرف بلي السيرفر خدام"""
    return "Dragon Bot is Running! 🚀"

# هاد السطر مهم لـ Vercel
app = app
