from flask import Flask, request, jsonify
import google.generativeai as genai

app = Flask(__name__)

@app.route('/gemini', methods=['POST'])
def gemini_proxy():
    data = request.get_json()
    prompt = data.get('prompt')
    api_key = data.get('api_key')
    
    if not prompt or not api_key:
        return jsonify({"error": "Missing prompt or api_key"}), 400

    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-2.0-flash')
        response = model.generate_content(prompt)
        return jsonify({"text": response.text})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/')
def home():
    return "Dragon Proxy is Online!"
