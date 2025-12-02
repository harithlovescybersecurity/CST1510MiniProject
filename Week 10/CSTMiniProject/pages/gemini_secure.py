import google.generativeai as genai
from dotenv import load_dotenv
import os

#load environment variables from .env file
load_dotenv()

#get API key from environment variable
api_key = os.getenv("GENAI_API_KEY")

#initialize client
genai.configure(api_key=api_key)

messages = [{"role": "user", "parts": ["You are a helpful assistant"]}]

print("Gemini Console Chat (type 'quit' to exit)")
print("-" * 50)

while True:
    user_input = input("You: ")
    if user_input.lower() == "quit":
        print("Goodbye")
        break

    #add user message to history
    messages.append({"role": "user", "parts": [user_input]})

    #get AI response
    response = genai.GenerativeModel("gemini-2.5-flash").generate_content(messages)
    assistant_message = response.text

    #add assistant response to history
    messages.append({"role": "user", "parts": [assistant_message]})

    print(f"AI: {assistant_message}\n")