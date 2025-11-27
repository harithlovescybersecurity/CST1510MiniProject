import google.generativeai as genai

#configure the API key
genai.configure(api_key="AIzaSyB9IQr1sHlMgqPiXcjwwn6ca7BxADPJ7xA")

#initialize conversation history
messages = [{"role": "user", "parts": ["You are a helpful assistant"]}]
print("Gemini Console Chat (type 'quit' to exit)")
print("-" * 50)

while True:
    #get user input
    user_input = input("You:")

    #exit condition
    if user_input.lower() == 'quit':
        print("Goodbye!")
        break

    #add user message to history
    messages.append({"role": "user", "parts": [user_input]})

    try:
        #get AI response
        response = genai.GenerativeModel("gemini-2.5-flash").generate_content(messages)

        #extract response
        assistant_message = response.text

        #add assistant response to history
        messages.append({"role": "model", "parts": [assistant_message]})

        #display response
        print(f"AI: {assistant_message}\n")
    except Exception as e:
        print(f"Error: {e}\n")
