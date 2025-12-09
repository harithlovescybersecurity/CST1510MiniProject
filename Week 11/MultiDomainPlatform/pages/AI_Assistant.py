import streamlit as st
import google.generativeai as genai

class AIAssistant:
    def __init__(self):
        pass

    def run(self):
        st.set_page_config(page_title="Gemini Interactive",layout="wide")

        #added login function
        if "logged_in" not in st.session_state or not st.session_state.logged_in:
            st.error("Please login first")
            st.stop()

        #config the api key
        genai.configure(api_key="key")

        #initializes the conversation history
        if "messages" not in st.session_state:
            st.session_state.messages = []

        st.title("Gemini Interactive")
        st.write("Type 'quit' to exit")
        st.write("-" * 50)

        #display chat history
        for msg in st.session_state.messages:
            if msg["role"] == "user":
                st.write(f"**You:** {msg['parts'][0]}")
            else:
                st.write(f"**AI:** {msg['parts'][0]}")
            st.write("")

        #get user input
        user_input = st.text_input("Type your message...")

        #exit condition
        if user_input:
            if user_input.lower() == "quit":
                st.write("Goodbye")
                st.stop()

            #add user message to history
            st.session_state.messages.append({"role": "user", "parts": [user_input]})

            try:
                #get AI response
                response = genai.GenerativeModel("gemini-2.5-flash").generate_content(user_input)

                #extract response
                assistant_message = response.text

                #add assistant response to history
                st.session_state.messages.append({"role": "model", "parts": [assistant_message]})

                #display response
                st.write(f"AI: {assistant_message}\n")
                st.rerun()

            except Exception as e:
                st.write(f"Error: {e}\n")
                st.rerun()

assistant = AIAssistant()
assistant.run()

