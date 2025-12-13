import streamlit as st
import google.generativeai as genai
import time

class CyberSecurityAIAssistant:
    def __init__(self):
        #initialize session state if not exists
        if "messages" not in st.session_state:
            st.session_state.messages = []

        if "system_prompt" not in st.session_state:
            st.session_state.system_prompt= """You are a cyber security assistant.
            - Analyze incidents and threats
            - Provide technical guidance
            - Explain attack vectors and mitigations
            - Use standard terminology (MITRE ATT&CK, CVE)
            - Prioritize actionable recommendations
            Tone: Professional, technical
            Format: Clear, structured responses"""

        #config AI
        genai.configure(api_key=st.secrets["GENAI_API_KEY"])

        #set page config
        st.set_page_config(
            page_title="Cybersecurity AI Assistant",
            page_icon="💬",            layout="wide",
        )

    def render_sidebar(self):
        with st.sidebar:
            st.subheader("Chat controls")

            #displaying the message count
            message_count = len([m for m in st.session_state.messages if m["role"] == "user"])
            st.metric("Messages", message_count)

            #clear chat options
            if st.button("🗑️ Clear Chat", use_container_width=True):
                st.session_state.messages = []
                st.rerun()

            #temperature slider
            temperature = st.slider("Temperature",
                min_value=0.0,
                max_value=1.0,
                value=0.7,
                step=0.1,
                help="Higher values make output more creative"
            )
            return temperature

    def display_chat_history(self):
        #displays chat messages from history
        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.write(message["content"])

    def get_ai_response(self, prompt, temperature):
        model = genai.GenerativeModel("gemini-2.5-flash")
        full_prompt = f"{st.session_state.system_prompt}\n\nUser: {prompt}"

        #streaming the response
        response = model.generate_content(
            full_prompt,
            stream=True,
            generation_config=genai.types.GenerationConfig(temperature=temperature)
        )
        return response

    def stream_response(self, response):
        message_placeholder = st.empty()
        full_response = ""

        for chunk in response:
            if chunk.text:
                full_response += chunk.text
                message_placeholder.write(full_response + "▌")

        #displays the final response
        message_placeholder.write(full_response)
        return full_response

    def handle_user_input(self, temperature):
        prompt = st.chat_input("Ask about security incidents...")

        if prompt:
            # displays user message in chat message
            with st.chat_message("user"):
                st.write(prompt)

            #add user message to chat history
            st.session_state.messages.append({"role": "user", "content": prompt})

            #getting AI response
            response = self.get_ai_response(prompt, temperature)

            #displays assistant message in chat message container
            with st.chat_message("assistant"):
                full_response = self.stream_response(response)
            #adds assistant response to chat history
            st.session_state.messages.append({"role": "assistant", "content": full_response})

    def run(self):
        st.title("AI Assistant")
        st.caption("Powered by Google Gemini")

        #sidebar
        temperature = self.render_sidebar()

        #chat history
        self.display_chat_history()

        #user input
        self.handle_user_input(temperature)

if __name__ == "__main__":
    app = CyberSecurityAIAssistant()
    app.run()
