import streamlit as st
import google.generativeai as genai

#page
st.set_page_config(
    page_title="Cybersecurity AI Assistant",
    page_icon="💬",
    layout="wide",
)

genai.configure(api_key=st.secrets["GEMINI_API_KEY"])

st.title("Cyber Security Assistant")
st.caption("Powered by Google Gemini")

#initialize chat history in session state
if "messages" not in st.session_state:
    st.session_state.messages = []
    st.session_state.system_prompt = """You are a cyber security assistant.
            - Analyze incidents and threats
            - Provide technical guidance
            - Explain attack vectors and mitigations
            - Use standard terminology (MITRE ATT&CK, CVE)
            - Prioritize actionable recommendations
            Tone: Professional, technical
            Format: Clear, structured responses"""

#sidebar with controls
with st.sidebar:
    st.subheader("Chat controls")

    #displaying message count
    message_count = len([m for m in st.session_state.messages if m["role"] == "user"])
    st.metric("Messages", message_count)

    #clear chat option
    if st.button("🗑️ Clear Chat", use_container_width=True):
        st.session_state.messages = []
        st.rerun()

    #Temperature slider
    temperature = st.slider(
        "Temperature",
        min_value=0.0,
        max_value=1.0,
        value=0.7,
        step=0.1,
        help="Higher values make output more creative"
    )

#display chat messages from history on app rerun
for message in st.session_state.messages:
     with st.chat_message(message['role']):
         st.write(message["content"])

prompt = st.chat_input("Ask about security incidents...")

if prompt:
    #displaying user message in chat message container
    with st.chat_message("user"):
        st.write(prompt)
    #adding user message to chat history
    st.session_state.messages.append({"role": "user", "content": prompt})

    #getting AI response
    model = genai.GenerativeModel("gemini-2.5-flash")
    #including system prompt in the request
    full_prompt = f"{st.session_state.system_prompt}\n\nUser: {prompt}"

    #displaying assistant message in chat message container
    with st.chat_message("assistant"):
        message_placeholder = st.empty()
        full_response = ""

        #stream the response
        response = model.generate_content(
            full_prompt,
            stream=True,
            generation_config=genai.types.GenerationConfig(temperature=temperature)
        )
        for chunk in response:
            if chunk.text:
                full_response += chunk.text
                message_placeholder.write(full_response + "▌")

        #removes the cursor and displays the final response
        message_placeholder.write(full_response)

    #add assistant response to chat history
    st.session_state.messages.append({"role": "assistant", "content": full_response})
