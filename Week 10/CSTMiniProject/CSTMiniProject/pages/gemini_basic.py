import google.generativeai as genai

#configure the API key
genai.configure(api_key="AIzaSyB9IQr1sHlMgqPiXcjwwn6ca7BxADPJ7xA")

#create the model
model = genai.GenerativeModel("gemini-2.5-flash")

#generate content
response = model.generate_content("Hello! What is AI?")

#print the response
print(response.text)