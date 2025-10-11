import requests
import json

url = "https://routellm.abacus.ai/v1/chat/completions"
headers = {"Authorization": "Bearer s2_740eb068e89f4eec9d7c8762e09db7a0", "Content-Type": "application/json"}
stream = True # or False
payload = {
  "model": "route-llm",
  "messages": [
    {
      "role": "user",
      "content": "What is the meaning of life?"
    }
  ],
  "stream": stream
}
if stream:
  response = requests.post(url, headers=headers, data=json.dumps(payload), stream=True)
  for line in response.iter_lines():
    if line:
      line = line.decode("utf-8")
      if line.startswith("data: "):
        line = line[6:]
        if line == "[DONE]":
          break
        chunk = json.loads(line)
        if chunk["choices"][0].get("delta"):
          print(chunk["choices"][0]["delta"]["content"])
else:
  response = requests.post(url, headers=headers, data=json.dumps(payload))
  print(response.json())
