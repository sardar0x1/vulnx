import json
import torch
from transformers import pipeline

def load_model():
    """Loads the text generation model only once."""
    print("Loading local AI model... This might take a few minutes on the first run.")
    try:
        text_generator = pipeline(
            "text-generation",
            model="TinyLlama/TinyLlama-1.1B-Chat-v1.0",
            torch_dtype=torch.bfloat16,
            device_map="auto"
        )
        print("AI Model loaded successfully.")
        return text_generator
    except Exception as e:
        print(f"FATAL: Failed to load AI model: {e}")
        print("AI features will be disabled.")
        return None

# Load the model when the module is first imported
generator = load_model()

def get_ai_analysis(vuln_name, vuln_url):
    """Analyzes vulnerability using the pre-loaded local model."""
    if not generator:
        return "AI model is not available.", "AI model is not available."

    messages = [
        {"role": "system", "content": "You are a helpful cybersecurity assistant. Provide your response in a clean JSON format."},
        {"role": "user", "content": f'A scan found a vulnerability. Name: "{vuln_name}", URL: "{vuln_url}". Provide a JSON object with two keys: "summary" (a simple explanation) and "mitigation" (a short fix).'},
    ]

    prompt = generator.tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)

    try:
        outputs = generator(prompt, max_new_tokens=256, do_sample=True, temperature=0.7, top_k=50, top_p=0.95)
        generated_text = outputs[0]["generated_text"]
        
        json_part = generated_text.split("<|assistant|>")[-1].strip()
        
        start_index = json_part.find('{')
        end_index = json_part.rfind('}') + 1
        
        if start_index != -1 and end_index != 0:
            clean_json_str = json_part[start_index:end_index]
            analysis = json.loads(clean_json_str)
            return analysis.get('summary', 'Summary not found.'), analysis.get('mitigation', 'Mitigation not found.')
        else:
            raise ValueError("No valid JSON object found in response.")
    except Exception as e:
        print(f"Error processing model response: {e}")
        return "AI analysis failed.", "Could not generate mitigation."
