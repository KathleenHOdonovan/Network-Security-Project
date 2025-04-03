# Import necessary libraries from Hugging Face
from transformers import GPT2LMHeadModel, GPT2Tokenizer

# Load the pre-trained GPT-2 model and tokenizer
model_name = "gpt2"  # This loads the smaller version of GPT-2, you can also use 'gpt2-medium', 'gpt2-large', 'gpt2-xl'

tokenizer = GPT2Tokenizer.from_pretrained(model_name)
model = GPT2LMHeadModel.from_pretrained(model_name)

# Make sure the model is in evaluation mode
model.eval()

# Function to generate text based on a prompt
def generate_text(prompt):
    inputs = tokenizer.encode(prompt, return_tensors="pt")  # Tokenize the input prompt
    outputs = model.generate(inputs, max_length=100, num_return_sequences=1, no_repeat_ngram_size=2, temperature=0.7)
    
    generated_text = tokenizer.decode(outputs[0], skip_special_tokens=True)  # Decode the generated tokens into text
    return generated_text

# Test with a sample prompt
prompt = "The future of AI is"
generated_output = generate_text(prompt)

print(generated_output)