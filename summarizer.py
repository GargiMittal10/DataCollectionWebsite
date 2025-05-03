from transformers import pipeline
import sys
import json
from collections import Counter

# Load FLAN-T5 pipeline for text-to-text summarization
summarizer = pipeline("text2text-generation", model="google/flan-t5-large")

# Read JSON input from stdin
data = sys.stdin.read()
parsed = json.loads(data)

# Clean and deduplicate responses
def clean_responses(responses):
    blacklist = {"", "none", "na", "nil", "nothing", ".", "-", "no", "None", "N/A", "n/a"}
    cleaned = [r.strip().capitalize() for r in responses if r.strip().lower() not in blacklist]
    return list(set(cleaned))

# Extract top keywords for summarization guidance
def extract_keywords(responses, top_n=10):
    words = " ".join(responses).lower().split()
    common = Counter(words).most_common(top_n)
    return [w for w, _ in common]

# Generate detailed 3–4 sentence summary for each section
def summarize_responses(responses, label):
    responses = clean_responses(responses)
    if not responses:
        return f"No significant {label} were shared by the students."

    keyword_summary = ", ".join(extract_keywords(responses))
    combined_text = " ".join(responses)

    prompt = f"""
You are summarizing detailed feedback from nursing students about their **{label}** during a clinical simulation lab.
Your task is to write a **cohesive, detailed, and professional summary** using **3–4 full sentences**. Avoid bullet points. Focus on synthesizing common patterns, specific examples, and meaningful reflections. Write in a professional, human-like tone (not robotic or generic).

Guidelines for {label}:
- **Strengths**: Discuss key abilities, technical and communication skills, confidence levels, and what students felt they performed well in. Mention common positive experiences or improvements observed.
- **Challenges**: Focus on the main difficulties or discomforts students faced, such as confidence issues, handling equipment, time constraints, team dynamics, or procedural knowledge gaps.
- **Suggestions**: Capture concrete ideas proposed by students to enhance the lab — such as extending time for certain tasks, requesting more demonstrations, clearer instructions, or smaller group sizes.

Use the following commonly used keywords to guide your summary: {keyword_summary}

Here are the actual student responses (cleaned and deduplicated):

{combined_text}

Now write a high-quality summary in 3–4 sentences:
"""

    result = summarizer(prompt.strip(), max_new_tokens=350, do_sample=False)[0]['generated_text']
    return result.strip().replace(" .", ".").replace(" ,", ",")

# Run summarization for each section
strengths_summary = summarize_responses(parsed.get("strengths", []), "strengths")
challenges_summary = summarize_responses(parsed.get("challenges", []), "challenges")
suggestions_summary = summarize_responses(parsed.get("suggestions", []), "suggestions")

# Output JSON with detailed summaries
result = {
    "strengths": strengths_summary,
    "challenges": challenges_summary,
    "suggestions": suggestions_summary
}

print(json.dumps(result, indent=2))
