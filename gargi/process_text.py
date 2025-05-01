import sys
import json

# Load the resources JSON file
with open('resources.json', 'r') as f:
    resources = json.load(f)

# Function to process the query and extract skills
def process_query(query):
    # Skills you expect to detect directly
    skills = list(resources.keys())  # Extract skills from the resources JSON
    
    # Normalize the query and check for skill matches
    query = query.lower()  # Normalize to lowercase for easier matching
    
    # Try to match any known skill in the query
    detected_skill = None
    for skill in skills:
        if skill.lower() in query:
            detected_skill = skill
            break
    
    if detected_skill:
        return get_resources_for_skill(detected_skill)
    else:
        return "Sorry, I didn't quite understand that. You can ask about your skill performance or improvement suggestions."

# Function to fetch resources for a given skill
def get_resources_for_skill(skill):
    resources_for_skill = resources.get(skill, [])
    
    if not resources_for_skill:
        return f"No resources found for {skill}."
    
    result = f"Here are the resources for {skill}:\n"
    for resource in resources_for_skill:
        result += f"Type: {resource['type']}, Link: {resource['resource']}\n"
    
    return result

# Main function to handle the input query
if _name_ == "_main_":
    query = sys.argv[1]  # Get the query from the command line argument
    result = process_query(query)
    print(result)