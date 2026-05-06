import json

# ---- File paths ----
txt_file = "data/malicious_slugs.txt"       # your txt file with one slug per line
json_file = "data/clawhub_skills_meta_original.json"    # your json file

# ---- Load slugs from txt ----
with open(txt_file, "r") as f:
    txt_slugs = set(line.strip() for line in f if line.strip())

# ---- Load JSON keys ----
with open(json_file, "r") as f:
    data = json.load(f)
    json_keys = set(data.keys())

# ---- Find matches ----
matched = txt_slugs.intersection(json_keys)

# ---- Results ----
print(f"Total slugs in TXT: {len(txt_slugs)}")
print(f"Total keys in JSON: {len(json_keys)}")
print(f"Matched slugs: {len(matched)}")

print("\nMatched Slugs:")
with open("data/matched_slugs.txt", "w") as f:
    for slug in sorted(matched):
        f.write(slug + "\n")