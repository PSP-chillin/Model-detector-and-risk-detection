"""
Example vulnerable ML model file – for demonstration purposes only.
This file intentionally contains several security vulnerabilities.
DO NOT use in production.
"""
import pickle
import subprocess
import os
import yaml

# ── Vulnerability 1: Unsafe deserialization ──────────────────────────────────
def load_model(path):
    with open(path, "rb") as f:
        model = pickle.load(f)   # HIGH: unsafe deserialization
    return model


# ── Vulnerability 2: exec / eval ─────────────────────────────────────────────
def run_user_code(user_input):
    eval(user_input)             # HIGH: arbitrary code execution


# ── Vulnerability 3: Hardcoded API key ───────────────────────────────────────
OPENAI_API_KEY = "sk-abcdefghijklmnopqrstuvwxyz1234567890ABCD"  # HIGH


# ── Vulnerability 4: Shell injection ─────────────────────────────────────────
def run_preprocessing(data_path):
    subprocess.run(f"python preprocess.py {data_path}", shell=True)  # HIGH


# ── Vulnerability 5: Unsafe YAML loading ─────────────────────────────────────
def load_config(config_path):
    with open(config_path) as f:
        return yaml.load(f)      # HIGH: use yaml.safe_load instead


# ── Vulnerability 6: os.system ───────────────────────────────────────────────
def convert(file):
    os.system(f"convert {file} output.png")   # HIGH: shell injection risk
