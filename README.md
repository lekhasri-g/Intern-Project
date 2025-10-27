# Intern-Main Project
| Intern Project submission to elevate labs by Lekha Sri G |
GitHub README.md file 👇


---

🔐 Password Strength Analyzer with Custom Wordlist Generator

🧠 Internship Project — Elevate Lab

Duration: 2 Weeks
Internship Phase: Project Phase


---

📋 Overview

This project is a Python-based cybersecurity tool that analyzes password strength and generates custom wordlists for learning and password auditing.
It helps users understand how passwords are evaluated during security assessments and how personalized attack wordlists are created for ethical penetration testing.


---

🎯 Objective

To build a tool that:

Analyzes password strength using zxcvbn or a custom entropy calculator.

Generates custom wordlists from user details like names, dates, and pets.

Supports both CLI (Command Line Interface) and GUI (Tkinter) modes.

Exports password analysis and generated lists to .txt files for use with tools such as Hydra or Hashcat.

Provides security feedback to help improve password hygiene.



---

⚙️ Tools & Libraries Used

Tool / Library	Purpose

Python 3	Core language
argparse	CLI interface
Tkinter	GUI for end users
zxcvbn (optional)	Advanced password analysis
NLTK (optional)	Token processing
itertools, math, re, os	Logic, pattern, and combination handling



---

🌟 Features

🔎 Password Strength Analyzer

Uses entropy or zxcvbn scoring.

Detects weak patterns (e.g., years, repetitions, dictionary words).

Provides feedback and recommendations for improvement.


🧩 Custom Wordlist Generator

Takes user inputs such as names, pets, birth years, or extra words.

Generates password candidates using:

Leetspeak transformations (a → @, s → $, etc.)

Prefixes/suffixes and number sequences.

Year appending (e.g., 2000–2025).


Outputs ready-to-use .txt wordlists.


🖥️ Dual Interface

CLI Mode: For professionals and command-line users.

GUI Mode: Simple Tkinter interface for beginners.


🧰 Bonus Functions

Hashcat rule generation for mangling patterns.

ZIP bundling for packaging the tool and generated samples.

Interactive mode for guided step-by-step use.



---

🚀 How It Works

🔐 Password Analysis Mode

The tool estimates entropy using either:

zxcvbn library (if installed), or

a custom entropy calculator that factors in:

character set diversity

repetition penalties

dictionary and year detection



Output Includes:

Strength label (Very Weak → Very Strong)

Entropy value

Improvement feedback


🧠 Wordlist Generation Mode

You provide:

Names, pets, or dates

Year range (e.g., 2000-2025)

Optional extra words


The generator:

1. Expands entries with leetspeak variants.


2. Adds prefixes, suffixes, and years.


3. Produces a comprehensive .txt wordlist.




---

💻 Installation

pip install zxcvbn nltk


---

🧮 Usage Guide

1️⃣ Analyze a Password

python pwtool.py --analyze "P@ssw0rd2021!"

2️⃣ Generate Custom Wordlist

python pwtool.py --generate \
--name "Alice Bob" \
--pet "Rex" \
--birth "1990" \
--years 2005-2024 \
-o mylist.txt --max 10000

3️⃣ Launch GUI Mode

python pwtool.py --gui

4️⃣ Start Interactive Mode

python pwtool.py --interactive


---

🧾 Example Output

🔎 Password Analysis

Password: P@ssw0rd2021!
Entropy: 55.6
Score: Strong
Feedback:
 - Password contains a year — years are common and predictable.
 - Add more unique symbols to increase strength.

🧩 Wordlist Generation

Generating wordlist from inputs: {'name': 'Alice Bob', 'pet': 'Rex', 'birth': '1990', 'extra': ''}
Generated 9856 words (limited to max=10000).
Wordlist written to: mylist.txt


---

🧱 Project Phases

1. Research:
Studied password entropy, attack patterns, and dictionary creation.


2. Development:
Built CLI with argparse, added Tkinter GUI, and entropy scoring.


3. Testing:
Verified password analysis and generated lists with cracking tools.


4. Documentation:
Prepared README and internship project report.




---

🧭 Future Enhancements

Detect keyboard patterns (qwerty, 1234, asdf).

Generate Hashcat-compatible rules automatically.

Add breach database lookup (HaveIBeenPwned API).

Modernize GUI using customtkinter or PyQt5.



---

⚠️ Ethical Use Notice

This tool is for educational and defensive security purposes only.
Do not use it for unauthorized penetration testing.
Always obtain explicit written permission before conducting security assessments.


---

Prepared by:
🧑‍💻 Intern Name: Lekha Sri G 
📅 Duration: 2 Weeks
🏢 Organization: Elevate Lab


---

