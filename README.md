# 🔐 Password Strength Analyzer with Custom Wordlist Generator

### 🚀 Internship Project (2 Weeks)
**Organization:** Elevate Lab  
**Phase:** Internship Project Phase  
**Project Title:** Password Strength Analyzer with Custom Wordlist Generator  
**Intern Name:** Lekha Sri G  
**Duration:** 2 Weeks  

---

## 🧭 Project Overview

This project aims to **analyze the strength of passwords** and **generate customized wordlists** for cybersecurity learning and password auditing purposes.  
It demonstrates the use of **Python-based security automation**, **entropy-based strength estimation**, and **custom input-based dictionary creation**.

This tool was developed as part of the Elevate Lab Internship Project Phase. It helps users understand how passwords are evaluated in penetration testing and how customized wordlists are built for ethical security assessments.

---

## 🎯 **Objective**

To build a Python tool that:
- Analyzes password strength using **zxcvbn** or a custom entropy estimator.
- Generates **custom attack wordlists** based on user inputs like names, dates, pets, etc.
- Supports **CLI (Command Line Interface)** and **GUI (Graphical Interface)** for better usability.
- Exports results to a `.txt` file ready for password testing tools (like Hydra or Hashcat).
- Provides feedback on password weaknesses for defensive security learning.

---

## 🧰 **Tools & Technologies Used**

| Tool / Library | Purpose |
|----------------|----------|
| **Python 3** | Core language for implementation |
| **argparse** | Command-line interaction |
| **Tkinter** | GUI interface for non-technical users |
| **zxcvbn (optional)** | Advanced password strength estimation |
| **NLTK (optional)** | Natural language processing for token handling |
| **itertools, math, re, os** | Logic, combinations, and pattern handling |

---

## 🧱 **Features**

✅ **Password Strength Analysis**
- Evaluates password strength based on entropy or zxcvbn scoring.
- Detects patterns like years, repeated characters, and common dictionary words.
- Gives clear feedback and recommendations for improvement.

✅ **Custom Wordlist Generator**
- Accepts user details (name, pet, birth year, extra words).
- Creates realistic password candidates by:
  - Applying leetspeak variants (`a` → `@`, `s` → `$`, etc.)
  - Adding prefixes/suffixes and common number patterns.
  - Appending years or custom ranges (e.g., 2000–2025).
- Outputs to a ready-to-use `.txt` file for password testing tools.

✅ **Dual Interface**
- **CLI Mode** — for cybersecurity learners and professionals.
- **GUI Mode** — for users who prefer graphical interaction.

✅ **Failsafe Operation**
- Works even if optional libraries (`zxcvbn`, `nltk`) are not installed.
- Automatically switches to built-in entropy estimation.

---

## 🧮 **How It Works**

### 1️⃣ Password Analysis Mode

The tool calculates **entropy** (a measure of unpredictability) using either:
- **zxcvbn library** (if available): gives real-world pattern feedback.
- **Custom estimator**: uses pool size, repetitions, and length-based penalties.

Then it provides:
- A **strength label** (Very Weak → Very Strong)
- An **entropy value**
- **Feedback** explaining how to make the password stronger.

---

### 2️⃣ Wordlist Generation Mode

You provide basic details such as:
- **Name(s)** → “alice bob”
- **Pet name(s)** → “rex”
- **Birth/Year range** → “1995” or “2000-2025”
- **Extra words** → “hello, welcome”

The generator then:
1. Expands each word with **leet variants** and **prefix/suffix** additions.
2. Appends **years** and **numbers**.
3. Combines the variants up to a defined limit (`--max`).
4. Saves the final list to a text file like `custom_wordlist.txt`.

---

## 🖥️ **Usage Guide**

### ▶️ **1. Installation**

```bash
pip install zxcvbn nltk
```

### ▶️ **2. Running the Tool**

#### Analyze password strength (CLI)

```bash
python pwtool.py --analyze 'P@ssw0rd2021!'
```

#### Generate custom wordlist

```bash
python pwtool.py --generate   --name "Alice Bob"   --pet "Rex"   --birth "1990"   --years 2005-2024   -o mylist.txt --max 10000
```
#### Screenshot
(Screenshots/Screenshot_2025-10-28_01_47_22.png)

#### Start GUI mode

```bash
python pwtool.py --gui
```

---

## 📊 **Example Output**

### **Password Analysis**

```
Password analysis:
  Password: P@ssw0rd2021!
  Entropy: 55.6
  Score: Strong
  Feedback:
   - Password contains a year — years are common and predictable.
   - Add more unique symbols to increase strength.
```

### **Wordlist Generation**

```
Generating wordlist from inputs: {'name': 'Alice Bob', 'pet': 'Rex', 'birth': '1990', 'extra': ''}
  Generated 9856 words (limited to max=10000).
  Wordlist written to: mylist.txt
```

---

## 🧩 **Project Steps**

1. **Research Phase**
   * Studied password entropy and strength evaluation methods.
   * Analyzed common password generation patterns.

2. **Tool Development**
   * Designed CLI structure using `argparse`.
   * Added GUI using `Tkinter`.
   * Integrated entropy-based password strength analysis.

3. **Testing Phase**
   * Tested password variations for strength analysis.
   * Verified generated wordlists with known cracking tools.

4. **Report Preparation**
   * Summarized implementation, tools used, and usage instructions.

---

## 🧾 **Conclusion**

This project demonstrates how password security can be **quantitatively analyzed** and how customized **wordlists** can be automatically generated for **ethical security assessments**.
The tool promotes awareness of password strength, helping users and organizations improve digital hygiene and secure authentication practices.

The developed Python script (`pwtool.py`) is reliable, extendable, and easily adaptable for real-world **VAPT (Vulnerability Assessment and Penetration Testing)** practice.

---

## ⚙️ **Future Improvements**

* Integration of **keyboard pattern detection** (qwerty, 1234, asdf).
* Exporting **Hashcat-compatible rules** for advanced cracking.
* Adding **password breach API lookup** (HaveIBeenPwned).
* Improving GUI aesthetics using `customtkinter` or `PyQt5`.

---

## ⚖️ **Ethical Use Notice**

This tool is developed **strictly for educational and defensive cybersecurity purposes**.
Do **not** use it to test or attack systems without proper authorization.
Always obtain written permission before conducting any security assessment.

---

**Prepared by:**  
👤 **Intern Name:** Lekha Sri G  
📅 **Duration:** 2 Weeks  
🏢 **Organization:** Elevate Lab  
