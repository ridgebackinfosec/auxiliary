import os

NO_COLOR = (os.environ.get("NO_COLOR") is not None) or (os.environ.get("TERM") == "dumb")

class C:
    RESET  = "" if NO_COLOR else "\u001b[0m"
    BOLD   = "" if NO_COLOR else "\u001b[1m"
    BLUE   = "" if NO_COLOR else "\u001b[34m"
    GREEN  = "" if NO_COLOR else "\u001b[32m"
    YELLOW = "" if NO_COLOR else "\u001b[33m"
    RED    = "" if NO_COLOR else "\u001b[31m"
    CYAN   = "" if NO_COLOR else "\u001b[36m"
    MAGENTA= "" if NO_COLOR else "\u001b[35m"

def header(msg): print(f"{C.BOLD}{C.BLUE}\n{msg}{C.RESET}")
def ok(msg):     print(f"{C.GREEN}{msg}{C.RESET}")
def warn(msg):   print(f"{C.YELLOW}{msg}{C.RESET}")
def err(msg):    print(f"{C.RED}{msg}{C.RESET}")
def info(msg):   print(msg)
def fmt_action(text): return f"{C.CYAN}>> {text}{C.RESET}"
def fmt_reviewed(text): return f"{C.MAGENTA}{text}{C.RESET}"
def cyan_label(s: str) -> str: return f"{C.CYAN}{s}{C.RESET}"

def colorize_severity_label(label: str) -> str:
    L = label.strip().lower()
    if "critical" in L:
        color = C.RED
    elif "high" in L:
        color = C.YELLOW
    elif "medium" in L:
        color = C.BLUE
    elif "low" in L:
        color = C.GREEN
    elif "info" in L:
        color = C.CYAN
    else:
        color = C.MAGENTA
    return f"{C.BOLD}{color}{label}{C.RESET}"
