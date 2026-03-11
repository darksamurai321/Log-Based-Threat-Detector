import sys
import os

# Ensure the system sees the current directory modules
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

from gui import LogThreatApp

if __name__ == "__main__":
    app = LogThreatApp()
    app.mainloop()