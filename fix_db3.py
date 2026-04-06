with open("app/services/database.py", "r") as f:
    content = f.read()

content = content.replace(
    "class PhishingDatabase:",
    "class PhishingDatabase:\n    def get_recent_history(self, limit=20):\n        return self.get_recent_scans(limit)\n"
)

with open("app/services/database.py", "w") as f:
    f.write(content)
