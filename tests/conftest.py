"""Settings shared by every test."""

import os

# Services started by tests must never show real desktop notifications.
os.environ["SQUAWK_NO_NOTIFY"] = "1"
