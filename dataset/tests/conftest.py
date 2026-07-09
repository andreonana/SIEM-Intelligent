import sys
from pathlib import Path

# Rend dataset/ importable depuis pytest
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
