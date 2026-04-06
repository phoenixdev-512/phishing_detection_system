import json, os, logging
from pathlib import Path
from packaging import version

CORPUS_DIR = Path("data/corpus")

class CorpusManager:

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._brands = None
        self._keywords = None
        self._version = None
        self._load_latest()

    def _get_latest_corpus_file(self) -> Path | None:
        if not CORPUS_DIR.exists():
            return None
        files = list(CORPUS_DIR.glob("brands_v*.json"))
        if not files:
            return None
        # Sort by semantic version extracted from filename
        def extract_ver(f):
            try:
                return version.parse(f.stem.replace("brands_v", ""))
            except:
                return version.parse("0")
        return sorted(files, key=extract_ver)[-1]

    def _load_latest(self):
        path = self._get_latest_corpus_file()
        if path is None:
            self.logger.warning("No corpus file found. Using empty corpus.")
            self._brands = []
            self._keywords = []
            self._version = "0.0.0"
            return
        with open(path) as f:
            data = json.load(f)
        self._brands = [b.lower() for b in data.get("brands", [])]
        self._keywords = [k.lower() for k in data.get("suspicious_keywords", [])]
        self._version = data.get("version", "unknown")
        self.logger.info(
            f"Loaded corpus v{self._version} from {path.name}: "
            f"{len(self._brands)} brands, {len(self._keywords)} keywords"
        )

    @property
    def brands(self) -> list[str]:
        return self._brands

    @property
    def keywords(self) -> list[str]:
        return self._keywords

    @property
    def version(self) -> str:
        return self._version

    def reload(self):
        self._load_latest()
        self.logger.info("Corpus reloaded.")

# Module-level singleton
corpus = CorpusManager()
