import sys
import zipfile
import re

def get_text(path):
    try:
        with zipfile.ZipFile(path) as docx:
            xml_content = docx.read('word/document.xml').decode('utf-8')
            # Extract all <w:t> text nodes
            texts = re.findall(r'<w:t(?: [^>]*?)?>(.*?)</w:t>', xml_content)
            return ' '.join(texts)
    except Exception as e:
        return str(e)

if __name__ == "__main__":
    print("---BEGIN---")
    print(get_text(sys.argv[1]))
