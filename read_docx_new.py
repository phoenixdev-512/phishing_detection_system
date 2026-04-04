import sys
import docx

def getText(filename):
    doc = docx.Document(filename)
    fullText = []
    for para in doc.paragraphs:
        fullText.append(para.text)
    return '\n'.join(fullText)

if __name__ == '__main__':
    text = getText(sys.argv[1])
    with open('output_utf8.txt', 'w', encoding='utf-8') as f:
        f.write(text)
