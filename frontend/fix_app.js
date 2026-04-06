const fs = require('fs');
const content = fs.readFileSync('src/App.jsx', 'utf-8');
const top = content.split('        <ScanForm onScan={scan} loading={loading} />')[0];
const newContent = top + '        <ScanForm onScan={scan} loading={loading} />\n\n        <div className="mt-8">\n          <TGISResultCard result={result} loading={loading} error={error} />\n        </div>\n      </main>\n      <style dangerouslySetInnerHTML={{__html: `\n        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }\n        body { margin: 0; background-color: #030712; }\n      `}} />\n    </div>\n  );\n}';
fs.writeFileSync('src/App.jsx', newContent);
