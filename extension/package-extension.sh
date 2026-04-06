#!/bin/bash
set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'
BOLD='\033[1m'

mkdir -p dist/chrome dist/firefox dist/edge

echo -e "${BOLD}${BLUE}Packaging Chrome Extension...${NC}"
cp -r icons popup.html popup.js content.js content.css background.js \
      manifest.json dist/chrome/
cd dist/chrome && zip -r ../../tgis-chrome.zip . && cd ../..
echo -e "${GREEN}[✓] Chrome extension: tgis-chrome.zip${NC}"

echo -e "${BOLD}${BLUE}Packaging Firefox Extension...${NC}"
cp -r icons popup.html popup.js content.js content.css \
      background.firefox.js dist/firefox/
cp manifest.firefox.json dist/firefox/manifest.json
cd dist/firefox && zip -r ../../tgis-firefox.zip . && cd ../..
echo -e "${GREEN}[✓] Firefox extension: tgis-firefox.zip${NC}"

echo -e "${BOLD}${BLUE}Packaging Edge Extension (same as Chrome)...${NC}"
cp -r dist/chrome/. dist/edge/
cd dist/edge && zip -r ../../tgis-edge.zip . && cd ../..
echo -e "${GREEN}[✓] Edge extension: tgis-edge.zip${NC}"

echo -e "\n${BOLD}Install instructions:${NC}"
echo -e "  Chrome/Edge: chrome://extensions → Developer Mode → Load unpacked → dist/chrome"
echo -e "  Firefox:     about:debugging → Load Temporary Add-on → dist/firefox/manifest.json"
echo -e "  Production:  Submit .zip files to respective extension stores"
