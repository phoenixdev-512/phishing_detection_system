# Extension Icons

The extension requires icon files in PNG format at three sizes:
- icon16.png (16x16 pixels)
- icon48.png (48x48 pixels)  
- icon128.png (128x128 pixels)

## Creating Icons

### Option 1: Use the provided SVG
An SVG template is provided in `icon.svg`. Convert it to PNG using:

```bash
# Using ImageMagick
convert -background none icon.svg -resize 16x16 icon16.png
convert -background none icon.svg -resize 48x48 icon48.png
convert -background none icon.svg -resize 128x128 icon128.png
```

```bash
# Using Inkscape
inkscape icon.svg --export-png=icon16.png -w 16 -h 16
inkscape icon.svg --export-png=icon48.png -w 48 -h 48
inkscape icon.svg --export-png=icon128.png -w 128 -h 128
```

```bash
# Using rsvg-convert
rsvg-convert -w 16 -h 16 icon.svg > icon16.png
rsvg-convert -w 48 -h 48 icon.svg > icon48.png
rsvg-convert -w 128 -h 128 icon.svg > icon128.png
```

### Option 2: Use an online converter
1. Go to https://cloudconvert.com/svg-to-png
2. Upload `icon.svg`
3. Set output size (16x16, 48x48, 128x128)
4. Convert and download

### Option 3: Create custom icons
Create PNG files with:
- A shield icon (representing protection)
- Purple/indigo color scheme (#6366f1 to #8b5cf6)
- Transparent background
- Clean, modern design

## Fallback
If icons are missing, the extension will still work but won't show an icon in the browser toolbar. Chrome will display a default placeholder icon.

## Design Guidelines
- Use a shield or lock symbol to represent security
- Keep design simple and recognizable at small sizes
- Use the project's color scheme (purple/indigo gradient)
- Ensure good contrast for visibility
