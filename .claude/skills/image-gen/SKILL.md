---
name: image-gen
version: 1.0.0
description: Generate images using Google Imagen or OpenAI models. Use when creating diagrams, flowcharts, or visualizations.
runtime: python
deps-group: image-gen
entrypoints:
  - scripts/image-gen.py
---

# Image Generation

## Setup

Install dependencies from repo root:

```bash
pdm install -G image-gen
```

Set up your API key for the provider you want to use:

```bash
# For Google Imagen (default provider)
export GOOGLE_API_KEY="your-google-api-key"
# Or: export GEMINI_API_KEY="your-gemini-api-key"

# For OpenAI
export OPENAI_API_KEY="your-openai-api-key"
```

## Quick Start

Use the local utility to generate images. It handles API setup and output,
so your job is to provide a clear prompt and the right options.

```bash
# Generate with Google Imagen (default)
pdm run python .claude/skills/image-gen/scripts/image-gen.py \
  --prompt "A minimal flowchart with 4 steps..." \
  --output flow.png

# Generate with OpenAI
pdm run python .claude/skills/image-gen/scripts/image-gen.py \
  --provider openai \
  --prompt "A futuristic city at sunset" \
  --size 1024x1024 \
  --output city.png
```

## Providers

### Google Imagen (default)

Google's Imagen 4 model via the Gemini API. High-quality, photorealistic images.

| Model                | Notes                           |
| -------------------- | ------------------------------- |
| `imagen-4` (default) | Latest Imagen 4 standard model  |
| `imagen-4-ultra`     | Highest quality, 2K resolution  |
| `imagen-4-fast`      | Faster generation, good quality |
| `imagen-3`           | Previous generation model       |

**Options:**

- `--aspect-ratio`: 1:1 (default), 3:4, 4:3, 9:16, 16:9

```bash
pdm run python .claude/skills/image-gen/scripts/image-gen.py \
  --provider google \
  --model imagen-4-fast \
  --aspect-ratio 16:9 \
  --prompt "Mountain landscape at dawn" \
  --output landscape.png
```

### OpenAI

OpenAI's GPT Image and DALL-E models.

| Model                     | Notes                           |
| ------------------------- | ------------------------------- |
| `gpt-image-1.5` (default) | Latest GPT Image model          |
| `gpt-image-1`             | GPT Image model                 |
| `gpt-image-1-mini`        | Smaller/faster GPT Image model  |
| `dall-e-3`                | 1024x1024, 1792x1024, 1024x1792 |
| `dall-e-2`                | 256x256, 512x512, 1024x1024     |

**Options:**

- `--size`: 1024x1024 (default), 1792x1024, 1024x1792

```bash
pdm run python .claude/skills/image-gen/scripts/image-gen.py \
  --provider openai \
  --model dall-e-3 \
  --size 1792x1024 \
  --prompt "Abstract digital art" \
  --output art.png
```

## What makes a good prompt

Focus on structure, style, and constraints. Assume the utility will handle
the rest.

### Prompt template

```
Subject: <what it is>
Layout: <diagram type + layout details>
Labels: <exact labels, order, and casing>
Style: <clean/minimal, line weights, colors, typography>
Background: <solid color or transparent>
Constraints: <no extra text, no icons, consistent spacing>
```

### Example prompt (diagram)

```
Subject: Network access flow
Layout: Left-to-right, 4 nodes, simple arrows
Labels: Client, API Gateway, Core Service, Database
Style: Minimal, thin lines, rounded rectangles, monochrome
Background: White
Constraints: No icons, no gradients, no shadows
```

## Tables to image (SVG input)

For tables, provide SVG directly so layout is exact.

```bash
pdm run python .claude/skills/image-gen/scripts/image-gen.py \
  --svg-file table.svg \
  --size 1536x1024 \
  --output table.png
```

### SVG guidance

- Fixed widths for columns and padding
- Consistent font sizes and weights
- Avoid long text overflow; truncate with ellipsis
- Use high contrast for text on background

### Prompt pattern for SVG

```
Instruction: Render the following SVG exactly, with crisp text and no style changes.
SVG:
<svg ...>...</svg>
```

## Quality checklist

- Clear hierarchy: title, header row, body rows
- Consistent spacing and alignment
- Text is readable at target size
- No extra decorations or visual noise
