#!/usr/bin/env python3
"""
Image generation utility supporting multiple providers:
- Google Imagen (default): Uses Google's Imagen 4 model via Gemini API
- OpenAI: Uses GPT Image or DALL-E models

Environment variables:
- GOOGLE_API_KEY or GEMINI_API_KEY: Required for Google provider
- OPENAI_API_KEY: Required for OpenAI provider
"""
import argparse
import base64
import os
from pathlib import Path
from typing import Any


def build_prompt(prompt: str | None, svg_file: Path | None) -> str:
    """Build the image generation prompt from text or SVG file."""
    if svg_file:
        svg_text = svg_file.read_text(encoding="utf-8")
        return (
            "Instruction: Render the following SVG exactly, with crisp text and "
            "no style changes.\n"
            "SVG:\n"
            f"{svg_text}"
        )
    if prompt:
        return prompt
    raise ValueError("Provide --prompt or --svg-file.")


# =============================================================================
# Google Imagen Provider
# =============================================================================

GOOGLE_MODELS = {
    "imagen-4": "imagen-4.0-generate-001",
    "imagen-4-ultra": "imagen-4.0-ultra-generate-001",
    "imagen-4-fast": "imagen-4.0-fast-generate-001",
    "imagen-3": "imagen-3.0-generate-002",
}

GOOGLE_ASPECT_RATIOS = ["1:1", "3:4", "4:3", "9:16", "16:9"]


def get_google_api_key() -> str:
    """Get Google API key from environment variables."""
    api_key = os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise SystemExit(
            "Missing Google API key.\n"
            "Set GOOGLE_API_KEY or GEMINI_API_KEY environment variable.\n"
            "Get your API key at: https://aistudio.google.com/apikey"
        )
    return api_key


def generate_with_google(
    prompt: str,
    model: str,
    output_path: Path,
    aspect_ratio: str = "1:1",
) -> None:
    """Generate image using Google Imagen API."""
    try:
        from google import genai
        from google.genai import types
    except ImportError:
        raise SystemExit(
            "Google GenAI library not installed.\n"
            "Install with: pip install google-genai"
        )

    api_key = get_google_api_key()

    # Resolve model alias to full model name
    model_id = GOOGLE_MODELS.get(model, model)

    # Validate aspect ratio
    if aspect_ratio not in GOOGLE_ASPECT_RATIOS:
        raise SystemExit(
            f"Invalid aspect ratio '{aspect_ratio}' for Google provider.\n"
            f"Supported: {', '.join(GOOGLE_ASPECT_RATIOS)}"
        )

    try:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_images(
            model=model_id,
            prompt=prompt,
            config=types.GenerateImagesConfig(
                number_of_images=1,
                aspect_ratio=aspect_ratio,
            ),
        )

        if not response.generated_images:
            raise SystemExit("No images generated. The prompt may have been blocked.")

        # Save the first generated image
        image = response.generated_images[0]
        # The image object has image_bytes attribute
        if hasattr(image.image, "image_bytes"):
            output_path.write_bytes(image.image.image_bytes)
        elif hasattr(image.image, "_pil_image"):
            # Fallback: save PIL image
            image.image._pil_image.save(output_path, format="PNG")
        else:
            # Try to get raw bytes via save method
            from io import BytesIO

            buffer = BytesIO()
            image.image.save(buffer, format="PNG")
            output_path.write_bytes(buffer.getvalue())

        print(f"Image saved to: {output_path}")

    except Exception as e:
        error_msg = str(e)
        if "API_KEY_INVALID" in error_msg or "401" in error_msg:
            raise SystemExit(
                "Google API key is invalid or expired.\n"
                "Get a new key at: https://aistudio.google.com/apikey"
            )
        if "PERMISSION_DENIED" in error_msg or "403" in error_msg:
            raise SystemExit(
                "Permission denied. Your API key may not have access to Imagen.\n"
                "Check your API key permissions at: https://aistudio.google.com/"
            )
        raise SystemExit(f"Google Imagen API error: {error_msg}")


# =============================================================================
# OpenAI Provider
# =============================================================================

OPENAI_MODELS = [
    "gpt-image-1.5",
    "gpt-image-1",
    "gpt-image-1-mini",
    "dall-e-3",
    "dall-e-2",
]


def is_gpt_image_model(model: str) -> bool:
    """Check if the model is a GPT Image model."""
    return model.startswith("gpt-image")


def get_openai_api_key() -> str:
    """Get OpenAI API key from environment variable."""
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise SystemExit(
            "Missing OpenAI API key.\n"
            "Set OPENAI_API_KEY environment variable.\n"
            "Get your API key at: https://platform.openai.com/api-keys"
        )
    return api_key


def decode_openai_image(data: dict[str, Any], model: str) -> bytes:
    """Decode image bytes from OpenAI API response."""
    entry = data["data"][0]
    return base64.b64decode(entry["b64_json"])


def generate_with_openai(
    prompt: str,
    model: str,
    output_path: Path,
    size: str = "1024x1024",
) -> None:
    """Generate image using OpenAI Images API."""
    import requests

    api_key = get_openai_api_key()

    payload: dict[str, Any] = {
        "model": model,
        "prompt": prompt,
        "size": size,
    }
    if is_gpt_image_model(model):
        payload["output_format"] = "png"
    else:
        payload["response_format"] = "b64_json"

    try:
        resp = requests.post(
            "https://api.openai.com/v1/images/generations",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=120,
        )
    except requests.exceptions.RequestException as e:
        raise SystemExit(f"Network error: {e}")

    if not resp.ok:
        error_detail = resp.text
        try:
            error_detail = resp.json().get("error", {}).get("message", resp.text)
        except Exception:
            pass

        if resp.status_code == 401:
            raise SystemExit(
                "OpenAI API key is invalid or expired.\n"
                "Get a new key at: https://platform.openai.com/api-keys"
            )
        if resp.status_code == 403:
            raise SystemExit(
                "Permission denied. Your API key may not have access to this model.\n"
                "GPT Image models require API Organization Verification."
            )
        raise SystemExit(f"OpenAI API error ({resp.status_code}): {error_detail}")

    image_bytes = decode_openai_image(resp.json(), model)
    output_path.write_bytes(image_bytes)
    print(f"Image saved to: {output_path}")


# =============================================================================
# Main CLI
# =============================================================================


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate images using Google Imagen or OpenAI.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate with Google Imagen (default)
  %(prog)s --prompt "A robot holding a red skateboard"

  # Generate with OpenAI
  %(prog)s --provider openai --prompt "A futuristic city"

  # Use specific Google model
  %(prog)s --model imagen-4-fast --prompt "Mountain landscape"

  # Use specific OpenAI model
  %(prog)s --provider openai --model dall-e-3 --prompt "Abstract art"

Environment variables:
  GOOGLE_API_KEY or GEMINI_API_KEY  - Required for Google provider
  OPENAI_API_KEY                    - Required for OpenAI provider
""",
    )
    parser.add_argument("--prompt", help="Text prompt for image generation.")
    parser.add_argument(
        "--svg-file",
        type=Path,
        help="Path to SVG file to render via prompt.",
    )
    parser.add_argument(
        "--provider",
        choices=["google", "openai"],
        default="google",
        help="Image generation provider. Default: google",
    )
    parser.add_argument(
        "--model",
        help="Model to use. "
        f"Google: {', '.join(GOOGLE_MODELS.keys())} (default: imagen-4). "
        f"OpenAI: {', '.join(OPENAI_MODELS)} (default: gpt-image-1.5).",
    )
    parser.add_argument(
        "--size",
        default="1024x1024",
        help="Image size (OpenAI only). Options: 1024x1024, 1792x1024, 1024x1792. "
        "Default: 1024x1024",
    )
    parser.add_argument(
        "--aspect-ratio",
        default="1:1",
        help="Aspect ratio (Google only). Options: 1:1, 3:4, 4:3, 9:16, 16:9. "
        "Default: 1:1",
    )
    parser.add_argument(
        "--output",
        default="image.png",
        help="Output PNG file path. Default: image.png",
    )
    args = parser.parse_args()

    # Build prompt from text or SVG file
    prompt = build_prompt(args.prompt, args.svg_file)
    output_path = Path(args.output)

    if args.provider == "google":
        model = args.model or "imagen-4"
        generate_with_google(
            prompt=prompt,
            model=model,
            output_path=output_path,
            aspect_ratio=args.aspect_ratio,
        )
    else:  # openai
        model = args.model or "gpt-image-1.5"
        generate_with_openai(
            prompt=prompt,
            model=model,
            output_path=output_path,
            size=args.size,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
