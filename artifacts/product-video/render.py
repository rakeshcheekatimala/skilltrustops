from __future__ import annotations

import subprocess
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path

import imageio_ffmpeg
from PIL import Image, ImageDraw, ImageEnhance, ImageFont


WIDTH, HEIGHT, FPS = 1440, 900, 24
DURATION = 106.0
ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "skilltrustops-product-tour.mp4"
FONT = "/System/Library/Fonts/SFNS.ttf"


@dataclass(frozen=True)
class Scene:
    image: str | None
    title: str
    caption: str
    start: float
    end: float
    vertical_pan: bool = False


SCENES = (
    Scene(None, "Trust agent skills before they run", "SkillTrustOps turns uncertain instructions into testable evidence.", 0, 9),
    Scene("01-overview.png", "One clear trust workflow", "Select. Inspect. Apply policy. Explain the decision.", 9, 21),
    Scene("02-scan.png", "Inspect locally", "Check structure, dangerous behavior, secrets, and sensitive data—without executing submitted code.", 21, 33),
    Scene("03-redteam-config.png", "Attack safely", "Choose the model and configured sandbox. Use synthetic records, canaries, and fake tools.", 33, 47),
    Scene("04-redteam-result-full.png", "Evidence, not optimism", "Six attacks resisted. Docker passed. Decision: INCONCLUSIVE—development isolation is not assurance.", 47, 65, True),
    Scene("05-findings.png", "Explain every issue", "What happened. Why it matters. How to fix it. OWASP and MITRE attached.", 65, 77),
    Scene("06-ci.png", "One policy everywhere", "Use the same trust gate on a laptop, in CI, and across agent frameworks.", 77, 87),
    Scene("07-docs.png", "Keep durable proof", "Plain-English reports, JSON evidence, event logs, and integrity hashes.", 87, 97),
    Scene(None, "Test safely. Explain clearly.\nShip what you can prove.", "SkillTrustOps · The trust gate for agent skills", 97, DURATION),
)

title_font = ImageFont.truetype(FONT, 53)
scene_title_font = ImageFont.truetype(FONT, 31)
caption_font = ImageFont.truetype(FONT, 21)
label_font = ImageFont.truetype(FONT, 18)
cached_images = {
    scene.image: Image.open(ROOT / scene.image).convert("RGB")
    for scene in SCENES
    if scene.image
}


def centered_multiline(draw: ImageDraw.ImageDraw, text: str, y: int, font: ImageFont.FreeTypeFont, fill: str) -> None:
    lines = []
    for paragraph in text.split("\n"):
        lines.extend(textwrap.wrap(paragraph, width=42) or [""])
    spacing = 12
    boxes = [draw.textbbox((0, 0), line, font=font) for line in lines]
    total_height = sum(box[3] - box[1] for box in boxes) + spacing * (len(lines) - 1)
    cursor = y - total_height // 2
    for line, box in zip(lines, boxes, strict=True):
        line_width = box[2] - box[0]
        draw.text(((WIDTH - line_width) // 2, cursor), line, font=font, fill=fill)
        cursor += box[3] - box[1] + spacing


def screenshot_frame(scene: Scene, progress: float) -> Image.Image:
    source = cached_images[scene.image]
    zoom = 1.0 + progress * 0.025
    scale = max(WIDTH / source.width, HEIGHT / source.height) * zoom
    resized = source.resize((round(source.width * scale), round(source.height * scale)), Image.Resampling.LANCZOS)
    left = max(0, (resized.width - WIDTH) // 2)
    if scene.vertical_pan:
        top = round(max(0, resized.height - HEIGHT) * min(progress * 1.2, 1.0))
    else:
        top = max(0, (resized.height - HEIGHT) // 2)
    frame = resized.crop((left, top, left + WIDTH, top + HEIGHT))
    frame = ImageEnhance.Brightness(frame).enhance(0.78)
    overlay = Image.new("RGBA", frame.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)
    draw.rounded_rectangle((54, 690, 1386, 852), radius=18, fill=(6, 10, 12, 238), outline=(50, 71, 64, 255), width=2)
    draw.rectangle((54, 690, 61, 852), fill=(66, 214, 164, 255))
    draw.text((88, 716), scene.title, font=scene_title_font, fill="white")
    wrapped = textwrap.fill(scene.caption, width=102)
    draw.multiline_text((88, 765), wrapped, font=caption_font, fill=(210, 220, 218, 255), spacing=6)
    return Image.alpha_composite(frame.convert("RGBA"), overlay).convert("RGB")


def title_frame(scene: Scene) -> Image.Image:
    frame = Image.new("RGB", (WIDTH, HEIGHT), "#091014")
    draw = ImageDraw.Draw(frame)
    for radius, alpha in ((300, 22), (230, 30), (160, 42)):
        color = (14, 125 + alpha, 97 + alpha // 2)
        draw.ellipse((WIDTH // 2 - radius, HEIGHT // 2 - radius, WIDTH // 2 + radius, HEIGHT // 2 + radius), fill=color)
    draw.rectangle((0, 0, WIDTH, HEIGHT), fill=(7, 13, 16, 185))
    label = "SKILLTRUSTOPS"
    label_box = draw.textbbox((0, 0), label, font=label_font)
    draw.text(((WIDTH - (label_box[2] - label_box[0])) // 2, 205), label, font=label_font, fill="#42d6a4")
    centered_multiline(draw, scene.title, 430, title_font, "white")
    centered_multiline(draw, scene.caption, 590, caption_font, "#b9c5c2")
    return frame


def render_frame(seconds: float) -> Image.Image:
    scene = next((item for item in SCENES if item.start <= seconds < item.end), SCENES[-1])
    progress = min(1.0, max(0.0, (seconds - scene.start) / (scene.end - scene.start)))
    frame = screenshot_frame(scene, progress) if scene.image else title_frame(scene)
    fade = min(1.0, (seconds - scene.start) / 0.4, (scene.end - seconds) / 0.4)
    if fade < 1:
        frame = ImageEnhance.Brightness(frame).enhance(max(0, fade))
    draw = ImageDraw.Draw(frame)
    draw.rounded_rectangle((54, 36, 1386, 43), radius=4, fill="#263138")
    draw.rounded_rectangle((54, 36, 54 + round(1332 * seconds / DURATION), 43), radius=4, fill="#42d6a4")
    return frame


def main() -> None:
    ffmpeg = imageio_ffmpeg.get_ffmpeg_exe()
    command = [
        ffmpeg,
        "-y",
        "-f", "rawvideo",
        "-pix_fmt", "rgb24",
        "-s", f"{WIDTH}x{HEIGHT}",
        "-r", str(FPS),
        "-i", "-",
        "-i", str(ROOT / "narration.aiff"),
        "-c:v", "libx264",
        "-preset", "fast",
        "-crf", "20",
        "-pix_fmt", "yuv420p",
        "-c:a", "aac",
        "-b:a", "160k",
        "-shortest",
        "-movflags", "+faststart",
        str(OUTPUT),
    ]
    process = subprocess.Popen(command, stdin=subprocess.PIPE)
    assert process.stdin is not None
    try:
        for frame_number in range(round(DURATION * FPS)):
            frame = render_frame(frame_number / FPS)
            process.stdin.write(frame.tobytes())
    finally:
        process.stdin.close()
    if process.wait() != 0:
        raise SystemExit("FFmpeg failed to render the product video")
    print(OUTPUT)


if __name__ == "__main__":
    main()
