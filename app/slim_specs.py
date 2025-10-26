# app/slim_specs.py
import json
import gzip
from pathlib import Path
import sys


def slim_fmc_spec(input_path: Path, output_path: Path):
    """Slim an FMC OpenAPI spec by keeping only essential sections."""
    with open(input_path, "r") as f:
        spec = json.load(f)
    slim_spec = {
        "openapi": spec["openapi"],
        "info": spec.get("info", {}),
        "servers": spec.get("servers", []),
        "paths": spec["paths"],
        "components": {
            "securitySchemes": spec.get("components", {}).get("securitySchemes", {})
        },
    }
    with open(output_path, "w") as f:
        json.dump(slim_spec, f, indent=2)


def compress_spec(input_path: Path, output_path: Path):
    """Compress a JSON file to .gz."""
    with open(input_path, "rb") as f_in:
        with gzip.open(output_path, "wb") as f_out:
            f_out.writelines(f_in)


def process_specs(input_dir: str = "specs", output_dir: str = "specs"):
    """Slim and compress all .json files in input_dir, save to output_dir."""
    input_path = Path(input_dir)
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    temp_dir = output_path / "temp"
    temp_dir.mkdir(exist_ok=True)

    for json_file in input_path.glob("*.json"):
        if json_file.stem.endswith("_slim"):
            continue
        slim_path = temp_dir / f"{json_file.stem}_slim.json"
        gzip_path = output_path / f"{json_file.stem}_slim.json.gz"
        slim_fmc_spec(json_file, slim_path)
        compress_spec(slim_path, gzip_path)
        print(f"Processed {json_file} -> {gzip_path}")
        json_file.unlink()  # Remove original .json
        slim_path.unlink()  # Remove temp slimmed .json

    if temp_dir.exists():
        temp_dir.rmdir()


if __name__ == "__main__":
    input_dir = sys.argv[1] if len(sys.argv) > 1 else "specs"
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "specs"
    process_specs(input_dir, output_dir)
