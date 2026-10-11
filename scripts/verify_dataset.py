import sys
from pathlib import Path

# Ensure project root is in sys.path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.data_validation.report import run_full_validation
from src.data_validation.validators import CheckStatus


def main():
    data_dir = ROOT / "data"
    report = run_full_validation(data_dir)
    print(report.format_text())

    if report.overall_status != CheckStatus.PASS:
        print("\nDataset validation FAILED.")
        sys.exit(1)

    print("\nDataset validation passed.")


if __name__ == "__main__":
    main()
