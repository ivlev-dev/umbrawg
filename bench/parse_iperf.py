import json
import sys


def main() -> None:
    total_bps = 0.0
    loss_sum = 0.0
    files = 0
    ok = 1
    for path in sys.argv[1:]:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception:
            ok = 0
            continue
        end = data.get("end", {})
        summary = end.get("sum_received") or end.get("sum") or {}
        bps = summary.get("bits_per_second")
        if bps is None:
            summary = end.get("sum", {})
            bps = summary.get("bits_per_second", 0)
        total_bps += float(bps or 0)
        lost = summary.get("lost_percent")
        if lost is None:
            lost = end.get("sum", {}).get("lost_percent", 0)
        loss_sum += float(lost or 0)
        files += 1
    avg_loss = loss_sum / files if files else 0.0
    print(f"{total_bps:.3f},{avg_loss:.3f},{ok}")


if __name__ == "__main__":
    main()
