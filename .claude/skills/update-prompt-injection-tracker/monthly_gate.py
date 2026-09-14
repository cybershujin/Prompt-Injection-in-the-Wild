#!/usr/bin/env python3
"""
monthly_gate.py — light self-gate for the monthly sweep.

Monthly cadence IS directly cron-expressible (unlike the sibling tracker's "every
other Thursday"), so a scheduled routine can just fire on the 1st. This gate is a
safety net for setups that fire more often than intended: it runs only on the
configured day of the month.

Exit code 0  => RUN the sweep today.
Exit code 10 => SKIP (not the configured run day).

Usage:
  python monthly_gate.py                    # today's date (configured TZ)
  python monthly_gate.py --date 2026-10-01  # test a specific date
  python monthly_gate.py --json
"""
import argparse, datetime as dt, json, sys, zoneinfo
from pathlib import Path

CFG = json.loads((Path(__file__).parent / "config.json").read_text(encoding="utf-8"))["schedule"]


def decide(today: dt.date):
    run_day = CFG.get("run_day_of_month", 1)
    run = today.day == run_day
    return {
        "today": today.isoformat(),
        "weekday": today.strftime("%A"),
        "run_day_of_month": run_day,
        "run": run,
        "reason": (f"monthly run day ({run_day})" if run
                   else f"skip: not day {run_day} of the month"),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--date", help="YYYY-MM-DD override (default: today in configured TZ)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if a.date:
        today = dt.date.fromisoformat(a.date)
    else:
        tz = zoneinfo.ZoneInfo(CFG["timezone"])
        today = dt.datetime.now(tz).date()
    d = decide(today)
    print(json.dumps(d, indent=2) if a.json else
          f"{d['today']} ({d['weekday']}): {'RUN' if d['run'] else 'SKIP'} — {d['reason']}")
    sys.exit(0 if d["run"] else 10)


if __name__ == "__main__":
    main()
