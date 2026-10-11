from pathlib import Path
import csv

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT/"data"

def rows(name):
    with (DATA/name).open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

def test_training_normal_only():
    r = rows("security_windows_train_normal.csv")
    assert len(r)==12000
    assert {int(x["label"]) for x in r} == {0}

def test_eval_has_both_classes():
    r = rows("security_windows_eval_labeled.csv")
    assert len(r)==4000
    assert {int(x["label"]) for x in r} == {0,1}

def test_login_count_consistent():
    for name in ["security_windows_train_normal.csv","security_windows_eval_labeled.csv"]:
        for x in rows(name)[:500]:
            assert int(x["login_attempts"]) == int(x["failed_logins"]) + int(x["successful_logins"])
