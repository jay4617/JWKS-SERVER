import os
import time
from db import init_db, get_key
from keys import ensure_keys_in_db


def test_db_keys_exist():
    init_db()
    ensure_keys_in_db()

    assert os.path.exists("totally_not_my_privateKeys.db")

    now_ts = int(time.time())

    expired_row = get_key(expired=True)
    assert expired_row is not None
    assert expired_row["exp"] <= now_ts

    valid_row = get_key(expired=False)
    assert valid_row is not None
    assert valid_row["exp"] >= now_ts
