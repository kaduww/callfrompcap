import csv
from pathlib import Path
from typing import Dict

from models import Call


def write_index_csv(calls: Dict[str, Call], output_dir: Path) -> Path:
    index_path = output_dir / 'index.csv'
    with open(index_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['call_id', 'request_user', 'directory'])
        for call in calls.values():
            writer.writerow([call.call_id, call.request_user, str(call.directory)])
    return index_path
