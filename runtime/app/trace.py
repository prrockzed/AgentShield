from collections import defaultdict

_store: dict[str, list[dict]] = defaultdict(list)


def append_step(run_id: str, step: dict) -> None:
    _store[run_id].append(step)


def get_steps(run_id: str) -> list[dict]:
    return list(_store.get(run_id, []))


def clear(run_id: str) -> None:
    _store.pop(run_id, None)
