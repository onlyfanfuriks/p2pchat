"""Entry point for p2pchat.

Usage:
    python -m p2pchat
    # or
    p2pchat  (if installed via pip)
"""

from __future__ import annotations

import logging


def main() -> None:
    """Launch the p2pchat TUI application."""
    from p2pchat.core.account import ACCOUNT_DIR, ACCOUNTS_DIR, migrate_legacy_account

    ACCOUNT_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    ACCOUNTS_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    migrate_legacy_account()
    log_path = ACCOUNT_DIR / "p2pchat.log"

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s: %(message)s",
        handlers=[logging.FileHandler(log_path, mode="a", encoding="utf-8")],
    )
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("textual").setLevel(logging.WARNING)

    from p2pchat.app import ChatApp

    app = ChatApp()
    app.run()


if __name__ == "__main__":
    main()
