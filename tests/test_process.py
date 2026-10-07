import sys
import threading
import time
import unittest

from ida2pdb.errors import ExportError
from ida2pdb.util import run


class ProcessTests(unittest.TestCase):
    def test_cancellation_stops_running_child(self):
        event = threading.Event()
        timer = threading.Timer(0.3, event.set)
        timer.start()
        start = time.monotonic()
        try:
            with self.assertRaisesRegex(ExportError, "cancelled"):
                run([sys.executable, "-c", "import time; time.sleep(30)"], cancel_event=event)
        finally:
            timer.cancel()
        self.assertLess(time.monotonic() - start, 5)

    def test_timeout(self):
        with self.assertRaisesRegex(ExportError, "timeout"):
            run([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.1)


if __name__ == "__main__":
    unittest.main()
