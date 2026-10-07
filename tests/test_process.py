import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest

from ida2pdb.errors import ExportError
from ida2pdb.toolchain import executable
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


class ExecutableTests(unittest.TestCase):
    def test_symbolic_links_keep_their_name(self):
        # clang++ is often a link to clang, and Clang's driver mode depends on
        # the name it is invoked by.
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "clang"
            target.write_bytes(b"")
            link = Path(directory) / "clang++"
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError):
                self.skipTest("cannot create symbolic links here")
            self.assertEqual(executable(link).name, "clang++")


if __name__ == "__main__":
    unittest.main()
