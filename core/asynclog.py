"""v2.8.3: non-blocking log sink.

The GUI's log callback ran ON THE REQUEST THREAD and wrote synchronously
to stderr and gui.log. If stderr is a pipe/terminal nobody drains (a
paused console, a full pipe, a stalled disk), that write blocks forever:
/write lands its file then hangs in op_log, /exec and /proc/start hang
the same way, while /health and /stat (which never log) stay instant --
and one stuck thread also holds Python's stderr lock, so every later
logging call blocks behind it ("persists until restart").

AsyncLogSink moves each destination onto its own daemon thread behind a
bounded queue. Request threads only ever do put_nowait(); when a
destination is stuck its queue fills and the NEWEST lines for that
destination are dropped, so the host keeps serving."""
import queue
import threading
from typing import Optional

LOG_QUEUE_CAP = 5000


class AsyncLogSink:
    def __init__(self, file_path: Optional[str] = None, stream=None,
                 cap: int = LOG_QUEUE_CAP):
        self.dropped = 0
        self._targets = []
        if file_path:
            self._targets.append(self._start(self._to_file(file_path), cap))
        if stream is not None:
            self._targets.append(self._start(self._to_stream(stream), cap))

    @staticmethod
    def _to_file(path):
        def w(line):
            with open(path, "a", encoding="utf-8") as f:
                f.write(line)
        return w

    @staticmethod
    def _to_stream(stream):
        def w(line):
            stream.write(line)
            stream.flush()
        return w

    def _start(self, writer, cap):
        q: queue.Queue = queue.Queue(maxsize=cap)

        def loop():
            while True:
                line = q.get()
                try:
                    writer(line)
                except Exception:
                    pass            # best-effort, like the old code
        threading.Thread(target=loop, daemon=True,
                         name="llmac-log-writer").start()
        return q

    def write(self, line: str) -> None:
        """Never blocks."""
        for q in self._targets:
            try:
                q.put_nowait(line)
            except queue.Full:
                self.dropped += 1
