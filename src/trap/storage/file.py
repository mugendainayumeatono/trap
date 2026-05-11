import os
import json
import logging
import logging.handlers
import time
from datetime import datetime
from .base import Storage

class CombinedRotatingHandler(logging.handlers.RotatingFileHandler):
    def __init__(self, filename, maxBytes=0, maxDays=0):
        super().__init__(filename, maxBytes=maxBytes, backupCount=0)
        self.maxDays = maxDays
        self.maxInterval = maxDays * 24 * 3600
        self._update_rollover_at()

    def _update_rollover_at(self):
        if self.maxDays <= 0:
            self.rolloverAt = None
            return

        # 尝试从文件内容中读取第一行的时间戳，这比 mtime 更可靠（跨重启且不受文件系统 touch 影响）
        creation_time = None
        if os.path.exists(self.baseFilename):
            try:
                with open(self.baseFilename, 'r') as f:
                    first_line = f.readline()
                    if first_line:
                        data = json.loads(first_line)
                        creation_time = datetime.fromisoformat(data['timestamp']).timestamp()
            except Exception:
                pass
            
            # 如果读取失败，尝试使用 ctime (在 Linux 上是元数据改变时间，在 Windows 上是创建时间)
            # 虽然 ctime 在 Linux 上也会随修改而更新，但它依然比 mtime 相对更早一点（在某些边缘情况下）
            # 最理想的情况是上面的 "读取首行时间戳" 逻辑。
            if creation_time is None:
                try:
                    # 某些系统支持 birthtime
                    creation_time = os.stat(self.baseFilename).st_birthtime
                except AttributeError:
                    # 回退到 ctime (Linux 下通常等同于最后一次修改元数据的时间)
                    creation_time = os.path.getctime(self.baseFilename)
        else:
            creation_time = time.time()
            
        self.rolloverAt = creation_time + self.maxInterval

    def shouldRollover(self, record):
        if self.stream is None:
            self.stream = self._open()
            
        if self.maxBytes > 0:
            msg = "%s\n" % self.format(record)
            self.stream.seek(0, 2)
            if self.stream.tell() + len(msg) >= self.maxBytes:
                return 1
                
        if self.maxDays > 0 and self.rolloverAt and time.time() >= self.rolloverAt:
            return 1
            
        return 0

    def doRollover(self):
        if self.stream:
            self.stream.close()
            self.stream = None
        
        if os.path.exists(self.baseFilename):
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S_%f")
            dfn = f"{self.baseFilename}.{timestamp}"
            os.rename(self.baseFilename, dfn)
        
        if not self.delay:
            self.stream = self._open()
        
        # 轮转后，新文件的起始时间是现在
        self.rolloverAt = time.time() + self.maxInterval

class FileStorage(Storage):
    def __init__(self, file_path: str, max_size_mb: float, max_days: float = 0):
        self.file_path = file_path
        self.max_bytes = int(max_size_mb * 1024 * 1024)
        self.max_days = max_days
        
        self.logger_name = f"trap.file_storage.{id(self)}"
        self.logger = logging.getLogger(self.logger_name)
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False

    def setup(self):
        directory = os.path.dirname(self.file_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
            
        for h in self.logger.handlers[:]:
            h.close()
            self.logger.removeHandler(h)
            
        handler = CombinedRotatingHandler(
            self.file_path, 
            maxBytes=self.max_bytes, 
            maxDays=self.max_days
        )
        handler.setFormatter(logging.Formatter('%(message)s'))
        self.logger.addHandler(handler)

    def record(self, timestamp: datetime, sender_ip: str, content: bytes, decoded_content: str, protocol: str):
        entry = {
            "timestamp": timestamp.isoformat(),
            "sender_ip": sender_ip,
            "content_hex": content.hex(),
            "decoded_content": decoded_content,
            "protocol": protocol
        }
        self.logger.info(json.dumps(entry))
        for handler in self.logger.handlers:
            handler.flush()
