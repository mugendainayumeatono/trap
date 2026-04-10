import email.utils
from datetime import datetime

date_str = email.utils.formatdate(timeval=None, localtime=False, usegmt=True)
print(date_str)
