# Heinlein Support SLAC 2024 - Workshop - Sichere Mailcluster mit Rspamd und Spamhaus DQS
# https://github.com/HeinleinSupport/rspamd-slac-2024
#

# Timeout for messages processing (must be larger than any internal timeout used)
task_timeout = 11s;


max_message = 143699726;

# Emit soft reject when timeout takes place
soft_reject_on_timeout = true;
