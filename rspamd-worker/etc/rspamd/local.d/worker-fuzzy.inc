# Heinlein Support SLAC 2024 - Workshop - Sichere Mailcluster mit Rspamd und Spamhaus DQS
# https://github.com/HeinleinSupport/rspamd-slac-2024
#

allow_update = ["127.0.0.1", "::1"];

# Socket to listen on (UDP and TCP from rspamd 1.3)
bind_socket = "127.0.0.1:11335";
bind_socket = "[::1]:11335";
bind_socket = "10.0.3.146:11335";
bind_socket = "*:11335";

# Number of processes to serve this storage (useful for read scaling)
count = 2;

# Backend ("sqlite" or "redis" - default "sqlite")
backend = "redis";

# Hashes storage time (3 months)
expire = 90d;

# Synchronize updates to the storage each minute
sync = 1min;

