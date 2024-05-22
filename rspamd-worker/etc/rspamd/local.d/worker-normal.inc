# Heinlein Support SLAC 2024 - Workshop - Sichere Mailcluster mit Rspamd und Spamhaus DQS
# https://github.com/HeinleinSupport/rspamd-slac-2024
#

# the proxy worker will handle all the spam filtering
enabled = true;

## disabled because of high load on failure
#task_timeout = 16.0;

bind_socket = "127.0.0.1:11333";
bind_socket = "[::1]:11333";
bind_socket = "10.0.3.146:11333";
bind_socket = "*:11333";

keypair {
    algorithm = "curve25519";
    encoding = "base32";
    pubkey = "j4zcyxp84q47n8quhnmshbgaa5esjqu451hipxam49g6fhm5kpgy";
    type = "kex";
    privkey = "epo7fdbc9p1b9x16p4ss5f1b8xghtntzfd339cm7hpdybj6gxkoy";
    id = "gfo44wcadxk4ih6ubj4m3ec3nsb6pkx4hsc34brr9zha7gfppapb1sb8hy6j79uqyy47tcfuwg9otitucaq18fwnqakt9hfbj9s5ywn";
}
