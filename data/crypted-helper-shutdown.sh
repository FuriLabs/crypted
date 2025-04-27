#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2022 Eugenio Paolantonio (g7)
# Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>

# Exit if the helper isn't running
[ -e /run/crypted-helper.pid ] || exit 0

# Send SIGTERM to gracefully stop the encryption process
kill -s TERM $(cat /run/crypted-helper.pid)

# Wait for the PID file to be removed, which indicates process termination
while [ -e /run/crypted-helper.pid ]; do
    sleep 0.5
done

exit 0
