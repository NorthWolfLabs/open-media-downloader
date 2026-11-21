# Install the standalone engine on Ubuntu 24.04

The Linux x64 runtime archive is an advanced, headless installation. The desktop
DEB already provides its own runtime and policy. To use MCP with the desktop,
extract the standalone archive and point its bin/omd-mcp at the desktop's private
instance file; you do not need to start another engine or install this policy.

## Install the headless runtime

Use Ubuntu 24.04 amd64 with user namespaces, Landlock, seccomp and AppArmor 4.
Verify the archive and omd-v2-engine.apparmor against the release checksums.
Install the managed browser's system dependencies and fallback fonts:

```sh
sudo apt install apparmor libc6 libgcc-s1 libstdc++6 libnss3 libnspr4 \
  libasound2t64 libatk-bridge2.0-0t64 libatk1.0-0t64 libatspi2.0-0t64 \
  libcairo2 libcups2t64 libdbus-1-3 libdrm2 libexpat1 libgbm1 \
  libglib2.0-0t64 libpango-1.0-0 libx11-6 libxcb1 libxcomposite1 \
  libxdamage1 libxext6 libxfixes3 libxkbcommon0 libxrandr2 fonts-liberation
```

Use a new installation directory. Keep the runtime root-owned and run the engine
as your ordinary user. Profiles and downloads belong outside /opt/omd-engine.

```sh
(
set -eu
test ! -e /opt/omd-engine
sudo install -d -m 0755 /opt/omd-engine
sudo tar --extract --gzip --file OMD-Engine-0.2.4-linux-x64.tar.gz \
  --directory /opt/omd-engine --no-same-owner
sudo chown -R root:root /opt/omd-engine
sudo install -m 0644 omd-v2-engine.apparmor /etc/apparmor.d/omd-v2-engine
sudo apparmor_parser --replace /etc/apparmor.d/omd-v2-engine
/opt/omd-engine/start-engine.sh --profile "$HOME/.local/share/omd-engine"
)
```

With background operation off (the default), the engine started this way stops
about a minute after its last client leaves. CLI commands hold a client only
while they run, but they ask the engine to finish their downloads: a queued or
running download keeps it up until the queue is empty, so `start-engine.sh` plus
`omd` is enough for a one-off download.

The initial test must succeed before running the following commands; stop if the
installation directory already exists. The policy authorizes namespace creation
only for that installed guardian. The guardian applies its own filesystem,
network, syscall and resource restrictions before launching managed helpers. OMD
reports confinement failures rather than falling back to an unrestricted helper.
A different installation path needs a separately reviewed root-owned policy.

Native sign-in windows (`omd sign-in`, or `window: native`) need a desktop
session and the WebKitGTK runtime (`sudo apt install libwebkit2gtk-4.1-0`). On a
headless server, sign in on a computer with a desktop and import the account
instead.

In another terminal, attach the CLI or MCP server to the same profile:

```sh
/opt/omd-engine/bin/omd --instance "$HOME/.local/share/omd-engine/instance.json" status
/opt/omd-engine/bin/omd-mcp --instance "$HOME/.local/share/omd-engine/instance.json" --print-config
```

## Manual replacement

For every active profile, stop the engine with its authenticated update command:

```sh
/opt/omd-engine/bin/omd-engine --profile "$HOME/.local/share/omd-engine" --prepare-update
```

Wait for successful shutdown before replacing any files. Extract the next complete
release into a new root-owned staging directory, retain the previous runtime as a
backup, and move the staged runtime into /opt/omd-engine. Keep the stable guardian
path and reload the same scoped policy. Start the new engine as the same ordinary
user with the existing profile. Do not merge runtime directories or mix versions.
The background preference is retained and restored on the next interactive launch.
Keep a full profile backup before upgrading; newer database schemas
cannot be opened by an older engine. Source/rebuild materials retain their own
original component licenses and accompany the binary release.
