# SSH-based chat room (server part)

This is a fork of "Secure Shout Host Oriented Unified Talk" by Rivoreo originally published on [sourceforge](https://sourceforge.net/p/sshout).

The purpose of this program is to have a messenger program that works simply over the SSH protocol, without any additional dedicated third-party or self-hosted services.


## Building

```
mkdir build
cd build
cmake ..
make
make install
```


## Usage

1. First of all, you need to have a working SSH server installed; currently only OpenSSH server is supported.

2. Add a local user account, with name `sshout` and shell set to the path of installed sshoutd program; there is an example of suitable passwd(5) line:

```
sshout:*:115:115:Secure Shout Host Oriented Unified Talk:/var/lib/sshout:/usr/lib/sshout/sshoutd
```

3. The `sshout` user account must be allowed to log in with SSH public key authentication. The programs are currently assuming the `AuthorizedKeysFile` option in sshd_config(5) is left default, or contains `.ssh/authorized_keys`; otherwise the authentication won't work.

4. Create a service so sshoutd can be started automatically; the service must be started under the sshout user, instead of root. For systemd based systems,
you can simply use the systemd service file provided in 'deploy' directory, then enable the service, by running:

```
cp deploy/systemd/sshout.service /etc/systemd/system/
systemctl enable --now sshout
```

The CLI frontend requiring some addional programs for some features to work: `/pasteimage <user>` requires `xclip(1)` to be available in `PATH`; `/showhtml color|plain` requires `elinks(1)` version 0.12 or later to be available in `PATH`.
