# SSH-based chat room (server part)

This is a fork of "Secure Shout Host Oriented Unified Talk" by Rivoreo originally published on [sourceforge](https://sourceforge.net/p/sshout).

The purpose of this program is to have a messenger program that works simply over the SSH protocol, without any additional dedicated third-party or self-hosted services.


## Prerequisites


First of all, you need to have a working SSH server installed; currently only OpenSSH server is supported.

The `sshout` server additionally depends on mhash and readline, which could be installed from distro packages, e.g. for Ubuntu:

```
sudo apt install libmhash-dev libreadline-dev
```


## Building

```
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr ..
make
make install
```


## Usage

1. Add a local user account, with name `sshout` and shell set to the path of installed sshoutd program:

```
sudo useradd --create-home -c "Secure Shout Host Oriented Unified Talk" -d /var/lib/sshout -s /usr/lib/sshout/sshoutd sshout
```

The command above should create the following suitable passwd(5) line:

```
sshout:*:115:115:Secure Shout Host Oriented Unified Talk:/var/lib/sshout:/usr/lib/sshout/sshoutd
```

2. The `sshout` user account must be allowed to log in with SSH public key authentication. The programs are currently assuming the `AuthorizedKeysFile` option in `sshd_config(5)` is left default, or contains `.ssh/authorized_keys`; otherwise the authentication won't work.

3. Enable `sshout` systemd service so that `sshoutd` can be started automatically:

```
systemctl enable --now sshout
```

The service must be started under the sshout user, instead of root. The service file provided in the `deploy` directory will be installed by the `make install` command above.

The CLI frontend requiring some addional programs for some features to work: `/pasteimage <user>` requires `xclip(1)` to be available in `PATH`; `/showhtml color|plain` requires `elinks(1)` version 0.12 or later to be available in `PATH`.
