# 2fa-vault

2fa-vault is a two-factor authentication agent with Hashicorp vault for storage. It allows
you to share a OTP code to shared accounts with others in your organization. You should probably check out the [TOTP backend](https://www.vaultproject.io/docs/secrets/totp/index.html) for fault that does this and more anyways.

This was a project that interested me before I knew that Vault already handled this. You can use it or the TOTP backend for Vault.

2fa-vault is based on 2fa by rsc (https://github.com/rsc/2fa)

Usage:

    go get -u github.com/ahamilton55/2fa-vault

    2fa-vault -add [-7] [-8] [-hotp] name
    2fa-vault -list
    2fa-vault-vault name

`2fa-vault -add name` adds a new key to the 2fa-vault keychain with the given name. It
prints a prompt to standard error and reads a two-factor key from standard
input. Two-factor keys are short case-insensitive strings of letters A-Z and
digits 2-7.

By default the new key generates time-based (TOTP) authentication codes; the
`-hotp` flag makes the new key generate counter-based (HOTP) codes instead.

By default the new key generates 6-digit codes; the `-7` and `-8` flags select
7- and 8-digit codes instead.

`2fa-vault -list` lists the names of all the keys in the keychain.

`2fa-vault name` prints a two-factor authentication code from the key with the
given name.

With no arguments, `2fa-vault` prints two-factor authentication codes from all
known time-based keys.

The default time-based authentication codes are derived from a hash of the
key and the current time, so it is important that the system clock have at
least one-minute accuracy.

The keychain is stored unencrypted in the text file `$HOME/.2fa-vault`.

## Example

During GitHub 2fa-vault setup, at the “Scan this barcode with your app” step,
click the “enter this text code instead” link. A window pops up showing
“your two-factor secret,” a short string of letters and digits.

Add it to 2fa-vault under the name github, typing the secret at the prompt:

    $ 2fa-vault -add github
    2fa-vault key for github: nzxxiidbebvwk6jb
    $

Then whenever GitHub prompts for a 2fa-vault code, run 2fa-vault to obtain one:

    $ 2fa-vault github
    268346
    $

Or to type less:

    $ 2fa-vault
    268346	github
    $ 
