# DNS watch (phone-only)

A daily check of the firm's two domains that nothing on the firm's PC can switch off.

**Why it exists.** A standing key on the firm's PC can change the domains' DNS. The
firm repo's own daily checks are watched from that same PC, so a session or intruder
with the PC's credentials could change a record and silence the alarm. This copy runs
under a GitHub account that is signed in only on the operator's phone, with its own
read-only Cloudflare key that never touches the PC. When it finds a change, or cannot
read, the run fails and the GitHub app on the phone shows it.

**What it checks.** Every write Cloudflare logged to either zone since its last
successful read (a record added and removed between two checks still shows), any new or
changed Cloudflare API key or account member, and that both domains are still delegated to the firm's
Cloudflare nameservers at the .com and .ca registries, with no DS record.

**Who watches the watcher.** A run that fails buzzes the phone. A run that never starts
cannot. GitHub pauses schedules in a public repository after 60 days without activity;
each run switches its own schedule back on, which is meant to restart that clock (not
yet proven). The backstop is the firm repo's daily job: it reads this repository's
public run history and goes red if no run has started for two days. If that happens,
open this repository's Actions tab on the phone and tap **Enable workflow**.

**Never** sign in to this account, or make its key, on the firm's PC — that would put
it back within reach of the thing it watches. If the account has to be recovered, do it
from the phone.

## Setting it up (phone only, about 15 minutes, once)

1. Create a new GitHub account (it is the firm's one "machine account" under GitHub's
   terms) with an email address the PC cannot read: not the work mailbox and not any
   Gmail the PC is signed in to (a new address made on the phone works). Turn on
   two-factor sign-in with an authenticator app or passkey on the phone, and save the
   recovery codes somewhere that is not the PC.
2. Open the template link the setup session gives you, tap **Use this template** ->
   **Create a new repository**, owner = the new account, visibility **Public** (so the
   firm repo can see whether it is still running). Its run logs are public: they show
   when a change was made and the record's type and name, never the record's content
   or the name of the key that made it.
3. Open the Cloudflare link the setup session gives you, sign in, check the summary
   reads *Account Settings: Read* on the firm account, tap **Create Token**, copy it.
4. In the new repository: **Settings -> Secrets and variables -> Actions -> New
   repository secret**, name `CLOUDFLARE_AUDIT_READ_TOKEN`, paste, **Add secret**.
5. Install the GitHub app, sign in with the new account, and turn on push
   notifications for **Actions: failed workflows**.

Then the setup session points the firm repo at this repository (so it notices if the
watcher stops), makes one harmless test record (shown to you first) and removes it. The
first run reads everything since 28 October 2026, so it buzzes whether or not it saw
the test: the session tells you the test record's name, and the test has worked only if
one `CHANGE` line names it. A record made less than 6 hours before a run is read by the
run after.

## When it buzzes

Open the failed run. Each `CHANGE` line is one write. If you approved a change that
day and every line is it, nothing to do. Any other line: revoke the **WPM DNS edit**
key in Cloudflare from the phone. "Could not be read" usually means the key expired;
renew it (step 3 and 4) — but an intruder revoking it looks the same, so check
Cloudflare's token list too. Logs here never show record contents; to see what a
record was set to, ask a session on the PC to read the firm repo's own run, which
does.
