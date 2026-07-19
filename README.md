<h1 id="title">Ciphertext Unlock</h1>

1.  The script reads the content in the file `encrypted.json`, which contains the necessary info to decrypt the original content.
2.  It then tries the passwords from `passwords.txt`.
3.  If a password is correct it decrypts the ciphertext and extracts the decrypted value.

The repository already includes a `encrypted.json` file and the corresponding password in `passwords.txt` to test out the script.

### **Run the script**

```
node main.js
```

### **Användaravtal:**

*   Vid lyckad dekryptering av ciphertext är användaren skyldig Adrian (repository owner) en öl.
