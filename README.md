<h1>404Crypt Ransomware</h1>
<h1>By the1%</h1>

The Ransomware is 100% Written in Python language
> Watch the Tutorial to Fully Understanding the Working of the 404Crypt Ransomware
YouTube Tutorial: https://www.youtube.com/
> Google Gmail App Password: https://myaccount.google.com/apppasswords
> <h1>DISCLAIMER</h1> 
> <h5>This Tool Should Only Be Used For Educational & Cryptographical & Testing Purposes . Not for Revenge or Causing Harm</h5>
> <h5><br><br>Misuse or Illegal Usage of the Tool One will Be solely Be held Responsible for not Obeying Federal & State Laws</h5>
> <h5><br><br>The1% shall not assume any responsibility for Misuse or Damage Caused by the Program</h5>


<h1> The Ransomware Encryption is based on the 404Crypt.py file</h1>

<h4>Which is  made of The Following Python Classes</h4>
<ol>
<h2>Malicious(Encryption class)</h2>
<h2>RansomNote Class</h2>
<h2>Decryption Class</h2>
</ol>


<h3><li><b><h3>Malicious/Encryption Class</h3></b></li></h3>
    <ol>
    <h4> Encryption of target is done based on the OS Detection the Encrypts  File whose  extensions are specified then renames then with a 404Crypt File Extension</h4>
    <h4>File are Encrypted with a Unique AES key stored in the symmetric.pem </h4>
    <h6>After All Files Are Encrypted, The random AES key used for Encryption of the System is Encrypted using the Attacker's Public Key then Automatically Emailed To the Attacker via Gmail</h6>
    <h4>This means only the Attacker Can Decrypt the Encrypted key received via mail using their private key copy</h4>
    <h4>After all Encryption is Done a Ransom Note is Displayed onto the Victim's Screen</h4>
    <h3>The Ransom Note is generated by the NOTE CLASS which is responsible for generating and display of the Screen</h3>
    
<br>
<li><b><h3>NOTE CLASS (RansomNote Class)</h3></b></li>
    <ol>
    <h4>This is Displayed after Files are Encrypted</h4>
    <h4>The Ransom Note Initiates a CountDown Timer on the Target System </h4>
    <h6>Once Payments aren't Done Within the Period Of the Timer, All Files Encrypted are shredded | Deleted Permanently</h6>
    </ol>


<li><b><h3>DECRYPT CLASS</b></h3></b></li> 
    <ol>
    <h5>This handle the Decryption Of target System </h5>
    <h4>This is Derived as Child Class of Malicious class used for encryption</h4>
    <h4>Once the Victim places a Unencrypted Authentic AES key symmetric.pem File is placed on the Desktop of the currently logged users</h4>
    <h4>All Encrypted Files Will Be Decrypted </h4>
    </ol>
    
    
    
<br>
<li><b><h3>Key_Decrypt.py</h3></b></li> 
    <ol>
    <h6>This file is Retained by the Attacker</h6>
    <h4>When The Encrypted AES symmetric key symmetric.pem is received by the Attacker by Mail</h4>
    <h4>Once the symmetric.pem file is placed in the same Working Directory as the File Using the Attacker's Private key it can be Decrypted so that to Wait for the Ransom From the Victim</h4>
    <h6>The symmetric AES key symmetric.pem and the RSA asymmetric private Key private.pem Should Be kept in the same working directory as Key_Decrypt.py File</h6>
    </ol>
    
    
<br>
<li><b><h3>RSA_KEY_PAIR_GEN.py</h3></b></li> 
    <ol>
    <h4>This implements RSA to generate key pairs ie private & Public Key pairs that are used for Encryption/Decryption of the SYMMETRIC Key used in Encryption of Victim's Files</h4>
    <h4>The AES symmetric Key used in Victim Files Encryption is encrypted using Attackers Public key Hard Coded in the 404Crypt.py file</h4>
    <h4>The Public key stored in the public.pem file should be HardCorded in the 404Crypt.py file</h4>    
    <h4>The PRIVATE Key Should Be kept Private Such that only the Attacker using their Private key can decrypt the files on the Target System</h4>
    </ol>

<br>
<li><b><h3>encryption_key_gen.py</h3></b></li>
    <ol>
    <h4>Run this Once to generate a Encryption key</h4>
    <h4>Copy the key file symmetric.pem to a folder in which the 404Crypt.py file is located</h4>
    <h4>Since the file is required it contains the key used for encryption</h4>
    </ol>


