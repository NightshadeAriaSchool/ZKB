import hashlib

class CaesarCypher:
    class Alphabet:
        ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        LOWERCASE_ALPHABET = ALPHABET.lower()
        SPECIAL_CZECH = "ÁČĎÉĚÍŇÓŘŠŤÚŮÝŽ"
        SPECIAL_CZECH_LOWER = SPECIAL_CZECH.lower()
        SPACE = " "
        SYMBOLS = ".!?,;:()[]{}<>"
        DIGITS = "0123456789"

    @staticmethod
    def encrypt(message:str, alphabet:str, shift:int) -> str:
        """
        Encrypts a message using the Caesar cipher algorithm.
        :param message: The message to encrypt.
        :param alphabet: The alphabet to use for encryption.
        :param shift: The number of positions to shift each letter.
        :return: The encrypted message.
        """
        encrypted_message = ""
        for char in message:
            if char in alphabet:
                index = (alphabet.index(char) + shift) % len(alphabet)
                encrypted_message += alphabet[index]
            else:
                encrypted_message += char
        return encrypted_message
    
    @staticmethod
    def decrypt(message:str, alphabet:str, shift:int) -> str:
        """
        Decrypts a message using the Caesar cipher algorithm.
        :param message: The message to decrypt.
        :param alphabet: The alphabet to use for decryption.
        :param shift: The number of positions to shift each letter.
        :return: The decrypted message.
        """
        decrypted_message = ""
        for char in message:
            if char in alphabet:
                index = (alphabet.index(char) - shift) % len(alphabet)
                decrypted_message += alphabet[index]
            else:
                decrypted_message += char
        return decrypted_message
    
    @staticmethod
    def encrypt_file(file_path_from:str, file_path_to:str, alphabet: str, shift:int) -> None:
        """
        Encrypts a file using the Caesar cipher algorithm.
        :param file_path_from: The path to the file to encrypt.
        :param file_path_to: The path to save the encrypted file.
        :param alphabet: The alphabet to use for encryption.
        :param shift: The number of positions to shift each letter.
        """
        with open(file_path_from, 'r', encoding='utf-8') as f:
            data = f.read()
        
        encrypted_data = CaesarCypher.encrypt(data, alphabet, shift)
        
        with open(file_path_to, 'w', encoding='utf-8') as f:
            f.write(encrypted_data)
    
    @staticmethod
    def decrypt_file(file_path_from:str, file_path_to:str, alphabet: str, shift:int) -> None:
        """
        Decrypts a file using the Caesar cipher algorithm.
        :param file_path_from: The path to the file to decrypt.
        :param file_path_to: The path to save the decrypted file.
        :param alphabet: The alphabet to use for decryption.
        :param shift: The number of positions to shift each letter.
        """
        with open(file_path_from, 'r', encoding='utf-8') as f:
            data = f.read()
        
        decrypted_data = CaesarCypher.decrypt(data, alphabet, shift)
        
        with open(file_path_to, 'w', encoding='utf-8') as f:
            f.write(decrypted_data)

class AES:
    class SBox:
        s_box = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
        ]
        s_box_inv = [0] * 256
        for i in range(256):
            s_box_inv[s_box[i]] = i
        
        def sub_word(word:list[int]) -> list[int]:
            """Apply S-box to each byte in a word"""
            return [AES.SBox.s_box[b] for b in word]

        def inv_sub_word(word: list[int]) -> list[int]:
            """Apply inverse S-box to each byte in a word"""
            return [AES.SBox.s_box_inv[b] for b in word]
    
    class Key:
        Rcon = [
            0x00,  # not used
            0x01, 0x02, 0x04, 0x08,
            0x10, 0x20, 0x40, 0x80,
            0x1B, 0x36
        ]

        def rot_word(word:list[int]) -> list[int]:
            """Rotate a 4-byte word left"""
            return word[1:] + word[:1]

        def key_expansion(key: list[int]) -> list[list[int]]:
            if len(key) == 16:
                Nk = 4
                Nr = 10
            elif len(key) == 24:
                Nk = 6
                Nr = 12
            elif len(key) == 32:
                Nk = 8
                Nr = 14
            else:
                raise ValueError("Key must be 16, 24, or 32 bytes")

            Nb = 4
            w = []

            for i in range(Nk):
                w.append(key[4*i : 4*(i+1)])

            for i in range(Nk, Nb * (Nr + 1)):
                temp = w[i - 1]
                if i % Nk == 0:
                    temp = AES.SBox.sub_word(AES.Key.rot_word(temp))
                    temp[0] ^= AES.Key.Rcon[i // Nk]
                elif Nk > 6 and i % Nk == 4:
                    temp = AES.SBox.sub_word(temp)
                w.append([a ^ b for a, b in zip(w[i - Nk], temp)])

            round_keys = []
            for r in range(Nr + 1):
                round_key = []
                for c in range(4):  # 4 words per round key (always)
                    round_key += w[r*4 + c]
                round_keys.append(round_key)
            
            return round_keys
            
        def key_schedule(password: str, length: int) -> list[list[int]]:
            """
            Generate round keys for AES encryption.
            :param password: The password to use for key generation.
            :param length: The length of the key (16, 24, or 32 bytes).
            :return: A list of round keys.
            """
            if length not in [16, 24, 32]:
                raise ValueError("Key length must be 16, 24, or 32 bytes")
            
            # Hash the password to get a fixed-length key
            hashed_password = hashlib.sha256(password.encode()).digest()
            return AES.Key.key_expansion(hashed_password[:length])
        
    class Encryption:
        @staticmethod
        def add_round_key(block: list[int], round_key: list[int]) -> list[int]:
            """
            Add round key to the block.
            :param block: The block to modify.
            :param round_key: The round key to add.
            """

            return [b ^ k for b, k in zip(block, round_key)]
        
        @staticmethod
        def sub_bytes(block: list[int]) -> list[int]:
            """
            Substitute bytes in the block using the S-box.
            :param block: The block to modify.
            """
            return [AES.SBox.s_box[b] for b in block]
        
        @staticmethod   
        def shift_rows(block: list[int]) -> list[int]:
            """
            Shift rows in the block.
            :param block: The block to modify.
            """
            # state is a flat list of 16 bytes
            return [
                block[0], block[1], block[2], block[3],
                block[5], block[6], block[7], block[4],
                block[10], block[11], block[8], block[9],
                block[15], block[12], block[13], block[14]
            ]
        
        @staticmethod
        def xtime(a):
            return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1)

        @staticmethod
        def mix_single_column(col):
            t = col[0] ^ col[1] ^ col[2] ^ col[3]
            u = col[0]
            col[0] ^= t ^ AES.Encryption.xtime(col[0] ^ col[1])
            col[1] ^= t ^ AES.Encryption.xtime(col[1] ^ col[2])
            col[2] ^= t ^ AES.Encryption.xtime(col[2] ^ col[3])
            col[3] ^= t ^ AES.Encryption.xtime(col[3] ^ u)
            return col

        @staticmethod
        def mix_columns(block:list[int]) -> list[int]:
            for i in range(0, 16, 4):
                col = block[i:i+4]
                mixed = AES.Encryption.mix_single_column(col)
                block[i:i+4] = mixed
            return block
        
        @staticmethod
        def encrypt_block(block: list[int], keys: list[list[int]]) -> list[int]:
            """
            Encrypt a single block of data using AES.
            :param block: The block to encrypt.
            :param key: The round keys.
            :return: The encrypted block.
            """
            block = AES.Encryption.add_round_key(block, keys[0])

            for round in range(1, len(keys) - 1):
                block = AES.Encryption.sub_bytes(block)
                block = AES.Encryption.shift_rows(block)
                if round != len(keys[round]) - 2:
                    block = AES.Encryption.mix_columns(block)
                block = AES.Encryption.add_round_key(block, keys[round])

            block = AES.Encryption.sub_bytes(block)
            block = AES.Encryption.shift_rows(block)
            block = AES.Encryption.add_round_key(block, keys[-1])

            return block
    
    class Decryption:
        @staticmethod
        def add_round_key(block: list[int], round_key: list[int]) -> list[int]:
            """
            Add round key to the block.
            :param block: The block to modify.
            :param round_key: The round key to add.
            """
            return [b ^ k for b, k in zip(block, round_key)]
        
        @staticmethod
        def inv_sub_bytes(block: list[int]) -> list[int]:
            """
            Substitute bytes in the block using the inverse S-box.
            :param block: The block to modify.
            """
            return [AES.SBox.s_box_inv[b] for b in block]
        
        @staticmethod
        def inv_shift_rows(block: list[int]) -> list[int]:
            """
            Inverse shift rows in the block.
            :param block: The block to modify.
            """
            return [
                block[0], block[1], block[2], block[3],
                block[7], block[4], block[5], block[6],
                block[10], block[11], block[8], block[9],
                block[13], block[14], block[15], block[12]
            ]
        
        def gf_mult(a: int, b: int) -> int:
            """Multiply two bytes in GF(2^8)"""
            p = 0
            for i in range(8):
                if b & 1:
                    p ^= a
                carry = a & 0x80
                a = (a << 1) & 0xFF
                if carry:
                    a ^= 0x1B
                b >>= 1
            return p


        def inv_mix_single_column(col: list[int]) -> list[int]:
            """Perform Inverse MixColumns on a single column"""
            assert len(col) == 4, "Column must be 4 bytes long"

            a = col.copy()
            col0 = AES.Decryption.gf_mult(a[0], 0x0e) ^ AES.Decryption.gf_mult(a[1], 0x0b) ^ AES.Decryption.gf_mult(a[2], 0x0d) ^ AES.Decryption.gf_mult(a[3], 0x09)
            col1 = AES.Decryption.gf_mult(a[0], 0x09) ^ AES.Decryption.gf_mult(a[1], 0x0e) ^ AES.Decryption.gf_mult(a[2], 0x0b) ^ AES.Decryption.gf_mult(a[3], 0x0d)
            col2 = AES.Decryption.gf_mult(a[0], 0x0d) ^ AES.Decryption.gf_mult(a[1], 0x09) ^ AES.Decryption.gf_mult(a[2], 0x0e) ^ AES.Decryption.gf_mult(a[3], 0x0b)
            col3 = AES.Decryption.gf_mult(a[0], 0x0b) ^ AES.Decryption.gf_mult(a[1], 0x0d) ^ AES.Decryption.gf_mult(a[2], 0x09) ^ AES.Decryption.gf_mult(a[3], 0x0e)

            return [col0, col1, col2, col3]
        
        @staticmethod
        def inv_mix_columns(block: list[int]) -> list[int]:
            for i in range(0, 16, 4):
                col = block[i:i + 4]
                mixed = AES.Decryption.inv_mix_single_column(col)
                block[i:i + 4] = mixed
            return block
        
        @staticmethod
        def decrypt_block(block: list[int], keys: list[int]) -> list[int]:
            """
            Decrypt a single block of data using AES.
            :param block: The block to decrypt.
            :param keys: Tge round keys.
            :return: The decryoted block.
            """
            block = AES.Decryption.add_round_key(block, keys[-1])
            block = AES.Decryption.inv_shift_rows(block)
            block = AES.Decryption.inv_sub_bytes(block)
            
            for round in range(len(keys) - 2, 0, -1):
                block = AES.Decryption.add_round_key(block, keys[round])
                if round != len(keys[round]) - 2:
                    block = AES.Decryption.inv_mix_columns(block)
                block = AES.Decryption.inv_sub_bytes(block)
                block = AES.Decryption.inv_shift_rows(block)

            block = AES.Decryption.add_round_key(block, keys[0])

            return block

    @staticmethod
    def encrypt(message: str, password: str, length: int = 16) -> list[int]:
        """
        Encrypts a message using AES encryption.
        :param message: The message to encrypt.
        :param password: The password to use for key generation.
        :param length: The length of the key (16, 24, or 32 bytes).
        :return: The encrypted message.
        """
        keys = AES.Key.key_schedule(password, length)
        byte_message = list(bytes(message.encode('utf-8')))
        for i in range(len(byte_message) % length, length):
            byte_message.append(0)

        encrypted_message = [AES.Encryption.encrypt_block(byte_message[i:i+16], keys) for i in range(0, len(byte_message), 16)]
        return [byte for block in encrypted_message for byte in block]
    
    @staticmethod
    def decrypt(message: list[int], password: str, length: int = 16):
        keys = AES.Key.key_schedule(password, length)
        decrypted_message = [AES.Decryption.decrypt_block(message[i:i + 16], keys) for i in range(0, len(message), 16)]
        decrypted_message = [byte & 0x7F for block in decrypted_message for byte in block]

        return bytes(decrypted_message).decode('ascii').rstrip('\x00')

    @staticmethod
    def encrypt_file(file_path_from: str, file_path_to: str, password: str, length: int = 16) -> None:
        """
        Encrypts a file using AES encryption.
        :param file_path_from: The path to the file to encrypt.
        :param file_path_to: The path to save the encrypted file.
        :param password: The password to use for key generation.
        :param length: The length of the key (16, 24, or 32 bytes).
        """
        with open(file_path_from, 'rb') as f:
            data = f.read()
        
        encrypted_data = AES.encrypt(data.decode('utf-8'), password, length)
        
        with open(file_path_to, 'wb') as f:
            f.write(bytes(encrypted_data))
    
    @staticmethod
    def decrypt_file(file_path_from: str, file_path_to: str, password: str, length: int = 16) -> None:
        """
        Decrypts a file using AES encryption.
        :param file_path_from: The path to the file to decrypt.
        :param file_path_to: The path to save the decrypted file.
        :param password: The password to use for key generation.
        :param length: The length of the key (16, 24, or 32 bytes).
        """
        with open(file_path_from, 'rb') as f:
            data = f.read()
        
        decrypted_data = AES.decrypt(list(data), password, length)
        
        with open(file_path_to, 'w', encoding='utf-8') as f:
            f.write(decrypted_data)

AES.encrypt_file('cat_cz.txt', 'cat_cz_enc.enc', 'password', 16)
AES.decrypt_file('cat_cz_enc.enc', 'cat_cz_dec_correct.txt', 'password', 16)
AES.decrypt_file('cat_cz_enc.enc', 'cat_cz_dec_wrong.txt', 'passwore', 16)

alphabet = CaesarCypher.Alphabet.ALPHABET + \
    CaesarCypher.Alphabet.LOWERCASE_ALPHABET + \
    CaesarCypher.Alphabet.SPACE + \
    CaesarCypher.Alphabet.SYMBOLS + \
    CaesarCypher.Alphabet.DIGITS
CaesarCypher.encrypt_file('cat_en.txt', 'cat_en_enc.txt', alphabet, 3)
CaesarCypher.decrypt_file('cat_en_enc.txt', 'cat_en_dec_correct.txt', alphabet, 3)
CaesarCypher.decrypt_file('cat_en_enc.txt', 'cat_en_dec_wrong.txt', alphabet, 4)
