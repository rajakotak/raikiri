# cipher_app.py
import streamlit as st
from fpdf import FPDF
from docx import Document


def caesar_encryption(message, key):
    if not key:
        return "Key cannot be empty for Caesar Cipher!"
    
    encrypted_text = ""
    for char in message:
        if char.isalpha():
            shift = (ord(char) - ord('A') + key) % 26
            encrypted_text += chr(ord('A') + shift)
        else:
            encrypted_text += char
    return encrypted_text

def caesar_decryption(message, key):
    if not key:
        return "Key cannot be empty for Caesar Cipher!"
    
    decrypted_text = ""
    for char in message:
        if char.isalpha():
            shift = (ord(char) - ord('A') - key) % 26
            decrypted_text += chr(ord('A') + shift)
        else:
            decrypted_text += char
    return decrypted_text

def rode_encryption(message):
    key = 13
    encrypted_text = ""
    for char in message:
        if char.isalpha():
            temp = ord(char) + key
            if temp > ord('Z'):
                temp -= 26
            encrypted_text += chr(temp)
        else:
            encrypted_text += char
    return encrypted_text

def rode_decryption(message):
    key = 13
    decrypted_text = ""
    for char in message:
        if char.isalpha():
            temp = ord(char) - key
            if temp < ord('A'):
                temp += 26
            decrypted_text += chr(temp)
        else:
            decrypted_text += char
    return decrypted_text

def rot13_encryption(message):
    encrypted_text = ""
    for char in message:
        if char.isalpha():
            temp = ord(char) + 13
            if char.islower() and temp > ord('z'):
                temp -= 26
            elif char.isupper() and temp > ord('Z'):
                temp -= 26
            encrypted_text += chr(temp)
        else:
            encrypted_text += char
    return encrypted_text

def rot13_decryption(message):
    decrypted_text = ""
    for char in message:
        if char.isalpha():
            temp = ord(char) - 13
            if char.islower() and temp < ord('a'):
                temp += 26
            elif char.isupper() and temp < ord('A'):
                temp += 26
            decrypted_text += chr(temp)
        else:
            decrypted_text += char
    return decrypted_text

def encrypt_vigenere_cipher(text, keyword):
    if not keyword:
        st.warning("Key cannot be empty for Vigenere Cipher!")
        return
    
    result = ""
    keyword_length = len(keyword)
    keyword = keyword.upper()
    key_index = 0

    for char in text:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            keyword_shifted = ord(keyword[key_index % keyword_length]) - ord('A')
            alphabet = ord(char) - ascii_offset
            alphabet_shifted = (alphabet + keyword_shifted) % 26
            char = chr(alphabet_shifted + ascii_offset)
            key_index += 1
        result += char

    return result

def decrypt_vingenere_cipher(text, keyword):
    if not keyword:
        st.warning("Key cannot be empty for Vigenere Cipher!")
        return
    
    result = ""
    keyword_length = len(keyword)
    keyword = keyword.upper()
    key_index = 0

    for char in text:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            keyword_shifted = ord(keyword[key_index % keyword_length]) - ord('A')
            alphabet = ord(char) - ascii_offset
            alphabet_shift_reversed = (alphabet - keyword_shifted) % 26
            char = chr(alphabet_shift_reversed + ascii_offset)
            key_index += 1
        result += char

    return result


def process_caesar_cipher(message, option, key):
    if option == 'Encryption':
        return caesar_encryption(message.upper(), key)
    else:
        return caesar_decryption(message.upper(), key)

def process_rode_cipher(message, option):
    if option == 'Encryption':
        return rode_encryption(message.upper())
    else:
        return rode_decryption(message.upper())

def process_rot13_cipher(message, option):
    if option == 'Encryption':
        return rot13_encryption(message.upper())
    else:
        return rot13_decryption(message.upper())

def process_vigenere_cipher(message, option, key):
    if option == 'Encryption':
        return encrypt_vigenere_cipher(message.upper(), key)
    else:
        return decrypt_vingenere_cipher(message.upper(), key)


def main():
    st.title('Cipher App')
    st.caption('Made by: Muhammad Faridan Sutariya')

    cipher_options = ['Caesar Cipher', 'Rode', 'Rot13', 'Vigenere']
    selected_cipher = st.selectbox('Select Cipher:', cipher_options)

    def display_caesar_cipher():
        option = st.radio('Select Option:', ('Encryption', 'Decryption'))
        message = st.text_input('Enter Message:')
        key = st.number_input('Enter Key:', value=1)
        
        if st.button('Encrypt' if option == 'Encryption' else 'Decrypt'):
            if not message:
                st.warning('Please enter a message!')
            else:
                processed_text = process_caesar_cipher(message, option, key)
                st.markdown(f'Processed Text: \n```\n{processed_text}\n```')

    def display_rode_rot13_cipher():
        option = st.radio('Select Option:', ('Encryption', 'Decryption'))
        message = st.text_input('Enter Message:')
        
        if st.button('Encrypt' if option == 'Encryption' else 'Decrypt'):
            if not message:
                st.warning('Please enter a message!')
            else:
                if selected_cipher == 'Rode':
                    processed_text = process_rode_cipher(message, option)
                else:
                    processed_text = process_rot13_cipher(message, option)

                st.markdown(f'Processed Text: \n```\n{processed_text}\n```')

    def display_vigenere_cipher():
        option = st.radio('Select Option:', ('Encryption', 'Decryption'))
        message = st.text_input('Enter Message:')
        key = st.text_input('Key:')
        if st.button('Encrypt' if option == 'Encryption' else 'Decrypt') and (not key or not key.isalpha()):
            if not key:
                st.warning('Key cannot be empty for Vigenere Cipher!')
            else:
                st.warning('Key for Vigenere Cipher must contain only alphabetic characters!')
        else:
            if not message:
                st.warning('Please enter a message!')
            else:
                processed_text = process_vigenere_cipher(message, option, key)
                st.markdown(f'Processed Text: \n```\n{processed_text}\n```')

    if selected_cipher == 'Caesar Cipher':
        display_caesar_cipher()
    elif selected_cipher in ['Rode', 'Rot13']:
        display_rode_rot13_cipher()
    elif selected_cipher == 'Vigenere':
        display_vigenere_cipher()

if __name__ == "__main__":
    main()
