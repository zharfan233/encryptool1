from flask import Flask, render_template, request, send_file
import os
import io
import string
import numpy as np
from itertools import cycle

app = Flask(__name__)

# Fungsi-fungsi untuk metode enkripsi

def vigenere_cipher(text, key, mode='encrypt'):
    result = []
    key_cycle = cycle(key.upper())
    for char in text.upper():
        if char in string.ascii_uppercase:
            k = next(key_cycle)
            if mode == 'encrypt':
                result.append(chr((ord(char) + ord(k) - 2 * ord('A')) % 26 + ord('A')))
            else:
                result.append(chr((ord(char) - ord(k) + 26) % 26 + ord('A')))
        else:
            result.append(char)
    return ''.join(result)

def auto_key_vigenere(text, key, mode='encrypt'):
    result = []
    if mode == 'encrypt':
        full_key = key.upper() + text.upper()
    else:
        full_key = key.upper()
    
    for i, char in enumerate(text.upper()):
        if char in string.ascii_uppercase:
            k = full_key[i]
            if mode == 'encrypt':
                result.append(chr((ord(char) + ord(k) - 2 * ord('A')) % 26 + ord('A')))
                if mode == 'decrypt':
                    full_key += chr((ord(char) - ord(k) + 26) % 26 + ord('A'))
            else:
                dec = chr((ord(char) - ord(k) + 26) % 26 + ord('A'))
                result.append(dec)
                full_key += dec
        else:
            result.append(char)
    return ''.join(result)

def generate_playfair_matrix(key):
    key = key.upper().replace('J', 'I')
    matrix = []
    for char in key + string.ascii_uppercase:
        if char not in matrix and char in string.ascii_uppercase:
            matrix.append(char)
    return [matrix[i:i+5] for i in range(0, 25, 5)]

def playfair_cipher(text, key, mode='encrypt'):
    matrix = generate_playfair_matrix(key)
    text = text.upper().replace('J', 'I')
    if len(text) % 2 != 0:
        text += 'X'
    
    result = []
    for i in range(0, len(text), 2):
        a, b = text[i], text[i+1]
        row_a, col_a = next((r, c) for r, row in enumerate(matrix) for c, char in enumerate(row) if char == a)
        row_b, col_b = next((r, c) for r, row in enumerate(matrix) for c, char in enumerate(row) if char == b)
        
        if row_a == row_b:
            if mode == 'encrypt':
                result.extend([matrix[row_a][(col_a+1)%5], matrix[row_b][(col_b+1)%5]])
            else:
                result.extend([matrix[row_a][(col_a-1)%5], matrix[row_b][(col_b-1)%5]])
        elif col_a == col_b:
            if mode == 'encrypt':
                result.extend([matrix[(row_a+1)%5][col_a], matrix[(row_b+1)%5][col_b]])
            else:
                result.extend([matrix[(row_a-1)%5][col_a], matrix[(row_b-1)%5][col_b]])
        else:
            result.extend([matrix[row_a][col_b], matrix[row_b][col_a]])
    
    return ''.join(result)

def hill_cipher(text, key, mode='encrypt'):
    key_matrix = np.array([ord(c) - ord('A') for c in key.upper()]).reshape(2, 2)
    if mode == 'decrypt':
        det = int(np.linalg.det(key_matrix))
        det_inv = pow(det, -1, 26)
        adj = np.array([[key_matrix[1, 1], -key_matrix[0, 1]], 
                        [-key_matrix[1, 0], key_matrix[0, 0]]])
        key_matrix = (det_inv * adj) % 26
    
    result = []
    for i in range(0, len(text), 2):
        pair = np.array([ord(c) - ord('A') for c in text[i:i+2].upper()])
        encrypted = np.dot(key_matrix, pair) % 26
        result.extend([chr(int(c) + ord('A')) for c in encrypted])
    
    return ''.join(result)

def super_encryption(text, v_key, t_key, mode='encrypt'):
    if mode == 'encrypt':
        text = vigenere_cipher(text, v_key, 'encrypt')
        return transposition_cipher(text, t_key, 'encrypt')
    else:
        text = transposition_cipher(text, t_key, 'decrypt')
        return vigenere_cipher(text, v_key, 'decrypt')

def transposition_cipher(text, key, mode='encrypt'):
    key_order = sorted(range(len(key)), key=lambda k: key[k])
    
    if mode == 'encrypt':
        padding = (len(key) - len(text) % len(key)) % len(key)
        text += 'X' * padding
        rows = [text[i:i+len(key)] for i in range(0, len(text), len(key))]
        return ''.join(''.join(row[i] for row in rows) for i in key_order)
    else:
        cols = len(text) // len(key)
        rows = [''] * cols
        for i, k in enumerate(key_order):
            for j in range(cols):
                rows[j] += text[i * cols + j]
        return ''.join(rows)

# Flask routes

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    method = request.form['method']
    key = request.form['key']
    text = request.form['text']
    file = request.files['file']

    if file:
        text = file.read().decode('utf-8', errors='ignore')

    if method == 'vigenere':
        result = vigenere_cipher(text, key, 'encrypt')
    elif method == 'auto_key':
        result = auto_key_vigenere(text, key, 'encrypt')
    elif method == 'playfair':
        result = playfair_cipher(text, key, 'encrypt')
    elif method == 'hill':
        result = hill_cipher(text, key, 'encrypt')
    elif method == 'super':
        v_key, t_key = key.split(',')
        result = super_encryption(text, v_key, t_key, 'encrypt')
    
    return render_template('result.html', result=result.lower(), operation='Encryption')

@app.route('/decrypt', methods=['POST'])
def decrypt():
    method = request.form['method']
    key = request.form['key']
    text = request.form['text']
    file = request.files['file']

    if file:
        text = file.read().decode('utf-8', errors='ignore')

    if method == 'vigenere':
        result = vigenere_cipher(text, key, 'decrypt')
    elif method == 'auto_key':
        result = auto_key_vigenere(text, key, 'decrypt')
    elif method == 'playfair':
        result = playfair_cipher(text, key, 'decrypt')
    elif method == 'hill':
        result = hill_cipher(text, key, 'decrypt')
    elif method == 'super':
        v_key, t_key = key.split(',')
        result = super_encryption(text, v_key, t_key, 'decrypt')
    
    return render_template('result.html', result=result, operation='Decryption')

@app.route('/download', methods=['POST'])
def download():
    text = request.form['text']
    return send_file(io.BytesIO(text.encode()), as_attachment=True, download_name='result.txt', mimetype='text/plain')

if __name__ == '__main__':
    app.run(debug=True)