# ImgCRYPT - Image Encryption and Decryption Tool

This tool allows you to encrypt and decrypt images using a keyword-based encryption method. The encryption adds random noise to the image and embeds text into the noise, while the decryption restores the image using the same keyword.

## Features
- Encrypt images with a password/keyword.
- Embed custom text into the encrypted image.
- Decrypt encrypted images using the same keyword.

## Requirements
- Python 3.x
- OpenCV (`cv2`)
- NumPy
- Cryptography library (`cryptography`)

## Setup

1. Clone or download the repository.
2. Install the required dependencies:
   ```bash
   pip install opencv-python numpy cryptography
   ```

3. Make sure you have an image file (e.g., `.png`, `.jpg`) to encrypt.

## Usage

### Running the Program

1. Open a terminal and navigate to the folder containing the `img_crypt.py` file.
2. Run the script:
   ```bash
   python img_crypt.py
   ```

### Options
- **Encrypt Image:**
  - Provide the path of the image to encrypt.
  - Enter a password/keyword to encrypt the image.
  - The tool will generate an encrypted image file and a noise image with embedded text.
  
- **Decrypt Image:**
  - Provide the path of the encrypted file (not the noise image).
  - Enter the same password/keyword used during encryption.
  - The tool will decrypt and save the original image.

### Example Commands

#### Encrypting an Image
```bash
Enter input image path: /path/to/image.jpg
Enter encryption keyword: mysecretkey
Enter output file path (without extension): /path/to/encrypted_image
Enter text to embed in encrypted image: Any text you want
```

#### Decrypting an Image
```bash
Enter encrypted file path (without _noise.png): /path/to/encrypted_image
Enter decryption keyword: mysecretkey
Enter output image path: /path/to/decrypted_image.png
```

## Notes
- Always remember the keyword used for encryption; it's required for decryption.
- The noise image (`_noise.png`) is generated for visual effect and contains embedded text.
  
## License
This project is licensed under the YASL License - see the [License](License.md) file for details.