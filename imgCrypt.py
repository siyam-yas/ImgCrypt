import cv2
import numpy as np
import hashlib
import os
import base64
from cryptography.fernet import Fernet
from typing import Tuple, Optional

class ImageCrypto:
    @staticmethod
    def generate_key(keyword: str) -> Fernet:
        """
        Generate a Fernet key from a keyword using SHA256.
        
        Args:
            keyword (str): The password/keyword to generate the key from
            
        Returns:
            Fernet: A Fernet cipher object for encryption/decryption
        """
        hash_obj = hashlib.sha256(keyword.encode('utf-8'))
        key = base64.urlsafe_b64encode(hash_obj.digest())
        return Fernet(key)
    
    @staticmethod
    def add_text_to_image(image: np.ndarray, text: str) -> np.ndarray:
        """
        Add text overlay to an image.
        
        Args:
            image (np.ndarray): The image to add text to
            text (str): The text to add
            
        Returns:
            np.ndarray: Image with text overlay
        """
        img_with_text = image.copy()
        font = cv2.FONT_HERSHEY_SIMPLEX
        font_scale = 1
        thickness = 2
        color = (255, 255, 255)
        
        (text_width, text_height), _ = cv2.getTextSize(text, font, font_scale, thickness)
        text_x = 10
        text_y = text_height + 10
        
        cv2.putText(img_with_text, text, (text_x, text_y), font, font_scale, (0, 0, 0), thickness + 1)
        cv2.putText(img_with_text, text, (text_x, text_y), font, font_scale, color, thickness)
        
        return img_with_text

    def encrypt_image(self, image_path: str, keyword: str, output_path: str, text: str) -> bool:
        """
        Encrypt an image and save it with random noise and embedded text.
        
        Args:
            image_path (str): Path to the input image
            keyword (str): Encryption keyword
            output_path (str): Path to save the encrypted file
            text (str): Text to embed in the noise image
            
        Returns:
            bool: True if encryption was successful, False otherwise
        """
        try:
            # Read and validate image
            image = cv2.imread(image_path, cv2.IMREAD_UNCHANGED)
            if image is None:
                raise ValueError("Failed to load image")
            
            # Generate cipher and encrypt image data
            cipher = self.generate_key(keyword)
            encrypted_data = cipher.encrypt(image.tobytes())
            
            # Create and save noise image with text
            noise = np.random.randint(0, 256, image.shape, dtype=np.uint8)
            noise_with_text = self.add_text_to_image(noise, text)
            noise_path = f"{output_path}_noise.png"
            cv2.imwrite(noise_path, noise_with_text)
            
            # Save encrypted data with shape information
            shape_info = np.array(image.shape, dtype=np.int32).tobytes()
            shape_size = len(shape_info).to_bytes(4, 'big')
            
            with open(output_path, 'wb') as f:
                f.write(shape_size + shape_info + encrypted_data)
            
            return True
            
        except Exception as e:
            print(f"Encryption failed: {str(e)}")
            return False

    def decrypt_image(self, encrypted_path: str, keyword: str, output_path: str) -> bool:
        """
        Decrypt an encrypted image file.
        
        Args:
            encrypted_path (str): Path to the encrypted file
            keyword (str): Decryption keyword
            output_path (str): Path to save the decrypted image
            
        Returns:
            bool: True if decryption was successful, False otherwise
        """
        try:
            # Validate file path
            if encrypted_path.endswith('_noise.png'):
                raise ValueError("You are trying to decrypt the noise image. Please use the encrypted data file (without '_noise.png')")
            
            # Add .png extension if not provided in output path
            if not output_path.lower().endswith(('.png', '.jpg', '.jpeg')):
                output_path += '.png'
            
            # Read encrypted file
            try:
                with open(encrypted_path, 'rb') as f:
                    data = f.read()
            except FileNotFoundError:
                # Try adding default extension if file not found
                if os.path.exists(encrypted_path + '.enc'):
                    with open(encrypted_path + '.enc', 'rb') as f:
                        data = f.read()
                else:
                    raise FileNotFoundError("Encrypted file not found. Make sure you're using the correct file path.")
            
            # Validate minimum file size
            if len(data) < 8:  # Minimum size for header
                raise ValueError("Invalid encrypted file format")
            
            # Extract shape information
            try:
                shape_size = int.from_bytes(data[:4], 'big')
                shape_info = data[4:4 + shape_size]
                encrypted_data = data[4 + shape_size:]
            except Exception:
                raise ValueError("File appears to be corrupted or in wrong format")
            
            if len(shape_info) % 4 != 0:
                raise ValueError("Corrupted file: invalid shape information")
            
            # Generate cipher and decrypt
            cipher = self.generate_key(keyword)
            try:
                decrypted_data = cipher.decrypt(encrypted_data)
            except Exception:
                raise ValueError("Decryption failed - incorrect password or corrupted file")
            
            # Reconstruct and save image
            try:
                image_shape = tuple(np.frombuffer(shape_info, dtype=np.int32))
                image = np.frombuffer(decrypted_data, dtype=np.uint8).reshape(image_shape)
                cv2.imwrite(output_path, image)
            except Exception:
                raise ValueError("Failed to reconstruct image - file may be corrupted")
            
            return True
            
        except Exception as e:
            print(f"Decryption failed: {str(e)}")
            return False

def main():
    crypto = ImageCrypto()
    
    while True:
        print("\nImage Encryption/Decryption Tool")
        print("1. Encrypt image")
        print("2. Decrypt image")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == '1':
            image_path = input("Enter input image path: ").strip()
            if not os.path.exists(image_path):
                print("Error: Input image not found!")
                continue
                
            keyword = input("Enter encryption keyword: ").strip()
            if not keyword:
                print("Error: Keyword cannot be empty!")
                continue
                
            output_path = input("Enter output file path (without extension): ").strip()
            text = input("Enter text to embed in encrypted image: ").strip()
            
            if crypto.encrypt_image(image_path, keyword, output_path, text):
                print("\nEncryption successful!")
                print(f"Encrypted file saved as: {output_path}")
                print(f"Noise image saved as: {output_path}_noise.png")
            
        elif choice == '2':
            encrypted_path = input("Enter encrypted file path (without _noise.png): ").strip()
            keyword = input("Enter decryption keyword: ").strip()
            if not keyword:
                print("Error: Keyword cannot be empty!")
                continue
                
            output_path = input("Enter output image path (will add .png if no extension): ").strip()
            
            if crypto.decrypt_image(encrypted_path, keyword, output_path):
                print("\nDecryption successful!")
                print(f"Decrypted image saved as: {output_path}")
            
        elif choice == '3':
            print("\nGoodbye!")
            break
            
        else:
            print("\nInvalid choice! Please select 1, 2, or 3.")

if __name__ == "__main__":
    main()