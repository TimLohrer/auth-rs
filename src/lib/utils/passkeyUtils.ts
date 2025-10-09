/**
 * Functions copied from https://github.com/MasterKale/SimpleWebAuthn
 */

export default class PasskeyUtils {
    static bufferToBase64URLString(buffer: ArrayBuffer): string {
      const bytes = new Uint8Array(buffer);
      let str = '';
    
      for (const charCode of bytes) {
        str += String.fromCharCode(charCode);
      }
    
      const base64String = btoa(str);
    
      return base64String.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }
    
    static base64URLStringToBuffer(base64URLString: string): ArrayBuffer {
      // Convert from Base64URL to Base64
      const base64 = base64URLString.replace(/-/g, '+').replace(/_/g, '/');
      /**
       * Pad with '=' until it's a multiple of four
       * (4 - (85 % 4 = 1) = 3) % 4 = 3 padding
       * (4 - (86 % 4 = 2) = 2) % 4 = 2 padding
       * (4 - (87 % 4 = 3) = 1) % 4 = 1 padding
       * (4 - (88 % 4 = 0) = 4) % 4 = 0 padding
       */
      const padLength = (4 - (base64.length % 4)) % 4;
      const padded = base64.padEnd(base64.length + padLength, '=');
    
      // Convert to a binary string
      const binary = atob(padded);
    
      // Convert binary string to buffer
      const buffer = new ArrayBuffer(binary.length);
      const bytes = new Uint8Array(buffer);
    
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
    
      return buffer;
    }
}
