import { PlatformEncryptionProvider } from '../common/types'
import { getAllPotentialKeys } from './keyring'
import crypto from 'crypto'
import { error, infoblue } from '../../src/common/log'

export class LinuxCryptoProvider implements PlatformEncryptionProvider {
    private potentialKeys: Uint8Array[]
    private verifiedKey: Uint8Array | null = null

    constructor() {
        try {
            this.potentialKeys = getAllPotentialKeys()
            // infoblue(`linux crypto provider: initialized with ${this.potentialKeys.length} keys.`);
        } catch (e) {
            error("provider init failed:", e)
            this.potentialKeys = []
        }
    }

    getRawKey(): Uint8Array | null {
        return this.verifiedKey || (this.potentialKeys.length > 0 ? this.potentialKeys[0] : null)
    }

    decrypt(encryptedBuffer: Buffer): Buffer {
        if (encryptedBuffer.length < 3) throw new Error('short payload')
        const version = encryptedBuffer.subarray(0, 3).toString('ascii')
        if (version !== 'v10' && version !== 'v11') {
            throw new Error(`unsupported encryption version: ${version}`)
        }

        const iv = Buffer.alloc(16, 0x20)
        const ciphertext = encryptedBuffer.subarray(3)

        if (this.verifiedKey) {
            try { return this.attemptDecryption(ciphertext, this.verifiedKey, iv) } 
            catch { this.verifiedKey = null }
        }

        for (const key of this.potentialKeys) {
            try {
                const decrypted = this.attemptDecryption(ciphertext, key, iv)
                this.verifiedKey = key
                infoblue(`${version} decryption match found!`);
                return decrypted
            } catch { continue }
        }

        throw new Error(`BAD_DECRYPT: ${version} failed after trying ${this.potentialKeys.length} keys.`)
    }

    private attemptDecryption(ciphertext: Buffer, key: Uint8Array, iv: Buffer): Buffer {
        const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv)
        decipher.setAutoPadding(true)
        return Buffer.concat([decipher.update(ciphertext), decipher.final()])
    }

    encrypt(plaintext: Buffer): Buffer {
        const key = this.getRawKey()
        if (!key) throw new Error('no key available')
        const iv = Buffer.alloc(16, 0x20)
        const cipher = crypto.createCipheriv('aes-128-cbc', key, iv)
        return Buffer.concat([Buffer.from('v10'), cipher.update(plaintext), cipher.final()])
    }
}