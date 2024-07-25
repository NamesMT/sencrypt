import { decrypt, encrypt } from '@namesmt/aes-gcm'
import type { SEncryptEncrypterInterface } from '~/SEncrypt'

export class AesGcmEncrypter implements SEncryptEncrypterInterface {
  encrypt = async (plaintext: string, password: string) => {
    return encrypt(plaintext, password)
  }

  decrypt = async (ciphertext: string, password: string) => {
    return decrypt(ciphertext, password)
  }
}
