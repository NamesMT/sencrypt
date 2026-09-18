import { decrypt as aesGcmDecrypt, encrypt as aesGcmEncrypt } from '@namesmt/aes-gcm'
import type { SEncryptEncrypterInterface } from '#src/SEncrypt.js'

export class AesGcmEncrypter implements SEncryptEncrypterInterface {
  encrypt = aesGcmEncrypt

  decrypt = aesGcmDecrypt
}
