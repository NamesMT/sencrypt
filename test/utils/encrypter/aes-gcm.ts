import { decrypt as aesGcmDecrypt, encrypt as aesGcmEncrypt } from '@namesmt/aes-gcm'
import type { SEncryptEncrypterInterface } from '~/SEncrypt'

export class AesGcmEncrypter implements SEncryptEncrypterInterface {
  encrypt = aesGcmEncrypt

  decrypt = aesGcmDecrypt
}
