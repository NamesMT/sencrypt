import type { SEncryptEncrypterInterface } from '~/SEncrypt'

/**
 * This is a simple demo encrypter implementation.
 * 
 * This is NOT FOR PRODUCTION USE, it is useful for testing.
 */
export class SimpleEncrypter implements SEncryptEncrypterInterface {
  encrypt = async (plaintext: string, password: string) => {
    return `${plaintext}#${password}`
  }

  decrypt = async (ciphertext: string, password: string) => {
    const splitted = ciphertext.split('#')
    if (splitted[1] !== password)
      throw new Error('Invalid password')

    return ciphertext.split('#')[0]
  }
}
