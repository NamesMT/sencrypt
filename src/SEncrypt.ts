/**
 * @module SEncrypt
 */

import type { SHashStorageInterface } from '@namesmt/shash'
import { SHash } from '@namesmt/shash'
import { validParams } from './utils'

export interface SEncryptStorageInterface extends SHashStorageInterface {
  /**
   * Get ciphertext stored in the given partition and id.
   */
  getCiphertext: (partition: string, id: string) => Promise<string | undefined>

  /**
   * Set (store) ciphertext into the given partition and id.
   */
  setCiphertext: (partition: string, id: string, ciphertext: string) => Promise<void>
}

export interface SEncryptEncrypterInterface {
  /**
   * Encrypts plaintext into a ciphertext with the supplied password.
   */
  encrypt: (plaintext: string, password: string) => Promise<string>

  /**
   * Decrypts ciphertext back into plaintext with the supplied password.
   */
  decrypt: (ciphertext: string, password: string) => Promise<string>
}

/**
 * Main entry of the module, create your SEncrypt helpers with this class.
 * 
 * @param storage - The storage interface, implementing SEncryptStorageInterface.
 * @param hasher - The hashing algorithm, which should return a string.
 * @param encrypter - The encryption algorithm, which should return a string.
 */
export class SEncrypt {
  private SHash: SHash

  constructor(private storage: SEncryptStorageInterface, private hasher: (input: string) => string | Promise<string>, private encrypter: SEncryptEncrypterInterface) {
    this.SHash = new SHash(this.storage, this.hasher)
  }

  /**
   * Encrypts plaintext into ciphertext, secured with a hash key created from the given salt, partition and id.
   */
  encrypt = async (salt: string, partition: string, id: string, plaintext: string): Promise<string> => {
    const cKey = await this.SHash.getHash(salt, partition, id)

    validParams(plaintext)

    return await this.encrypter.encrypt(plaintext, cKey)
  }

  /**
   * Decrypts a ciphertext that was secured with a hash key created from the given salt, partition and id, back into plaintext.
   */
  decrypt = async (salt: string, partition: string, id: string, ciphertext: string): Promise<string> => {
    const cKey = await this.SHash.getHash(salt, partition, id)

    validParams(ciphertext)

    return await this.encrypter.decrypt(ciphertext, cKey)
  }
}
