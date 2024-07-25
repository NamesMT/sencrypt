import type { SEncryptStorageInterface } from '~/SEncrypt'

/**
 * This is a simple in-memory storage implementation.
 * 
 * This is not recommended for production use, but it is useful for testing.
 */
export class MemoryStorage implements SEncryptStorageInterface {
  saltStore: Record<string, string> = {}

  cipherStore: Record<string, string> = {}

  async getSalt(partition: string, id: string) { return this.saltStore[`${partition}#${id}`] }
  async setSalt(partition: string, id: string, value: string) { this.saltStore[`${partition}#${id}`] = value }

  async getCiphertext(partition: string, id: string) { return this.cipherStore[`${partition}#${id}`] }
  async setCiphertext(partition: string, id: string, value: string) { this.cipherStore[`${partition}#${id}`] = value }
}
