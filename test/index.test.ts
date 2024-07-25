import { describe, expect, it } from 'vitest'
import { MemoryStorage } from './utils/storage/memory'
import { SimpleEncrypter } from './utils/encrypter/simple'
import { AesGcmEncrypter } from './utils/encrypter/aes-gcm'
import { SEncrypt } from '~/index'

describe('basic tests', () => {
  it('basic usages should work', async () => {
    expect(SEncrypt).toBeTypeOf('function')

    const helper = new SEncrypt(new MemoryStorage(), str => `${str}2`, new SimpleEncrypter())

    expect(helper).toMatchObject({
      encrypt: expect.any(Function),
      decrypt: expect.any(Function),
    })

    // Encrypt and decrypt
    const encrypted = await helper.encrypt('salt', 'partition', 'id', 'pt')
    expect(encrypted).toBeTypeOf('string')
    const decrypted = await helper.decrypt('salt', 'partition', 'id', encrypted)
    expect(decrypted).toBe('pt')
    // trying to decrypt with wrong password (different salt)
    await expect(helper.decrypt('salt2', 'partition', 'id', encrypted)).rejects.toThrowError('Invalid password')

    // Invalid param
    // @ts-expect-error params should be strings
    await expect(helper.encrypt('salt', 'partition', 'id', 5)).rejects.toThrowError('Params invalid')
  })

  it('destructured usage should work', async () => {
    const { encrypt, decrypt } = new SEncrypt(new MemoryStorage(), str => `${str}2`, new SimpleEncrypter())

    // Encrypt and decrypt
    const encrypted = await encrypt('salt', 'partition', 'id', 'pt')
    expect(encrypted).toBeTypeOf('string')
    const decrypted = await decrypt('salt', 'partition', 'id', encrypted)
    expect(decrypted).toBe('pt')
    // trying to decrypt with wrong password (different salt)
    await expect(decrypt('salt2', 'partition', 'id', encrypted)).rejects.toThrowError('Invalid password')

    // Invalid param
    // @ts-expect-error params should be strings
    await expect(encrypt('salt', 'partition', 'id', 5)).rejects.toThrowError('Params invalid')
  })

  it('real world usage should work - aes-gcm encrypter', async () => {
    const { encrypt, decrypt } = new SEncrypt(new MemoryStorage(), str => `${str}2`, new AesGcmEncrypter())

    // Encrypt and decrypt
    const encrypted = await encrypt('salt', 'partition', 'id', 'pt')
    expect(encrypted).toBeTypeOf('string')
    const decrypted = await decrypt('salt', 'partition', 'id', encrypted)
    expect(decrypted).toBe('pt')
    // trying to decrypt with wrong password (different salt)
    await expect(decrypt('salt2', 'partition', 'id', encrypted)).rejects.toThrowError()
  })
})
