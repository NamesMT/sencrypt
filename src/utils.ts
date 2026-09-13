export function validParams(...params: unknown[]) {
  for (const param of params) {
    if (typeof param !== 'string' || param.length === 0)
      throw new Error('Params invalid')
  }
}
