import { fn, BigInt } from 'download0/types'

export function checkJailbroken (): boolean {
  fn.register(24, 'getuid', [], 'bigint')
  fn.register(23, 'setuid', ['number'], 'bigint')

  const uidBefore = fn.getuid()
  const uidBeforeVal = uidBefore instanceof BigInt ? uidBefore.lo : uidBefore
  log('UID: ' + uidBeforeVal)

  if (uidBeforeVal === 0) {
    log('UID is already 0 — already jailbroken (skipping setuid probe)')
    return true
  }

  log('Attempting setuid(0)...')

  try {
    const setuidResult = fn.setuid(0)
    const setuidRet = setuidResult instanceof BigInt ? setuidResult.lo : setuidResult
    log('setuid returned: ' + setuidRet)
  } catch (e) {
    log('setuid threw exception: ' + (e as Error).toString())
  }

  const uidAfter = fn.getuid()
  const uidAfterVal = uidAfter instanceof BigInt ? uidAfter.lo : uidAfter

  const jailbroken = uidAfterVal === 0
  log(jailbroken ? 'Already jailbroken' : 'Not jailbroken')
  return jailbroken
}
