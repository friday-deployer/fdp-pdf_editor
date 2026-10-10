// Type tests, checked with `tsc --noEmit -p test` (pnpm test:types). Nothing here is executed.

import { version } from 'folioxide'
import * as binding from '../binding.js'

type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false

// The public facade: version(): string.
const v: string = version()
const facadeSignature: Equal<typeof version, () => string> = true

// @ts-expect-error version() takes no arguments
version('0.1.0')

// @ts-expect-error the result is a string, not a number
const n: number = version()

// The generated binding declares the same signature as the hand-written facade.
const bindingSignature: Equal<typeof binding.version, typeof version> = true

export { bindingSignature, facadeSignature, n, v }
