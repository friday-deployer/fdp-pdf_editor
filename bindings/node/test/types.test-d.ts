// Type tests, checked with `tsc --noEmit -p test` (pnpm test:types). Nothing here is executed.

import { FolioxideError, PdfDocument, fromPdfDate, toPdfDate, version } from 'folioxide'
import type {
  Diagnostic,
  DiagnosticKind,
  DocInfo,
  ErrorCode,
  IncrementalSaveOptions,
  InfoUpdate,
  OpenOptions,
  PageBox,
  PageInfo,
  PdfDateInput,
  Rect,
  SaveOptions,
  StreamCompression,
  Trapped,
  XrefStyle,
} from 'folioxide'
import * as binding from '../binding.js'

type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false

// ---- version() ---------------------------------------------------------------------------------

const v: string = version()
const facadeSignature: Equal<typeof version, () => string> = true

// @ts-expect-error version() takes no arguments
version('0.1.0')

// @ts-expect-error the result is a string, not a number
const n: number = version()

// The generated binding declares the same signature as the hand-written facade.
const bindingSignature: Equal<typeof binding.version, typeof version> = true

// ---- opening and creating ----------------------------------------------------------------------

declare const bytes: Uint8Array
declare const buffer: Buffer

const opened: PdfDocument = PdfDocument.open(bytes)
const openedStrict: PdfDocument = PdfDocument.open(buffer, { strict: true })
const openedAsync: Promise<PdfDocument> = PdfDocument.openAsync(bytes, { strict: false })
const created: PdfDocument = PdfDocument.create()
const openOptions: OpenOptions = {}

// @ts-expect-error the data is bytes, not a string
PdfDocument.open('%PDF-1.7')
// @ts-expect-error strict is a boolean
PdfDocument.open(bytes, { strict: 'yes' })
// @ts-expect-error documents come from open, openAsync or create
new PdfDocument()

// ---- reading -----------------------------------------------------------------------------------

const pageCount: number = opened.pageCount
const pdfVersion: string = opened.version
const isModified: boolean = opened.isModified
// @ts-expect-error pageCount is read-only
opened.pageCount = 3

// ---- memory ------------------------------------------------------------------------------------

const nativeMemory: number = opened.nativeMemory
const isClosed: boolean = opened.isClosed
// @ts-expect-error nativeMemory is read-only
opened.nativeMemory = 0
const closeResult: void = opened.close()
const disposeResult: void = opened[Symbol.dispose]()
const disposable: Disposable = opened

const page: PageInfo = opened.getPage(0)
const pageShape: Equal<
  PageInfo,
  { index: number; width: number; height: number; mediaBox: Rect; cropBox: Rect; rotation: number }
> = true
const rectShape: Equal<Rect, { llx: number; lly: number; urx: number; ury: number }> = true

const info: DocInfo = opened.getInfo()
const title: string | undefined = info.title
const creationDate: string | undefined = info.creationDate
const trapped: Trapped | undefined = info.trapped
const custom: Record<string, string> = info.custom
const trappedValues: Equal<Trapped, 'true' | 'false' | 'unknown'> = true

const diagnostics: Diagnostic[] = opened.diagnostics()
const firstDiagnostic: Diagnostic | undefined = diagnostics[0]
const offset: number | null | undefined = firstDiagnostic?.offset
const kind: DiagnosticKind | undefined = firstDiagnostic?.kind
const someKind: DiagnosticKind = 'xrefReconstructed'
// @ts-expect-error not a diagnostic kind
const notAKind: DiagnosticKind = 'somethingElse'

// ---- editing -----------------------------------------------------------------------------------

const update: InfoUpdate = {
  title: 'Отчёт 年度報告',
  author: null,
  creationDate: new Date(),
  modDate: 'D:20261010093000Z',
  trapped: 'unknown',
  custom: { Department: 'Finance', Obsolete: null },
}
opened.setInfo(update)
opened.setInfo({})
const dateInput: Equal<PdfDateInput, Date | string> = true
// @ts-expect-error trapped is 'true', 'false' or 'unknown'
opened.setInfo({ trapped: 'maybe' })
// @ts-expect-error a title is text
opened.setInfo({ title: 42 })
// @ts-expect-error custom values are text or null
opened.setInfo({ custom: { Key: 1 } })

opened.setPageRotation(0, -90)
opened.setPageBox(0, 'crop', { llx: 0, lly: 0, urx: 300, ury: 400 })
opened.setPageBox(0, 'crop', null)
const pageBox: Equal<PageBox, 'media' | 'crop'> = true
// @ts-expect-error only the media box and the crop box
opened.setPageBox(0, 'bleed', null)
// @ts-expect-error the rectangle is required (null removes the crop box)
opened.setPageBox(0, 'crop')

// ---- saving ------------------------------------------------------------------------------------

const saveOptions: SaveOptions = {
  xref: 'stream',
  objectStreams: true,
  compress: 'recompress',
  gc: true,
  renumber: true,
  deterministic: true,
  id: [bytes, buffer],
  minVersion: '1.7',
  flateLevel: 9,
}
const saved: Buffer = opened.save(saveOptions)
const savedDefault: Buffer = created.save()
const savedAsync: Promise<Buffer> = opened.saveAsync({ xref: 'table' })
const xrefStyles: Equal<XrefStyle, 'auto' | 'table' | 'stream'> = true
const compressions: Equal<StreamCompression, 'keep' | 'compressNew' | 'recompress'> = true
// @ts-expect-error xref styles are lower case
opened.save({ xref: 'Table' })
// @ts-expect-error minVersion is a version string such as "1.7"
opened.save({ minVersion: 1.7 })

const incrementalOptions: IncrementalSaveOptions = { suffixOnly: true, deterministic: true, id1: bytes }
const incremental: Buffer = opened.saveIncremental()
const suffix: Buffer = opened.saveIncremental(incrementalOptions)
const incrementalAsync: Promise<Buffer> = opened.saveIncrementalAsync()

// ---- errors and dates --------------------------------------------------------------------------

declare const caught: unknown
if (caught instanceof FolioxideError) {
  const code: ErrorCode = caught.code
  const asError: Error = caught
  const details: Record<string, unknown> | undefined = caught.details
  void [code, asError, details]
}
const busy: ErrorCode = 'E_BUSY'
const closedCode: ErrorCode = 'E_CLOSED'
const syntax: ErrorCode = 'E_SYNTAX'
// @ts-expect-error not an error code
const notACode: ErrorCode = 'E_NOPE'
const constructed = new FolioxideError('E_IO', 'message', { cause: new Error('inner'), details: { path: 'x' } })
// @ts-expect-error the code must be an ErrorCode
new FolioxideError('NOPE', 'message')

const pdfDate: string = toPdfDate(new Date())
const parsed: Date | null = fromPdfDate('D:2026')
// @ts-expect-error toPdfDate takes a Date
toPdfDate('2026-10-10')

// ---- the generated binding agrees with the facade ----------------------------------------------

// What the native addon returns is exactly what the facade declares (Diagnostic narrows `kind`
// from a string to DiagnosticKind).
const bindingPage: Equal<binding.PageInfo, PageInfo> = true
const bindingRect: Equal<binding.Rect, Rect> = true
const bindingInfo: Equal<binding.DocInfo, DocInfo> = true
const bindingTrapped: Equal<binding.Trapped, Trapped> = true
const bindingPageBox: Equal<binding.PageBox, PageBox> = true
const bindingXref: Equal<binding.XrefStyle, XrefStyle> = true
const bindingCompression: Equal<binding.StreamCompression, StreamCompression> = true
const bindingDiagnostic: binding.Diagnostic = {} as Diagnostic
// What the facade takes, the native addon takes too (dates converted to strings first).
const bindingSaveOptions: binding.SaveOptions = saveOptions
const bindingIncremental: binding.IncrementalSaveOptions = incrementalOptions
const bindingOpenOptions: binding.OpenOptions = openOptions
const bindingUpdate: binding.InfoUpdate = { ...update, creationDate: 'D:2026', modDate: null }

export {
  bindingCompression,
  bindingDiagnostic,
  bindingIncremental,
  bindingInfo,
  bindingOpenOptions,
  bindingPage,
  bindingPageBox,
  bindingRect,
  bindingSaveOptions,
  bindingSignature,
  bindingTrapped,
  bindingUpdate,
  bindingXref,
  busy,
  closeResult,
  closedCode,
  compressions,
  constructed,
  creationDate,
  custom,
  dateInput,
  disposable,
  disposeResult,
  facadeSignature,
  incremental,
  incrementalAsync,
  info,
  isClosed,
  isModified,
  kind,
  n,
  nativeMemory,
  notACode,
  notAKind,
  offset,
  openedAsync,
  openedStrict,
  page,
  pageBox,
  pageCount,
  pageShape,
  parsed,
  pdfDate,
  pdfVersion,
  rectShape,
  saved,
  savedAsync,
  savedDefault,
  someKind,
  suffix,
  syntax,
  title,
  trapped,
  trappedValues,
  v,
  xrefStyles,
}
